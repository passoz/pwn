import { Ajv, type ValidateFunction } from 'ajv';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import evidenceSchema from '../../schemas/evidence.schema.json' with { type: 'json' };
import pipelineSchema from '../../schemas/pipeline.schema.json' with { type: 'json' };
import planSchema from '../../schemas/plan.schema.json' with { type: 'json' };
import policySchema from '../../schemas/policy.schema.json' with { type: 'json' };
import prdSchema from '../../schemas/prd.schema.json' with { type: 'json' };
import systemSchema from '../../schemas/system.schema.json' with { type: 'json' };
import tasksSchema from '../../schemas/tasks.schema.json' with { type: 'json' };

/**
 * Conjunto de leis do harness, **embutido no bundle**.
 *
 * Import de JSON é resolvido na construção: sob `bun src/cli.ts` o arquivo é
 * lido do disco a cada execução; sob `bun build --compile` a cópia congelada vai
 * dentro do binário. Em nenhum dos dois casos o caminho do módulo entra na
 * decisão — é isso que permite rodar o verificador fora da árvore do repo (o
 * mesmo binário, movido para outro diretório, continua validando contra as
 * mesmas leis).
 */
const EMBEDDED_SCHEMAS: Record<string, unknown> = {
  'evidence.schema.json': evidenceSchema,
  'pipeline.schema.json': pipelineSchema,
  'plan.schema.json': planSchema,
  'policy.schema.json': policySchema,
  'prd.schema.json': prdSchema,
  'system.schema.json': systemSchema,
  'tasks.schema.json': tasksSchema,
};

/** Nomes das leis conhecidas pelo verificador. */
export const LAW_NAMES: string[] = Object.keys(EMBEDDED_SCHEMAS);

let cachedLawsDigest: string | null = null;

/**
 * Hash determinístico de todas as leis embutidas no verificador (SHA256).
 * Qualquer alteração em qualquer schema embutido altera este hash.
 */
export function lawsDigest(): string {
  if (cachedLawsDigest !== null) return cachedLawsDigest;
  const hasher = crypto.createHash('sha256');
  for (const name of LAW_NAMES) {
    hasher.update(name);
    hasher.update(JSON.stringify(EMBEDDED_SCHEMAS[name]));
  }
  cachedLawsDigest = hasher.digest('hex').slice(0, 16);
  return cachedLawsDigest;
}
const ajv = new Ajv({ allErrors: true, strict: false, formats: { date: true, 'date-time': true } });

export interface ValidationResult {
  valid: boolean;
  file: string;
  errors: string[];
}

const compileCache: Record<string, ValidateFunction> = {};

function compile(schemaFile: string): ValidateFunction {
  const cached = compileCache[schemaFile];
  if (cached) return cached;
  const schema = EMBEDDED_SCHEMAS[schemaFile];
  if (!schema) throw new Error(`unknown schema: ${schemaFile} (conhecidas: ${LAW_NAMES.join(', ')})`);
  const compiled = ajv.compile(structuredClone(schema));
  compileCache[schemaFile] = compiled;
  return compiled;
}

function schemaNameFromDoc(data: unknown): string | null {
  if (data && typeof data === 'object' && '$schema' in (data as Record<string, unknown>)) {
    const value = (data as Record<string, unknown>).$schema;
    if (typeof value === 'string') return path.basename(value);
  }
  return null;
}

function ajvErrors(validate: ValidateFunction, data: unknown): string[] {
  validate(data);
  return (validate.errors ?? []).map((err) => `${err.instancePath || '/'} ${err.message ?? 'invalid'}`);
}

// ── Pinning das leis ───────────────────────────────────────────────

/**
 * Candidatos de diretório para as cópias em disco dos schemas: ao lado do
 * módulo (interpretador) e ao lado do executável (binário compilado).
 */
function schemaDirs(): string[] {
  return [
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../schemas'),
    path.join(path.dirname(process.execPath), 'schemas'),
  ];
}

/** Diretório com cópias em disco, se algum acompanhar o verificador; senão `null`. */
function diskSchemaDir(): string | null {
  for (const dir of schemaDirs()) {
    try {
      if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) return dir;
    } catch {
      // ignore
    }
  }
  return null;
}

/**
 * Leis cujo arquivo em disco divergiu da cópia embutida.
 *
 * A cópia embutida é a que o verificador aplica. O disco é só revisável/diffável:
 * se divergir, alguém editou a lei sem reconstruir o verificador — cenário em que
 * editar `schemas/*.json` viraria bypass de gate.
 */
export function findLawDrift(): string[] {
  const dir = diskSchemaDir();
  if (dir === null) return [];

  const drifted: string[] = [];
  for (const name of LAW_NAMES) {
    const file = path.join(dir, name);
    if (!fs.existsSync(file)) {
      drifted.push(`${name} (ausente no disco)`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      drifted.push(`${name} (JSON inválido)`);
      continue;
    }
    if (JSON.stringify(parsed) !== JSON.stringify(EMBEDDED_SCHEMAS[name])) {
      drifted.push(name);
    }
  }
  return drifted;
}

/** Aborta quando as leis em disco divergem das embutidas (ver {@link findLawDrift}). */
export function assertLawsPinned(): void {
  const drifted = findLawDrift();
  if (drifted.length === 0) return;
  console.error(`[pwn] leis embutidas divergem de schemas/ no disco: ${drifted.join(', ')}`);
  console.error('     A cópia embutida é a que vale. Reconstrua o harness para adotar a edição, ou reverta o arquivo.');
  process.exit(1);
}

// ── Validação ──────────────────────────────────────────────────────

/**
 * Validate a single normative document against its JSON Schema (when declared).
 * Documents without a declared schema are checked only for parseability; a
 * declared schema that the verifier does not carry is an error, never a pass.
 */
export function validateNormativeDocument(filePath: string, rootDir: string = process.cwd()): ValidationResult {
  const absolute = path.resolve(rootDir, filePath);
  const relative = path.relative(rootDir, absolute);

  if (!fs.existsSync(absolute)) {
    return { valid: false, file: relative, errors: [`File not found: ${relative}`] };
  }

  let data: unknown;
  try {
    data = JSON.parse(fs.readFileSync(absolute, 'utf8'));
  } catch (err) {
    return { valid: false, file: relative, errors: [`JSON Syntax Error: ${(err as Error).message}`] };
  }

  const schemaFile = schemaNameFromDoc(data);
  if (!schemaFile) return { valid: true, file: relative, errors: [] };
  if (!(schemaFile in EMBEDDED_SCHEMAS)) {
    return {
      valid: false,
      file: relative,
      errors: [`Schema não verificável: ${schemaFile} (conhecidas: ${LAW_NAMES.join(', ')})`],
    };
  }

  const errors = ajvErrors(compile(schemaFile), data);
  return { valid: errors.length === 0, file: relative, errors };
}

/**
 * Validate a work directory's normative documents against their schemas.
 * Documents without a matching schema are validated structurally by the gates.
 */
export function validateWorkDocuments(workId: string, rootDir: string = process.cwd()): ValidationResult[] {
  const workDir = path.resolve(rootDir, '.piwerness/work', workId);
  const docSchemas: Record<string, string> = {
    'prd.json': 'prd.schema.json',
    'plan.json': 'plan.schema.json',
    'evidence.json': 'evidence.schema.json',
  };

  const results: ValidationResult[] = [];
  for (const [doc, schemaFile] of Object.entries(docSchemas)) {
    const absolute = path.join(workDir, doc);
    const relative = path.relative(rootDir, absolute);
    if (!fs.existsSync(absolute)) continue;

    let data: unknown;
    try {
      data = JSON.parse(fs.readFileSync(absolute, 'utf8'));
    } catch (err) {
      results.push({ valid: false, file: relative, errors: [`JSON Syntax Error: ${(err as Error).message}`] });
      continue;
    }

    const errors = ajvErrors(compile(schemaFile), data);
    results.push({ valid: errors.length === 0, file: relative, errors });
  }

  return results;
}

/**
 * Validate the framework's own normative documents (repo-relative core set).
 */
export function validateAllCoreNormatives(rootDir: string = process.cwd()): ValidationResult[] {
  const normatives = [
    '.specs/system.json',
    'spec.json',
    'todo.json',
    'packs/core/pipeline-core.json',
  ];

  return normatives.map((file) => validateNormativeDocument(file, rootDir));
}
