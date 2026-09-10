import Ajv, { type ValidateFunction } from 'ajv';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Schemas live at the harness install root, not at the caller's cwd.
const SCHEMA_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../schemas');

const ajv = new Ajv({ allErrors: true, strict: false, formats: { date: true, 'date-time': true } });

export interface ValidationResult {
  valid: boolean;
  file: string;
  errors: string[];
}

const compileCache: Record<string, ValidateFunction> = {};

function compile(schemaFile: string): ValidateFunction {
  if (!compileCache[schemaFile]) {
    const schema = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, schemaFile), 'utf8'));
    compileCache[schemaFile] = ajv.compile(schema);
  }
  return compileCache[schemaFile];
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

/**
 * Validate a single normative document against its JSON Schema (when declared).
 * Documents without a declared schema are checked only for parseability.
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
  if (schemaFile && fs.existsSync(path.join(SCHEMA_DIR, schemaFile))) {
    const errors = ajvErrors(compile(schemaFile), data);
    return { valid: errors.length === 0, file: relative, errors };
  }

  return { valid: true, file: relative, errors: [] };
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
