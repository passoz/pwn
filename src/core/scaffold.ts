import fs from 'node:fs';
import path from 'node:path';
import { createDefaultContractV4, type RiskLevel, type TaskContractV4 } from './contract-engine.js';
import { frozenTestsRequired } from './gates.js';
import { getNextWorkId, getWorkArtifactsPaths, initWorkDirectory } from './work-artifacts.js';
import { renderTasksMarkdown, tasksMarkdownPath, type Plan } from './plan-renderer.js';

// ── Work scaffolding ───────────────────────────────────────────────
//
// Creates a COMPLETE, schema-valid, gate-passing, executable Work chain:
// discovery → requirements → prd → spec → plan + frozen V4 contract +
// traceability matrix + the derived v3 markdown. Unlike the older shell
// scripts, the generated plan.json/prd.json pass `pwn validate`, the 5 gates
// and `pwn work contract`, so `pwn work run` can execute it immediately.

/** Task explícita do scaffold: arquivos concretos e (opcionalmente) escopo exato de escrita. */
export interface ScaffoldTaskSpec {
  title: string;
  implementationFiles: string[];
  testFiles: string[];
  behavior?: string;
  /** Sem isso, o contrato usa a allowlist genérica do scaffold (`src/**`, `tests/**`). */
  writeAllow?: string[];
  writeDeny?: string[];
}

/** Texto do Work quando a origem não é um greenfield (ex.: conciliação de mudanças feitas fora do pwn). */
export interface ScaffoldNarrative {
  problem: string;
  solution: string;
  objective: string;
  scenario: 'greenfield' | 'brownfield';
  author: string;
}

export interface ScaffoldOptions {
  rootDir: string;
  title: string;
  workId?: string;
  /** Legacy spec / source document to snapshot inside the work directory. */
  sourcePath?: string;
  risk?: RiskLevel;
  force?: boolean;
  /** Substitui o texto padrão de discovery/PRD. */
  narrative?: ScaffoldNarrative;
  /** Tasks explícitas; sem elas o scaffold gera uma única task esqueleto. */
  tasks?: ScaffoldTaskSpec[];
}

export interface ScaffoldResult {
  workId: string;
  workDir: string;
  generated: string[];
  skipped: Array<{ file: string; reason: string }>;
  review: string[];
}

const DEFAULT_ACCEPTANCE = 'bun test';
const DEFAULT_TYPE_CHECK = 'bun run check';

/**
 * Slug determinístico do título para nomear os arquivos esqueleto da task.
 * O plano nunca pode declarar diretório/glob/placeholder (o gate de aceitação
 * bloqueia), então o scaffold precisa de caminhos concretos desde o início;
 * renomear para os nomes reais é parte da revisão da task.
 */
function titleSlug(title: string): string {
  const slug = title
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48)
    .replace(/-+$/g, '');
  return slug || 'task';
}

function writeFile(
  rootDir: string,
  filePath: string,
  content: string,
  generated: string[],
  skipped: ScaffoldResult['skipped'],
  force: boolean,
): void {
  if (fs.existsSync(filePath) && !force) {
    skipped.push({ file: path.relative(rootDir, filePath), reason: 'já existe (use --force para sobrescrever)' });
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, 'utf8');
  generated.push(path.relative(rootDir, filePath));
}

function writeJson(
  rootDir: string,
  filePath: string,
  value: unknown,
  generated: string[],
  skipped: ScaffoldResult['skipped'],
  force: boolean,
): void {
  writeFile(rootDir, filePath, `${JSON.stringify(value, null, 2)}\n`, generated, skipped, force);
}

/**
 * Build the frozen V4 contract for a freshly scaffolded task.
 * Acceptance commands drive the runtime shell allowlist (fail-closed).
 */
export function scaffoldContract(
  workId: string,
  taskId: string,
  title: string,
  risk: RiskLevel,
  scope?: { writeAllow: string[]; writeDeny: string[] },
): TaskContractV4 {
  const contract = createDefaultContractV4(taskId, workId, title, risk, {
    writeAllow: scope?.writeAllow ?? ['src/**', 'tests/**'],
    writeDeny: scope?.writeDeny ?? ['.git/**', 'package.json', '.env*'],
  });
  contract.validation_strategy = 'tdd-strict';
  contract.acceptance_contract.commands = [DEFAULT_ACCEPTANCE, DEFAULT_TYPE_CHECK];
  return contract;
}

export function scaffoldWork(options: ScaffoldOptions): ScaffoldResult {
  const { rootDir, title, sourcePath, risk = 'L2', force = false } = options;
  if (!title || title.trim().length < 5) {
    throw new Error('--title deve ter ao menos 5 caracteres');
  }

  const workId = options.workId ?? getNextWorkId(rootDir);
  if (!/^\d{4}$/.test(workId)) {
    throw new Error(`Work ID inválido: ${workId} (esperado quatro dígitos)`);
  }

  // `work init` lays down discovery/requirements/prd/traceability templates.
  // A freshly created Work is ours to fill; a pre-existing one needs --force.
  const workDirPath = getWorkArtifactsPaths(workId, rootDir).workDir;
  const freshWork = !fs.existsSync(workDirPath);
  const paths = initWorkDirectory(workId, rootDir);
  const overwrite = force || freshWork;
  const generated: string[] = [];
  const skipped: ScaffoldResult['skipped'] = [];
  const now = new Date().toISOString();

  let legacyReference: string | null = null;
  if (sourcePath) {
    const absolute = path.resolve(rootDir, sourcePath);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
      throw new Error(`--source não encontrado: ${sourcePath}`);
    }
    const snapshot = path.join(paths.workDir, 'legacy-spec.md');
    writeFile(rootDir, snapshot, fs.readFileSync(absolute, 'utf8'), generated, skipped, true);
    legacyReference = 'legacy-spec.md';
  }
  const problem = options.narrative?.problem
    ?? `O projeto precisa de "${title}" implementado com comportamento verificável e escopo de escrita limitado por contrato.`;
  const solution = options.narrative?.solution
    ?? `Executar "${title}" em TDD estrito sob sandbox Git worktree, com diff guard e orçamento congelados no contrato V4.`;

  writeJson(rootDir, path.join(paths.workDir, 'discovery.json'), {
    work_id: workId,
    title,
    grilling_depth: 'medium',
    problem,
    actors: ['ACT-001'],
    objectives: [options.narrative?.objective ?? `Entregar "${title}" com critérios de aceite observáveis`],
    constraints: [
      'Manter a suíte de testes existente verde (sem regressões)',
      'Permanecer dentro da write_allow do contrato V4',
    ],
    ...(legacyReference ? { legacy_spec: legacyReference } : {}),
  }, generated, skipped, overwrite);

  writeJson(rootDir, path.join(paths.workDir, 'requirements.json'), {
    work_id: workId,
    requirements: [
      {
        id: 'FR-001',
        title: `Implementar "${title}"`,
        user_story: `Como operador, quero "${title}" para obter o resultado descrito no objetivo`,
        acceptance_criteria: [
          `${DEFAULT_ACCEPTANCE} — a suíte completa passa com exit 0`,
          `${DEFAULT_TYPE_CHECK} — typecheck estrito passa com exit 0`,
        ],
      },
    ],
  }, generated, skipped, overwrite);

  writeJson(rootDir, path.join(paths.workDir, 'prd.json'), {
    $schema: '../../../schemas/prd.schema.json',
    id: `PRD-${workId}`,
    meta: { version: '1.0', created_at: now, author: options.narrative?.author ?? 'pwn-scaffold' },
    title: `PRD — ${title}`.slice(0, 100),
    status: 'draft',
    scenario: options.narrative?.scenario ?? (legacyReference ? 'brownfield' : 'greenfield'),
    problem: { statement: problem.length >= 20 ? problem : `${problem} (escopo mínimo)` },
    solution: { statement: solution.length >= 20 ? solution : `${solution} (escopo mínimo)` },
    decisions: [
      {
        id: 'DEC-001',
        statement: `Adotar contrato V4 congelado (risco ${risk}) como fronteira de execução do Work ${workId}.`,
        status: 'accepted',
        made_by: options.narrative?.author ?? 'pwn-scaffold',
      },
    ],
    requirements: [
      { id: 'FR-001', type: 'functional', statement: `Implementar "${title}" com critérios observáveis.` },
    ],
    stakeholders: [{ name: 'Operador humano', role: 'ACT-001' }],
    scope: {
      in_scope: [`Implementação de "${title}"`],
      out_of_scope: ['Mudanças de infraestrutura não declaradas no contrato'],
    },
    accepted_requirements: ['FR-001'],
  }, generated, skipped, overwrite);

  writeJson(rootDir, path.join(paths.workDir, 'spec.json'), {
    work_id: workId,
    title,
    capabilities: [
      {
        id: 'CAP-001',
        name: title,
        description: `Capacidade entregue pelo Work ${workId}: ${title}.`,
        rules: ['BR-001', 'BR-002'],
      },
    ],
    rules: [
      { id: 'BR-001', statement: 'A execução deve permanecer dentro da write_allow do contrato V4.', coverage: ['CAP-001'], evidence: 'diff guard' },
      { id: 'BR-002', statement: 'Nenhuma regressão: a suíte existente deve permanecer verde.', coverage: ['CAP-001'], evidence: DEFAULT_ACCEPTANCE },
    ],
  }, generated, skipped, overwrite);

  const slug = titleSlug(title);
  const specs: ScaffoldTaskSpec[] = options.tasks ?? [{
    title,
    implementationFiles: [`src/${slug}.ts`],
    testFiles: [`tests/${slug}.test.ts`],
  }];
  if (specs.length === 0) throw new Error('tasks deve declarar ao menos uma task');
  const taskIdOf = (index: number): string => `1.${index + 1}`;
  const sequenceOf = (index: number): string => String(index + 1).padStart(3, '0');
  const focusedAcceptanceOf = (spec: ScaffoldTaskSpec): string => `${DEFAULT_ACCEPTANCE} ${spec.testFiles.join(' ')}`;

  const plan: Plan = {
    work_id: workId,
    title,
    components: [{ name: 'core', purpose: `Componente principal de "${title}"` }],
    global_gates: [
      `\`${DEFAULT_ACCEPTANCE}\` — a suíte completa passa com exit 0.`,
      `\`${DEFAULT_TYPE_CHECK}\` — typecheck estrito passa com exit 0.`,
    ],
    tasks: specs.map((spec, index) => {
      const focusedAcceptance = focusedAcceptanceOf(spec);
      return {
        id: taskIdOf(index),
        title: spec.title,
        requirement_id: 'FR-001',
        depends_on: [],
        behavior: spec.behavior ?? `implementa "${spec.title}" com o resultado observável declarado nos critérios de aceite`,
        components: ['core'],
        files: [...spec.implementationFiles, ...spec.testFiles],
        implementation_files: spec.implementationFiles,
        test_files: spec.testFiles,
        red: { command: focusedAcceptance, description: `a asserção do novo comportamento falha antes da implementação de ${spec.implementationFiles.join(', ')}` },
        implementation_steps: [
          'Escrever o teste que falha (RED) para o comportamento declarado',
          'Implementar o mínimo para o teste passar (GREEN) e refatorar preservando a suíte verde',
        ],
        acceptance_criteria: [
          { command: focusedAcceptance, description: 'o comportamento declarado é observado pelo teste focado da task' },
        ],
        visual: 'N/A' as const,
        documentation: 'N/A' as const,
        spec_reference: 'CAP-001',
        contract_id: `CTR-${sequenceOf(index)}`,
        complexity: 'standard',
        status: 'pending' as const,
      };
    }),
  };

  writeJson(rootDir, path.join(paths.workDir, 'plan.json'), { $schema: '../../../schemas/plan.schema.json', ...plan }, generated, skipped, overwrite);
  specs.forEach((spec, index) => {
    const scope = spec.writeAllow ? { writeAllow: spec.writeAllow, writeDeny: spec.writeDeny ?? ['.git/**', 'package.json', '.env*'] } : undefined;
    writeJson(rootDir, path.join(paths.workDir, `CTR-${sequenceOf(index)}.json`), scaffoldContract(workId, taskIdOf(index), spec.title, risk, scope), generated, skipped, overwrite);
  });

  writeJson(rootDir, path.join(paths.workDir, 'traceability-matrix.json'), {
    work_id: workId,
    matrix: specs.map((_, index) => ({
      origin: 'DISC-001',
      requirement_id: 'FR-001',
      decision_id: 'DEC-001',
      spec_section: 'CAP-001',
      task_id: taskIdOf(index),
      contract_id: `CTR-${sequenceOf(index)}`,
      evidence_id: `EVD-${sequenceOf(index)}`,
      status: 'planned',
    })),
  }, generated, skipped, overwrite);

  // Derived v3 markdown (canonical source stays plan.json).
  const markdownPath = tasksMarkdownPath(workId, rootDir);
  writeFile(rootDir, markdownPath, renderTasksMarkdown(plan), generated, skipped, overwrite);
  const relativeMarkdown = path.relative(rootDir, markdownPath);

  const review: string[] = [];
  if (!options.tasks) {
    review.push(`Renomeie os arquivos esqueleto da task 1.1 (${specs[0].implementationFiles[0]}, ${specs[0].testFiles[0]}) para os nomes reais do módulo e do teste — o audit congela exatamente o que o plano declarar.`);
  }
  review.push(
    `Revise ${relativeMarkdown}: o RED/AC de cada task apontam para o teste focado dela; a suíte e o typecheck ficam nos gates globais.`,
    `O risco congelado é ${risk}; ajuste com --risk se a mudança for mais sensível.`,
  );
  if (frozenTestsRequired(risk) && !options.tasks) {
    review.push(
      `Risco ${risk}: comite o teste de aceitação e rode 'pwn work contract --work ${workId} --task 1.1 --freeze-tests ${specs[0].testFiles[0]}' ANTES da implementação — o gate GATE-PLAN-CONTRACT bloqueia até os testes estarem congelados.`,
    );
  }
  return {
    workId,
    workDir: path.relative(rootDir, paths.workDir),
    generated,
    skipped,
    review,
  };
}
