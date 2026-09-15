import fs from 'node:fs';
import path from 'node:path';
import { createDefaultContractV4, type RiskLevel, type TaskContractV4 } from './contract-engine.js';
import { getNextWorkId, getWorkArtifactsPaths, initWorkDirectory } from './work-artifacts.js';
import { renderTasksMarkdown, tasksMarkdownPath, type Plan } from './plan-renderer.js';

// ── Work scaffolding ───────────────────────────────────────────────
//
// Creates a COMPLETE, schema-valid, gate-passing, executable Work chain:
// discovery → requirements → prd → spec → plan + frozen V4 contract +
// traceability matrix + the derived v3 markdown. Unlike the older shell
// scripts, the generated plan.json/prd.json pass `pwn validate`, the 5 gates
// and `pwn work contract`, so `pwn work run` can execute it immediately.

export interface ScaffoldOptions {
  rootDir: string;
  title: string;
  workId?: string;
  /** Legacy spec / source document to snapshot inside the work directory. */
  sourcePath?: string;
  risk?: RiskLevel;
  force?: boolean;
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
export function scaffoldContract(workId: string, taskId: string, title: string, risk: RiskLevel): TaskContractV4 {
  const contract = createDefaultContractV4(taskId, workId, title, risk, {
    writeAllow: ['src/**', 'tests/**'],
    writeDeny: ['.git/**', 'package.json', '.env*'],
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
  const problem = `O projeto precisa de "${title}" implementado com comportamento verificável e escopo de escrita limitado por contrato.`;
  const solution = `Executar "${title}" em TDD estrito sob sandbox Git worktree, com diff guard e orçamento congelados no contrato V4.`;

  writeJson(rootDir, path.join(paths.workDir, 'discovery.json'), {
    work_id: workId,
    title,
    grilling_depth: 'medium',
    problem,
    actors: ['ACT-001'],
    objectives: [`Entregar "${title}" com critérios de aceite observáveis`],
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
    meta: { version: '1.0', created_at: now, author: 'pwn-scaffold' },
    title: `PRD — ${title}`.slice(0, 100),
    status: 'draft',
    scenario: legacyReference ? 'brownfield' : 'greenfield',
    problem: { statement: problem.length >= 20 ? problem : `${problem} (escopo mínimo)` },
    solution: { statement: solution.length >= 20 ? solution : `${solution} (escopo mínimo)` },
    decisions: [
      {
        id: 'DEC-001',
        statement: `Adotar contrato V4 congelado (risco ${risk}) como fronteira de execução do Work ${workId}.`,
        status: 'accepted',
        made_by: 'pwn-scaffold',
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

  const plan: Plan = {
    work_id: workId,
    title,
    components: [{ name: 'core', purpose: `Componente principal de "${title}"` }],
    global_gates: [
      `\`${DEFAULT_ACCEPTANCE}\` — a suíte completa passa com exit 0.`,
      `\`${DEFAULT_TYPE_CHECK}\` — typecheck estrito passa com exit 0.`,
    ],
    tasks: [
      {
        id: '1.1',
        title,
        requirement_id: 'FR-001',
        depends_on: [],
        behavior: `implementa "${title}" com o resultado observável declarado nos critérios de aceite`,
        components: ['core'],
        files: ['src/', 'tests/'],
        implementation_files: ['src/'],
        test_files: ['tests/'],
        red: { command: DEFAULT_ACCEPTANCE, description: 'a asserção do novo comportamento falha antes da implementação' },
        implementation_steps: [
          'Escrever o teste que falha (RED) para o comportamento declarado',
          'Implementar o mínimo para o teste passar (GREEN) e refatorar preservando a suíte verde',
        ],
        acceptance_criteria: [
          { command: DEFAULT_ACCEPTANCE, description: 'a suíte completa passa' },
          { command: DEFAULT_TYPE_CHECK, description: 'o typecheck estrito passa' },
        ],
        visual: 'N/A',
        documentation: 'N/A',
        spec_reference: 'CAP-001',
        contract_id: 'CTR-001',
        complexity: 'standard',
        status: 'pending',
      },
    ],
  };

  writeJson(rootDir, path.join(paths.workDir, 'plan.json'), { $schema: '../../../schemas/plan.schema.json', ...plan }, generated, skipped, overwrite);
  writeJson(rootDir, path.join(paths.workDir, 'CTR-001.json'), scaffoldContract(workId, '1.1', title, risk), generated, skipped, overwrite);

  writeJson(rootDir, path.join(paths.workDir, 'traceability-matrix.json'), {
    work_id: workId,
    matrix: [
      {
        origin: 'DISC-001',
        requirement_id: 'FR-001',
        decision_id: 'DEC-001',
        spec_section: 'CAP-001',
        task_id: '1.1',
        contract_id: 'CTR-001',
        evidence_id: 'EVD-001',
        status: 'planned',
      },
    ],
  }, generated, skipped, overwrite);

  // Derived v3 markdown (canonical source stays plan.json).
  const markdownPath = tasksMarkdownPath(workId, rootDir);
  writeFile(rootDir, markdownPath, renderTasksMarkdown(plan), generated, skipped, overwrite);
  const relativeMarkdown = path.relative(rootDir, markdownPath);

  return {
    workId,
    workDir: path.relative(rootDir, paths.workDir),
    generated,
    skipped,
    review: [
      `Revise ${path.join('.piwerness/work', workId, 'plan.json')}: files/implementation_files/test_files são placeholders ("src/", "tests/").`,
      `Revise ${relativeMarkdown}: a task 1.1 é um esqueleto e precisa ser detalhada antes de implementar.`,
      `O risco congelado é ${risk}; ajuste com --risk se a mudança for mais sensível.`,
    ],
  };
}
