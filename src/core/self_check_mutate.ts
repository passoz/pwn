import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  evaluateGateDiscReq,
  evaluateGatePlanContract,
  evaluateGatePrdSpec,
  evaluateGateReqPrd,
  evaluateGateSpecPlan,
  type GateOutput,
} from './gates.js';

/**
 * Mutation testing determinístico dos próprios gates do harness.
 *
 * A ideia é a mesma do mutation testing de código: se o gate é real, ele precisa
 * reagir a uma violação concreta do artefato que ele diz proteger. Cada caso
 * abaixo escreve uma violação numa **cópia temporária** de um Work válido e
 * compara o resultado do gate antes/depois. Nada aqui usa IA: são mutações de
 * JSON e reavaliações puras dos gates de `gates.ts`.
 */

export interface MutationCase {
  id: string;
  description: string;
  gate: string; // gate que DEVE falhar
  expect_blocked: boolean; // true = o gate precisa retornar 'blocked' após a mutação
}

export interface MutationResult {
  id: string;
  description: string;
  gate: string;
  detected: boolean; // o gate realmente pegou a mutação
  detail: string;
}

/** Gate avaliável: recebe (workId, workDir) e devolve o resultado do gate. */
type GateEvaluator = (workId: string, workDir: string) => GateOutput;

/** Mapa canônico gate → avaliador real de `src/core/gates.ts`. */
const GATE_EVALUATORS: Record<string, GateEvaluator> = {
  'GATE-DISC-REQ': evaluateGateDiscReq,
  'GATE-REQ-PRD': evaluateGateReqPrd,
  'GATE-PRD-SPEC': evaluateGatePrdSpec,
  'GATE-SPEC-PLAN': evaluateGateSpecPlan,
  'GATE-PLAN-CONTRACT': evaluateGatePlanContract,
};

/** Artefatos que um Work precisa ter para servir de baseline das mutações. */
const REQUIRED_ARTIFACTS = [
  'discovery.json',
  'requirements.json',
  'prd.json',
  'spec.json',
  'plan.json',
  'traceability-matrix.json',
] as const;

// ── Baseline canônica ──────────────────────────────────────────────

/**
 * Work mínimo porém **válido** (todos os gates passam antes de qualquer mutação).
 * Usado como baseline quando o Work pedido está incompleto ou não existe, para
 * que o resultado das mutações reflita os gates — e não o estado dos artefatos
 * do projeto.
 */
function canonicalArtifacts(workId: string): Record<string, unknown> {
  return {
    'discovery.json': {
      work_id: workId,
      problem: 'Problema de referência da baseline canônica de mutation testing',
      actors: ['ACT-001'],
      objectives: ['Objetivo de referência'],
      constraints: ['Restrição de referência'],
    },
    'requirements.json': {
      work_id: workId,
      requirements: [
        {
          id: 'FR-001',
          title: 'Requisito de referência',
          user_story: 'Como operador, quero X para obter Y',
          acceptance_criteria: ['Critério observável de referência'],
        },
      ],
    },
    'prd.json': {
      $schema: '../../schemas/prd.schema.json',
      id: `PRD-${workId}`,
      title: `PRD de referência do Work ${workId}`,
      status: 'draft',
      accepted_requirements: ['FR-001'],
      requirements: [
        {
          id: 'FR-001',
          statement: 'O Work mantém a cadeia de rastreabilidade entre os artefatos.',
        },
      ],
    },
    'spec.json': {
      work_id: workId,
      capabilities: [
        {
          id: 'CAP-001',
          description: 'Capacidade de referência que atende FR-001',
          rules: ['RULE-001: a rastreabilidade deve ser preservada'],
        },
      ],
    },
    'plan.json': {
      work_id: workId,
      tasks: [
        {
          id: 'T-001',
          description: 'Task de referência',
          spec_reference: 'CAP-001',
          contract_id: 'CTR-001',
          acceptance_criteria: ['Critério de aceite observável da task'],
        },
      ],
    },
    'traceability-matrix.json': {
      work_id: workId,
      matrix: [
        {
          origin: 'DISC-001',
          requirement_id: 'FR-001',
          decision_id: 'TD-001',
          spec_section: 'CAP-001',
          task_id: 'T-001',
          contract_id: 'CTR-001',
          evidence_id: 'EVD-001',
          status: 'planned',
        },
      ],
    },
  };
}

/** Diretório do Work (`<root>/.pwn/work/<id>`) ou o próprio root quando ele já é o Work. */
function resolveWorkDir(workId: string, rootDir: string): string | null {
  const nested = path.join(rootDir, '.pwn', 'work', workId);
  try {
    if (fs.statSync(nested).isDirectory()) return nested;
  } catch {
    /* segue para o fallback */
  }
  const isWorkDir = ['discovery.json', 'requirements.json', 'prd.json', 'spec.json'].some((f) =>
    fs.existsSync(path.join(rootDir, f)),
  );
  return isWorkDir ? rootDir : null;
}

/** Artefatos obrigatórios ausentes num diretório de Work. */
function missingArtifacts(workDir: string): string[] {
  return REQUIRED_ARTIFACTS.filter((f) => !fs.existsSync(path.join(workDir, f)));
}

/**
 * Descreve a baseline que `runMutations` vai usar. Serve para a CLI ser honesta
 * sobre a origem dos resultados (Work real vs. baseline canônica).
 */
export function describeBaseline(options: { workId: string; rootDir?: string }): string {
  const rootDir = path.resolve(options.rootDir ?? process.cwd());
  const source = resolveWorkDir(options.workId, rootDir);
  if (!source) {
    return `baseline canônica (Work ${options.workId} não encontrado em ${rootDir})`;
  }
  const missing = missingArtifacts(source);
  if (missing.length > 0) {
    return `baseline canônica (Work ${options.workId} incompleto: falta ${missing.join(', ')})`;
  }
  return `Work ${options.workId} (${source})`;
}

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

// ── Casos de mutação ───────────────────────────────────────────────

/** Lista canônica das mutações que o harness garante detectar. */
export function mutationCases(): MutationCase[] {
  return [
    {
      id: 'mut-missing-ac',
      description: 'Remove acceptance_criteria de todas as tasks do plan.json',
      gate: 'GATE-SPEC-PLAN',
      expect_blocked: false,
    },
    {
      id: 'mut-missing-contract',
      description: 'Aponta contract_id de uma task para um contrato inexistente',
      gate: 'GATE-PLAN-CONTRACT',
      expect_blocked: false,
    },
    {
      id: 'mut-broken-traceability',
      description: 'Esvazia a matriz de rastreabilidade (traceability-matrix.json)',
      gate: 'GATE-DISC-REQ',
      expect_blocked: true,
    },
    {
      id: 'mut-prd-missing-accepted',
      description: 'Remove accepted_requirements do prd.json',
      gate: 'GATE-REQ-PRD',
      expect_blocked: true,
    },
    {
      id: 'mut-spec-no-rules',
      description: 'Remove rules de todas as capabilities do spec.json',
      gate: 'GATE-PRD-SPEC',
      expect_blocked: false,
    },
  ];
}

/** Aplicador de mutação: devolve a nota do que mudou, ou null se não era aplicável. */
type MutationApplier = (workDir: string) => string | null;

const MUTATIONS: Record<string, MutationApplier> = {
  'mut-missing-ac': (workDir) => {
    const planPath = path.join(workDir, 'plan.json');
    if (!fs.existsSync(planPath)) return null;
    const plan = readJson(planPath);
    const tasks: any[] = Array.isArray(plan.tasks) ? plan.tasks : [];
    let touched = 0;
    for (const task of tasks) {
      if (task && Object.prototype.hasOwnProperty.call(task, 'acceptance_criteria')) {
        delete task.acceptance_criteria;
        touched++;
      }
    }
    if (touched === 0) return null;
    writeJson(planPath, plan);
    return `acceptance_criteria removidos de ${touched} task(s) do plan.json`;
  },

  'mut-missing-contract': (workDir) => {
    const planPath = path.join(workDir, 'plan.json');
    if (!fs.existsSync(planPath)) return null;
    const plan = readJson(planPath);
    const tasks: any[] = Array.isArray(plan.tasks) ? plan.tasks : [];
    const target = tasks.find((t) => t && t.contract_id);
    if (!target) return null;
    target.contract_id = 'CTR-INEXISTENTE-9999';
    writeJson(planPath, plan);
    return `contract_id da task ${target.id ?? '?'} apontado para CTR-INEXISTENTE-9999`;
  },

  'mut-broken-traceability': (workDir) => {
    const matrixPath = path.join(workDir, 'traceability-matrix.json');
    if (!fs.existsSync(matrixPath)) return null;
    const matrix = readJson(matrixPath);
    const size = Array.isArray(matrix.matrix) ? matrix.matrix.length : 0;
    if (size === 0) return null;
    matrix.matrix = [];
    writeJson(matrixPath, matrix);
    return `matriz de rastreabilidade esvaziada (${size} entrada(s) removida(s))`;
  },

  'mut-prd-missing-accepted': (workDir) => {
    const prdPath = path.join(workDir, 'prd.json');
    if (!fs.existsSync(prdPath)) return null;
    const prd = readJson(prdPath);
    if (!Object.prototype.hasOwnProperty.call(prd, 'accepted_requirements')) return null;
    const size = Array.isArray(prd.accepted_requirements) ? prd.accepted_requirements.length : 0;
    delete prd.accepted_requirements;
    writeJson(prdPath, prd);
    return `accepted_requirements removido do prd.json (${size} requisito(s) aceito(s))`;
  },

  'mut-spec-no-rules': (workDir) => {
    const specPath = path.join(workDir, 'spec.json');
    if (!fs.existsSync(specPath)) return null;
    const spec = readJson(specPath);
    const caps: any[] = Array.isArray(spec.capabilities) ? spec.capabilities : [];
    let touched = 0;
    for (const cap of caps) {
      if (cap && Object.prototype.hasOwnProperty.call(cap, 'rules') && Array.isArray(cap.rules) && cap.rules.length > 0) {
        cap.rules = [];
        touched++;
      }
    }
    if (touched === 0) return null;
    writeJson(specPath, spec);
    return `rules removidas de ${touched} capability(ies) do spec.json`;
  },
};

// ── Execução ───────────────────────────────────────────────────────

/** Resumo legível dos findings que sobraram depois da mutação. */
function describeFindings(gate: GateOutput): string {
  if (gate.findings.length === 0) return 'gate não bloqueia: nenhum finding gerado para esta mutação';
  const severities = [...new Set(gate.findings.map((f) => f.severity))].join(', ');
  const types = [...new Set(gate.findings.map((f) => f.type))].join(', ');
  return `gate não bloqueia: finding advisory (severidade '${severities}', tipo '${types}') — result='${gate.result}'`;
}

/**
 * Executa as mutações num Work temporário (cópia de um Work válido) e verifica
 * que cada gate correspondente passa de 'pass' para 'blocked'.
 *
 * O Work real nunca é escrito: cada caso roda sobre uma cópia em `mkdtemp`.
 * Quando o Work pedido não existe ou está incompleto, a baseline é a Work
 * canônica embutida neste módulo (veja `describeBaseline`).
 */
export function runMutations(options: { workId: string; rootDir?: string }): MutationResult[] {
  const cases = mutationCases();
  const rootDir = path.resolve(options.rootDir ?? process.cwd());
  const source = resolveWorkDir(options.workId, rootDir);
  const missing = source ? missingArtifacts(source) : [...REQUIRED_ARTIFACTS];
  const useCanonical = missing.length > 0;

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-mut-'));
  const baselineDir = path.join(tempRoot, 'baseline');
  fs.mkdirSync(baselineDir, { recursive: true });

  try {
    if (useCanonical) {
      const artifacts = canonicalArtifacts(options.workId);
      for (const [name, value] of Object.entries(artifacts)) writeJson(path.join(baselineDir, name), value);
    } else if (source) {
      fs.cpSync(source, baselineDir, { recursive: true });
    }

    const results: MutationResult[] = [];
    for (const mutationCase of cases) {
      results.push(runSingleMutation(mutationCase, baselineDir, tempRoot, options.workId, useCanonical));
    }
    return results;
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

/** Roda um único caso sobre uma cópia limpa da baseline. */
function runSingleMutation(
  mutationCase: MutationCase,
  baselineDir: string,
  tempRoot: string,
  workId: string,
  canonical: boolean,
): MutationResult {
  const base = {
    id: mutationCase.id,
    description: mutationCase.description,
    gate: mutationCase.gate,
  };
  const origin = canonical ? ' [baseline canônica]' : '';

  const evaluator = GATE_EVALUATORS[mutationCase.gate];
  if (!evaluator) {
    return { ...base, detected: false, detail: `gate desconhecido: ${mutationCase.gate}` };
  }

  const applier = MUTATIONS[mutationCase.id];
  if (!applier) {
    return { ...base, detected: false, detail: 'mutação sem implementação registrada' };
  }

  const caseDir = path.join(tempRoot, `case-${mutationCase.id}`);
  try {
    fs.cpSync(baselineDir, caseDir, { recursive: true });

    const before = evaluator(workId, caseDir);
    const note = applier(caseDir);

    if (!note) {
      return {
        ...base,
        detected: false,
        detail: `mutação não aplicável neste baseline (estrutura alvo ausente)${origin}`,
      };
    }

    const after = evaluator(workId, caseDir);
    const detected = before.result !== 'blocked' && after.result === 'blocked';

    let detail = `${note}; antes='${before.result}', depois='${after.result}'${origin}`;
    if (before.result === 'blocked') {
      detail += '; gate já bloqueava antes da mutação (baseline inválida para este caso)';
    } else if (!detected) {
      detail += `; ${describeFindings(after)}`;
    } else {
      detail += `; gate passou a bloquear com ${after.findings.length} finding(s)`;
      if (!mutationCase.expect_blocked) {
        detail += '; gate endureceu desde a lista canônica (caso declarado advisory)';
      }
    }

    return { ...base, detected, detail };
  } catch (error: any) {
    return { ...base, detected: false, detail: `erro ao executar a mutação: ${error?.message ?? String(error)}` };
  } finally {
    fs.rmSync(caseDir, { recursive: true, force: true });
  }
}
