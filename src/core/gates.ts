import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { firstInlineCommand, genericCommandReason, placeholderPathReason, splitCommandLine } from './acceptance.js';

function shortHash(filePath: string): string {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex').slice(0, 12);
  } catch {
    return 'absent';
  }
}

/**
 * Versão combinada dos contratos referenciados pelo plano. Entra na chave do cache
 * de GATE-PLAN-CONTRACT: o gate lê os contratos, então um contrato editado não pode
 * continuar servindo o veredicto antigo.
 */
function contractsHash(workDir: string): string {
  let ids: string[] = [];
  try {
    const plan = JSON.parse(fs.readFileSync(path.join(workDir, 'plan.json'), 'utf8'));
    ids = (Array.isArray(plan?.tasks) ? plan.tasks : [])
      .map((task: { contract_id?: unknown }) => (typeof task?.contract_id === 'string' ? task.contract_id : ''))
      .filter(Boolean)
      .sort();
  } catch {
    return 'absent';
  }
  const hasher = crypto.createHash('sha256');
  for (const id of ids) hasher.update(`${id}:${shortHash(path.join(workDir, `${id}.json`))};`);
  return hasher.digest('hex').slice(0, 12);
}

export type GateResultStatus = 'pass' | 'pass_with_notes' | 'blocked';
export type FindingSeverity = 'low' | 'medium' | 'high' | 'critical';
export type FindingType = 'coverage_gap' | 'conflict' | 'ambiguity' | 'unverifiable_acceptance' | 'traceability_gap';

export interface GateFinding {
  id: string;
  severity: FindingSeverity;
  type: FindingType;
  source_refs: string[];
  target_refs: string[];
  description: string;
  required_resolution: string;
  resolution_owner: string;
  status: 'open' | 'resolved' | 'accepted_risk' | 'deferred';
}

export interface GateOutput {
  gate: string;
  work_id: string;
  input_versions: Record<string, string>;
  result: GateResultStatus;
  summary: {
    covered: number;
    gaps: number;
    conflicts: number;
    ambiguities: number;
    traceability_gaps: number;
  };
  findings: GateFinding[];
}

// ── Traceability Matrix Types ──────────────────────────────────────

export interface TraceabilityEntry {
  origin: string;
  requirement_id: string;
  decision_id: string;
  spec_section: string;
  task_id: string;
  contract_id: string;
  evidence_id: string;
  status: string;
}

export interface TraceabilityMatrix {
  work_id: string;
  matrix: TraceabilityEntry[];
}

/**
 * Load the traceability matrix for a work directory.
 * Returns null if the file doesn't exist or is invalid.
 */
export function loadTraceabilityMatrix(workDir: string): TraceabilityMatrix | null {
  const matrixPath = path.join(workDir, 'traceability-matrix.json');
  if (!fs.existsSync(matrixPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Validate that the traceability matrix has complete links for the given gate.
 * Returns findings for any gaps in the chain.
 */
function validateTraceability(
  matrix: TraceabilityMatrix | null,
  gateName: string,
  requiredFields: (keyof TraceabilityEntry)[],
  workId: string,
): GateFinding[] {
  const findings: GateFinding[] = [];

  if (!matrix) {
    findings.push({
      id: `FIND-TRACE-${gateName}-001`,
      severity: 'high',
      type: 'traceability_gap',
      source_refs: ['traceability-matrix.json'],
      target_refs: [],
      description: `Matriz de rastreabilidade ausente para gate ${gateName}`,
      required_resolution: 'Criar traceability-matrix.json com links entre artefatos',
      resolution_owner: 'architect',
      status: 'open',
    });
    return findings;
  }

  if (!matrix.matrix || matrix.matrix.length === 0) {
    findings.push({
      id: `FIND-TRACE-${gateName}-002`,
      severity: 'high',
      type: 'traceability_gap',
      source_refs: ['traceability-matrix.json'],
      target_refs: [],
      description: `Matriz de rastreabilidade vazia para gate ${gateName}`,
      required_resolution: 'Adicionar entradas à matriz de rastreabilidade',
      resolution_owner: 'architect',
      status: 'open',
    });
    return findings;
  }

  // Check each entry has the required fields populated
  matrix.matrix.forEach((entry, idx) => {
    for (const field of requiredFields) {
      const value = entry[field];
      if (!value || value === '' || value === `PLACEHOLDER-${field}`) {
        findings.push({
          id: `FIND-TRACE-${gateName}-${idx}-${field}`,
          severity: 'medium',
          type: 'traceability_gap',
          source_refs: [`matrix[${idx}]`],
          target_refs: [String(value || '')],
          description: `Entrada ${idx + 1} da matriz: campo "${field}" não preenchido ou é placeholder`,
          required_resolution: `Preencher ${field} com o ID real do artefato vinculado`,
          resolution_owner: 'architect',
          status: 'open',
        });
      }
    }
  });

  return findings;
}

/**
 * Validate the full provenance chain: DISC → REQ → PRD → CAP → TASK → CONTRACT → EVIDENCE
 */
export function validateFullTraceability(workDir: string, workId: string): GateFinding[] {
  const matrix = loadTraceabilityMatrix(workDir);
  const findings: GateFinding[] = [];

  if (!matrix) {
    findings.push({
      id: 'FIND-TRACE-FULL-001',
      severity: 'critical',
      type: 'traceability_gap',
      source_refs: ['traceability-matrix.json'],
      target_refs: [],
      description: 'Matriz de rastreabilidade ausente — cadeia de proveniência não verificável',
      required_resolution: 'Criar traceability-matrix.json antes de finalizar o Work',
      resolution_owner: 'architect',
      status: 'open',
    });
    return findings;
  }

  // Full chain validation
  const chainFindings = validateTraceability(
    matrix, 'FULL-CHAIN',
    ['origin', 'requirement_id', 'decision_id', 'spec_section', 'task_id', 'contract_id', 'evidence_id'],
    workId,
  );
  findings.push(...chainFindings);

  // Cross-reference: verify that referenced artifact files actually exist
  const verifyFile = (artifactId: string, expectedPattern: string | RegExp) => {
    if (!artifactId || artifactId === '') return;
    // Check if any file in workDir matches the pattern
    try {
      const files = fs.readdirSync(workDir);
      const matches = files.some(f => f.includes(artifactId) || f.match(expectedPattern));
      if (!matches) {
        findings.push({
          id: `FIND-TRACE-VERIFY-${artifactId}`,
          severity: 'medium',
          type: 'traceability_gap',
          source_refs: ['traceability-matrix.json'],
          target_refs: [artifactId],
          description: `Artefato referenciado "${artifactId}" não encontrado no diretório do Work`,
          required_resolution: `Verificar se o artefato ${artifactId} foi criado corretamente`,
          resolution_owner: 'architect',
          status: 'open',
        });
      }
    } catch {
      // Can't read directory — skip verification
    }
  };

  // Verify key artifacts exist
  matrix.matrix.forEach(entry => {
    if (entry.requirement_id) verifyFile(entry.requirement_id, /requirements/);
    if (entry.contract_id) verifyFile(entry.contract_id, /contract|plan/);
    if (entry.evidence_id) verifyFile(entry.evidence_id, /evidence|test/);
  });

  return findings;
}

// ── Gate Implementations ───────────────────────────────────────────

export function evaluateGateDiscReq(workId: string, workDir: string): GateOutput {
  const discoveryPath = path.join(workDir, 'discovery.json');
  const requirementsPath = path.join(workDir, 'requirements.json');

  const findings: GateFinding[] = [];
  let covered = 0;

  if (!fs.existsSync(discoveryPath)) {
    findings.push({
      id: 'FIND-001',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['discovery.json'],
      target_refs: [],
      description: 'Artefato discovery.json ausente no Work',
      required_resolution: 'Criar e preencher discovery.json antes de derivar requisitos',
      resolution_owner: 'product-owner',
      status: 'open',
    });
  }

  if (!fs.existsSync(requirementsPath)) {
    findings.push({
      id: 'FIND-002',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['requirements.json'],
      target_refs: [],
      description: 'Artefato requirements.json ausente no Work',
      required_resolution: 'Criar requisitos observáveis a partir do Discovery',
      resolution_owner: 'product-owner',
      status: 'open',
    });
  }

  if (findings.length === 0) {
    try {
      const reqData = JSON.parse(fs.readFileSync(requirementsPath, 'utf8'));
      const reqList = reqData.requirements || reqData.user_stories || [];
      covered = reqList.length;

      reqList.forEach((req: any, index: number) => {
        if (!req.acceptance_criteria || req.acceptance_criteria.length === 0) {
          findings.push({
            id: `FIND-REQ-${index + 1}`,
            severity: 'high',
            type: 'unverifiable_acceptance',
            source_refs: [req.id || `REQ-${index + 1}`],
            target_refs: [],
            description: `Requisito ${req.id || index + 1} sem critérios de aceite observáveis`,
            required_resolution: 'Adicionar critérios de aceite testáveis',
            resolution_owner: 'product-owner',
            status: 'open',
          });
        }
      });
    } catch (e: any) {
      findings.push({
        id: 'FIND-ERR-01',
        severity: 'critical',
        type: 'ambiguity',
        source_refs: ['requirements.json'],
        target_refs: [],
        description: `Erro ao ler JSON de requisitos: ${e.message}`,
        required_resolution: 'Corrigir a sintaxe JSON do arquivo de requisitos',
        resolution_owner: 'product-owner',
        status: 'open',
      });
    }
  }

  // Traceability: DISC-REQ should have origin + requirement_id linked
  const traceFindings = validateTraceability(
    loadTraceabilityMatrix(workDir), 'DISC-REQ',
    ['origin', 'requirement_id'],
    workId,
  );
  findings.push(...traceFindings);

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const traceGaps = findings.filter(f => f.type === 'traceability_gap').length;

  return {
    gate: 'GATE-DISC-REQ',
    work_id: workId,
    input_versions: { discovery: shortHash(discoveryPath), requirements: shortHash(requirementsPath), traceability_matrix: shortHash(path.join(workDir, 'traceability-matrix.json')) },
    result: hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass'),
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
      traceability_gaps: traceGaps,
    },
    findings,
  };
}

export function evaluateGateReqPrd(workId: string, workDir: string): GateOutput {
  const reqPath = path.join(workDir, 'requirements.json');
  const prdPath = path.join(workDir, 'prd.json');

  const findings: GateFinding[] = [];
  let covered = 0;

  if (!fs.existsSync(prdPath)) {
    findings.push({
      id: 'FIND-PRD-01',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['prd.json'],
      target_refs: [],
      description: 'Artefato prd.json ausente no Work',
      required_resolution: 'Consolidar decisão de produto em prd.json',
      resolution_owner: 'product-owner',
      status: 'open',
    });
  } else {
    try {
      const prdData = JSON.parse(fs.readFileSync(prdPath, 'utf8'));
      const acceptedReqs = prdData.accepted_requirements || [];
      covered = acceptedReqs.length;

      if (covered === 0) {
        findings.push({
          id: 'FIND-PRD-02',
          severity: 'high',
          type: 'coverage_gap',
          source_refs: ['prd.json'],
          target_refs: [],
          description: 'PRD não possui requisitos aceitos declarados (accepted_requirements)',
          required_resolution: 'Vincular IDs dos requisitos aceitos ao PRD',
          resolution_owner: 'product-owner',
          status: 'open',
        });
      }

      // Cross-reference: verify accepted requirements exist in requirements.json
      if (fs.existsSync(reqPath)) {
        try {
          const reqData = JSON.parse(fs.readFileSync(reqPath, 'utf8'));
          const reqIds = new Set((reqData.requirements || []).map((r: any) => r.id));
          for (const reqId of acceptedReqs) {
            if (!reqIds.has(reqId)) {
              findings.push({
                id: `FIND-PRD-XREF-${reqId}`,
                severity: 'high',
                type: 'traceability_gap',
                source_refs: ['prd.json', 'requirements.json'],
                target_refs: [reqId],
                description: `Requisito ${reqId} aceito no PRD mas não encontrado em requirements.json`,
                required_resolution: `Verificar se o requisito ${reqId} existe ou remover do PRD`,
                resolution_owner: 'product-owner',
                status: 'open',
              });
            }
          }
        } catch {
          // Can't read requirements — skip cross-reference
        }
      }
    } catch (e: any) {
      findings.push({
        id: 'FIND-PRD-ERR',
        severity: 'critical',
        type: 'ambiguity',
        source_refs: ['prd.json'],
        target_refs: [],
        description: `Erro na leitura do prd.json: ${e.message}`,
        required_resolution: 'Corrigir formato do prd.json',
        resolution_owner: 'product-owner',
        status: 'open',
      });
    }
  }

  // Semântica: requisito aceito precisa de critério observável; rejeitado, de justificativa.
  findings.push(...validatePRDSemantics(workDir));

  // Traceability
  const traceFindings = validateTraceability(
    loadTraceabilityMatrix(workDir), 'REQ-PRD',
    ['requirement_id', 'decision_id'],
    workId,
  );
  findings.push(...traceFindings);

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const traceGaps = findings.filter(f => f.type === 'traceability_gap').length;

  return {
    gate: 'GATE-REQ-PRD',
    work_id: workId,
    input_versions: { requirements: shortHash(reqPath), prd: shortHash(prdPath), traceability_matrix: shortHash(path.join(workDir, 'traceability-matrix.json')) },
    result: hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass'),
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
      traceability_gaps: traceGaps,
    },
    findings,
  };
}

export function evaluateGatePrdSpec(workId: string, workDir: string): GateOutput {
  const prdPath = path.join(workDir, 'prd.json');
  const specPath = path.join(workDir, 'spec.json');

  const findings: GateFinding[] = [];
  let covered = 0;

  if (!fs.existsSync(specPath)) {
    findings.push({
      id: 'FIND-SPEC-01',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['spec.json'],
      target_refs: [],
      description: 'Especificação técnica spec.json ausente no Work',
      required_resolution: 'Traduzir PRD aprovado em especificação técnica formal',
      resolution_owner: 'architect',
      status: 'open',
    });
  } else {
    try {
      const specData = JSON.parse(fs.readFileSync(specPath, 'utf8'));
      const caps = specData.capabilities || [];
      covered = caps.length;

      caps.forEach((cap: any, idx: number) => {
        if (!cap.rules || cap.rules.length === 0) {
          findings.push({
            id: `FIND-SPEC-CAP-${idx + 1}`,
            severity: 'medium',
            type: 'coverage_gap',
            source_refs: [cap.id || `CAP-${idx + 1}`],
            target_refs: [],
            description: `Capacidade ${cap.id || idx + 1} não vincula nenhuma regra de negócio (rules)`,
            required_resolution: 'Adicionar regras de negócio à capacidade',
            resolution_owner: 'architect',
            status: 'open',
          });
        }
      });

      // Cross-reference: verify capabilities are linked in traceability matrix
      if (fs.existsSync(path.join(workDir, 'traceability-matrix.json'))) {
        try {
          const matrixData: TraceabilityMatrix = JSON.parse(
            fs.readFileSync(path.join(workDir, 'traceability-matrix.json'), 'utf8'),
          );
          const specSections = new Set(matrixData.matrix.map(e => e.spec_section));
          caps.forEach((cap: any) => {
            if (cap.id && !specSections.has(cap.id)) {
              findings.push({
                id: `FIND-SPEC-TRACE-${cap.id}`,
                severity: 'medium',
                type: 'traceability_gap',
                source_refs: ['spec.json', 'traceability-matrix.json'],
                target_refs: [cap.id],
                description: `Capacidade ${cap.id} não está vinculada na matriz de rastreabilidade`,
                required_resolution: `Adicionar ${cap.id} ao traceability-matrix.json`,
                resolution_owner: 'architect',
                status: 'open',
              });
            }
          });
        } catch {
          // Skip
        }
      }
      // Semântica: todo requisito aceito precisa de uma capability que o cubra.
      findings.push(...requirementCoverageFindings(workDir));
    } catch (e: any) {
      findings.push({
        id: 'FIND-SPEC-ERR',
        severity: 'critical',
        type: 'ambiguity',
        source_refs: ['spec.json'],
        target_refs: [],
        description: `Erro ao ler spec.json: ${e.message}`,
        required_resolution: 'Corrigir formato do spec.json',
        resolution_owner: 'architect',
        status: 'open',
      });
    }
  }

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const traceGaps = findings.filter(f => f.type === 'traceability_gap').length;

  return {
    gate: 'GATE-PRD-SPEC',
    work_id: workId,
    input_versions: { prd: shortHash(prdPath), technical_decisions: shortHash(path.join(workDir, 'technical-decisions.json')), spec: shortHash(specPath), traceability_matrix: shortHash(path.join(workDir, 'traceability-matrix.json')) },
    result: hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass'),
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
      traceability_gaps: traceGaps,
    },
    findings,
  };
}

export function evaluateGateSpecPlan(workId: string, workDir: string): GateOutput {
  const specPath = path.join(workDir, 'spec.json');
  const planPath = path.join(workDir, 'plan.json');

  const findings: GateFinding[] = [];
  let covered = 0;

  if (!fs.existsSync(planPath)) {
    findings.push({
      id: 'FIND-PLAN-01',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['plan.json'],
      target_refs: [],
      description: 'Artefato plan.json ausente no Work',
      required_resolution: 'Decompor a spec técnica em plano executável de tarefas',
      resolution_owner: 'planner',
      status: 'open',
    });
  } else {
    try {
      const planData = JSON.parse(fs.readFileSync(planPath, 'utf8'));
      const tasks = planData.tasks || [];
      covered = tasks.length;

      if (covered === 0) {
        findings.push({
          id: 'FIND-PLAN-02',
          severity: 'high',
          type: 'coverage_gap',
          source_refs: ['plan.json'],
          target_refs: [],
          description: 'Plano não contém tarefas atomizadas declaradas',
          required_resolution: 'Adicionar tarefas ao plan.json',
          resolution_owner: 'planner',
          status: 'open',
        });
      }

      // Cross-reference: verify each task has a spec_section reference
      if (fs.existsSync(specPath)) {
        try {
          const specData = JSON.parse(fs.readFileSync(specPath, 'utf8'));
          const capIds = new Set((specData.capabilities || []).map((c: any) => c.id));
          tasks.forEach((t: any, idx: number) => {
            if (t.spec_reference && !capIds.has(t.spec_reference)) {
              findings.push({
                id: `FIND-PLAN-XREF-${idx + 1}`,
                severity: 'medium',
                type: 'traceability_gap',
                source_refs: ['plan.json', 'spec.json'],
                target_refs: [t.spec_reference],
                description: `Task ${t.id || idx + 1} referencia spec "${t.spec_reference}" que não existe na spec.json`,
                required_resolution: `Corrigir spec_reference na task ${t.id || idx + 1}`,
                resolution_owner: 'planner',
                status: 'open',
              });
            }
          });
        } catch {
          // Skip
        }
      }
    } catch (e: any) {
      findings.push({
        id: 'FIND-PLAN-ERR',
        severity: 'critical',
        type: 'ambiguity',
        source_refs: ['plan.json'],
        target_refs: [],
        description: `Erro ao ler plan.json: ${e.message}`,
        required_resolution: 'Corrigir formato do plan.json',
        resolution_owner: 'planner',
        status: 'open',
      });
    }
  }

  // Aceitação: cada task precisa de RED focado, ACs executáveis e específicos e arquivos concretos.
  findings.push(...validatePlanAcceptance(workDir));

  // Atomicidade é advisory: severidades low/medium nunca bloqueiam o gate.
  findings.push(...validateTaskAtomicity(workDir));

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const traceGaps = findings.filter(f => f.type === 'traceability_gap').length;

  return {
    gate: 'GATE-SPEC-PLAN',
    work_id: workId,
    input_versions: { spec: shortHash(specPath), work_governance: shortHash(path.join(workDir, 'work-governance.json')), plan: shortHash(planPath) },
    result: hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass'),
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
      traceability_gaps: traceGaps,
    },
    findings,
  };
}

export function evaluateGatePlanContract(workId: string, workDir: string): GateOutput {
  const planPath = path.join(workDir, 'plan.json');

  const findings: GateFinding[] = [];
  let covered = 0;

  if (!fs.existsSync(planPath)) {
    findings.push({
      id: 'FIND-CTR-01',
      severity: 'critical',
      type: 'coverage_gap',
      source_refs: ['plan.json'],
      target_refs: [],
      description: 'Plano ausente para congelar contratos de tarefas',
      required_resolution: 'Criar plan.json antes de gerar contratos',
      resolution_owner: 'planner',
      status: 'open',
    });
  } else {
    try {
      const planData = JSON.parse(fs.readFileSync(planPath, 'utf8'));
      const tasks = planData.tasks || [];
      covered = tasks.length;

      tasks.forEach((t: any) => {
        if (!t.contract_id) {
          findings.push({
            id: `FIND-CTR-TASK-${t.id}`,
            severity: 'high',
            type: 'coverage_gap',
            source_refs: [t.id],
            target_refs: [],
            description: `Task ${t.id} não vincula contract_id congelado`,
            required_resolution: 'Atribuir contract_id à task',
            resolution_owner: 'architect',
            status: 'open',
          });
        }
      });
    } catch (e: any) {
      findings.push({
        id: 'FIND-CTR-ERR',
        severity: 'critical',
        type: 'ambiguity',
        source_refs: ['plan.json'],
        target_refs: [],
        description: `Erro ao ler plan.json: ${e.message}`,
        required_resolution: 'Corrigir plan.json',
        resolution_owner: 'planner',
        status: 'open',
      });
    }
  }

  // Contrato congelado: existe, é legível, autoriza os ACs e congela os testes de aceitação exigidos.
  findings.push(...validateContractSemantics(workDir));

  // Traceability: PLAN-CONTRACT should have task_id + contract_id linked
  const traceFindings = validateTraceability(
    loadTraceabilityMatrix(workDir), 'PLAN-CONTRACT',
    ['task_id', 'contract_id'],
    workId,
  );
  findings.push(...traceFindings);

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const traceGaps = findings.filter(f => f.type === 'traceability_gap').length;

  return {
    gate: 'GATE-PLAN-CONTRACT',
    work_id: workId,
    input_versions: { plan: shortHash(planPath), task_contracts: shortHash(path.join(workDir, 'traceability-matrix.json')), contracts: contractsHash(workDir) },
    result: hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass'),
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
      traceability_gaps: traceGaps,
    },
    findings,
  };
}

// ── Semantic Traceability Validation ────────────────────────────────────

/** Risco a partir do qual a task só executa com testes de aceitação congelados antes da implementação. */
export const FROZEN_TESTS_REQUIRED_FROM_RISK = 'L3';
const RISK_ORDER = ['L0', 'L1', 'L2', 'L3', 'L4'];

/** O risco declarado exige testes de aceitação congelados no contrato antes da implementação. */
export function frozenTestsRequired(risk: string): boolean {
  return RISK_ORDER.indexOf(risk) >= RISK_ORDER.indexOf(FROZEN_TESTS_REQUIRED_FROM_RISK);
}
const ASSURANCE_KEYS = ['regression', 'lint', 'build', 'security'];

/** Critério que dá para checar: comando executável (com resultado esperado) ou verbo normativo. */
function isObservableCriterion(criterion: unknown): boolean {
  if (typeof criterion !== 'string') return false;
  return /`[^`]+`/.test(criterion)
    || /\S\s+—\s+\S/.test(criterion)
    || /deve|deveria|should|must|shall|verificável|observável|testável|mensurável/i.test(criterion);
}

/**
 * Semantic validation: verify that PRD requirements have observable acceptance criteria
 * and that rejected requirements carry a rationale.
 */
function validatePRDSemantics(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const reqData = readArtifactJson(path.join(workDir, 'requirements.json'));
  const prdData = readArtifactJson(path.join(workDir, 'prd.json'));
  if (!isJsonObject(reqData) || !isJsonObject(prdData)) return findings;

  const acceptedReqs = new Set(asJsonArray(prdData.accepted_requirements).map(String));
  asJsonArray(reqData.requirements).forEach((rawReq) => {
    const req = isJsonObject(rawReq) ? rawReq : {};
    const reqId = asJsonString(req.id);
    if (!reqId) return;
    const isAccepted = acceptedReqs.has(reqId);

    // Semantic check 1: accepted requirements must have acceptance criteria
    if (isAccepted && !asJsonArray(req.acceptance_criteria).some(isObservableCriterion)) {
      findings.push({
        id: `FIND-SEM-PRD-AC-${reqId}`,
        severity: 'medium',
        type: 'unverifiable_acceptance',
        source_refs: ['requirements.json', 'prd.json'],
        target_refs: [reqId],
        description: `Requisito aceito ${reqId} não possui critério de aceite observável/testável`,
        required_resolution: 'Reformular critérios de aceite com o comando que os verifica ou linguagem observável (deve, verificável, etc.)',
        resolution_owner: 'product-owner',
        status: 'open',
      });
    }

    // Semantic check 2: rejected requirements must have a rationale
    if (!isAccepted && req.status === 'rejected' && !req.rejection_rationale) {
      findings.push({
        id: `FIND-SEM-PRD-REJ-${reqId}`,
        severity: 'low',
        type: 'ambiguity',
        source_refs: ['requirements.json', 'prd.json'],
        target_refs: [reqId],
        description: `Requisito rejeitado ${reqId} não possui justificativa documentada`,
        required_resolution: 'Documentar por que o requisito foi rejeitado',
        resolution_owner: 'product-owner',
        status: 'open',
      });
    }
  });

  return findings;
}

/**
 * Requisitos aceitos que nenhuma capability cobre — nem por `covered_requirements`
 * nem pela matriz de rastreabilidade (requirement_id → spec_section existente).
 */
function requirementCoverageFindings(workDir: string): GateFinding[] {
  const prdData = readArtifactJson(path.join(workDir, 'prd.json'));
  const specData = readArtifactJson(path.join(workDir, 'spec.json'));
  if (!isJsonObject(prdData) || !isJsonObject(specData)) return [];

  const capabilities = asJsonArray(specData.capabilities).filter(isJsonObject);
  const capabilityIds = new Set(capabilities.map((cap) => asJsonString(cap.id)).filter(Boolean));
  const covered = new Set<string>();
  for (const cap of capabilities) {
    for (const reqId of asJsonArray(cap.covered_requirements)) covered.add(String(reqId));
  }
  const matrix = loadTraceabilityMatrix(workDir);
  for (const entry of Array.isArray(matrix?.matrix) ? matrix!.matrix : []) {
    if (entry?.requirement_id && capabilityIds.has(entry.spec_section)) covered.add(entry.requirement_id);
  }

  return asJsonArray(prdData.accepted_requirements)
    .map(String)
    .filter((reqId) => !covered.has(reqId))
    .map((reqId): GateFinding => ({
      id: `FIND-SEM-SPEC-COVER-${reqId}`,
      severity: 'high',
      type: 'coverage_gap',
      source_refs: ['prd.json', 'spec.json', 'traceability-matrix.json'],
      target_refs: [reqId],
      description: `Requisito aceito ${reqId} não é coberto por nenhuma capacidade técnica no spec.json`,
      required_resolution: `Vincular uma capacidade ao requisito ${reqId} (covered_requirements ou matriz) ou removê-lo do escopo aceito`,
      resolution_owner: 'architect',
      status: 'open',
    }));
}

/**
 * Semantic validation: verify that SPEC capabilities actually cover PRD requirements
 * and are more than a title.
 */
function validateSpecCoversPRD(workDir: string): GateFinding[] {
  const findings = requirementCoverageFindings(workDir);
  const specData = readArtifactJson(path.join(workDir, 'spec.json'));
  if (!isJsonObject(specData)) return findings;

  // Semantic check: capabilities must have at least one rule or implementation detail
  asJsonArray(specData.capabilities).filter(isJsonObject).forEach((cap) => {
    const capId = asJsonString(cap.id);
    if (!capId) return;
    const hasImplementation = asJsonArray(cap.rules).length > 0
      || asJsonArray(cap.api_endpoints).length > 0
      || asJsonArray(cap.data_models).length > 0;
    if (!hasImplementation) {
      findings.push({
        id: `FIND-SEM-SPEC-IMPL-${capId}`,
        severity: 'medium',
        type: 'coverage_gap',
        source_refs: ['spec.json'],
        target_refs: [capId],
        description: `Capacidade ${capId} não possui regras, endpoints ou modelos de dados — é apenas um título`,
        required_resolution: 'Especificar como a capacidade será implementada',
        resolution_owner: 'architect',
        status: 'open',
      });
    }
  });

  return findings;
}

/** Comandos de gate do plan.json (colunas de garantia dos componentes + gates globais): nenhum deles é AC. */
function planGateCommands(plan: Record<string, unknown>, components: string[]): string[] {
  const wanted = new Set(components);
  const fromComponents = asJsonArray(plan.components)
    .filter(isJsonObject)
    .filter((component) => wanted.size === 0 || wanted.has(asJsonString(component.name)))
    .flatMap((component) => ASSURANCE_KEYS.map((key) => asJsonString(component[key])))
    .filter((command) => command && command !== 'N/A');
  const fromGlobal = asJsonArray(plan.global_gates)
    .map((gate) => firstInlineCommand(asJsonString(gate)) ?? '')
    .filter(Boolean);
  return [...fromComponents, ...fromGlobal];
}

/**
 * Aceitação verificável por task: RED focado, ACs com comando executável e
 * específico (não vácuo, não gate global, não suíte inteira) e listas de arquivos
 * concretas — é isso que o audit amarra no baseline. Toda violação é `high`.
 */
export function validatePlanAcceptance(workDir: string): GateFinding[] {
  const planData = readArtifactJson(path.join(workDir, 'plan.json'));
  if (!isJsonObject(planData)) return [];

  const findings: GateFinding[] = [];
  const add = (id: string, taskId: string, description: string, resolution: string, type: FindingType = 'unverifiable_acceptance'): void => {
    findings.push({
      id,
      severity: 'high',
      type,
      source_refs: ['plan.json'],
      target_refs: [taskId],
      description,
      required_resolution: resolution,
      resolution_owner: 'planner',
      status: 'open',
    });
  };

  asJsonArray(planData.tasks).forEach((rawTask, idx) => {
    const task = isJsonObject(rawTask) ? rawTask : {};
    const taskId = asJsonString(task.id) || String(idx + 1);
    const gateCommands = planGateCommands(planData, asJsonArray(task.components).map(String));

    const acs = asJsonArray(task.acceptance_criteria);
    if (acs.length === 0) {
      add(`FIND-AC-MISSING-${taskId}`, taskId, `Task ${taskId} não declara critérios de aceite`, 'Declarar ao menos um AC { command, description } que prove o comportamento da task');
    }
    acs.forEach((rawAc, acIndex) => {
      const command = isJsonObject(rawAc) ? asJsonString(rawAc.command).trim() : '';
      const label = `AC-${acIndex + 1}`;
      if (!command) {
        add(`FIND-AC-COMMAND-${taskId}-${acIndex + 1}`, taskId, `${label} da task ${taskId} não tem comando executável`, 'Declarar o AC como { command, description }: texto livre não é verificável');
        return;
      }
      const generic = genericCommandReason(command, gateCommands);
      if (generic) {
        add(`FIND-AC-GENERIC-${taskId}-${acIndex + 1}`, taskId, `${label} da task ${taskId} (\`${command}\`) ${generic}`, 'Usar um comando focado no comportamento da task (arquivo de teste, filtro de nome ou probe do observável)');
      }
    });

    const redCommand = isJsonObject(task.red) ? asJsonString(task.red.command).trim() : '';
    if (!redCommand) {
      add(`FIND-RED-MISSING-${taskId}`, taskId, `Task ${taskId} não declara comando RED`, 'Declarar o comando focado que falha antes da implementação');
    } else {
      const generic = genericCommandReason(redCommand, gateCommands);
      if (generic) add(`FIND-RED-GENERIC-${taskId}`, taskId, `RED da task ${taskId} (\`${redCommand}\`) ${generic}`, 'Usar o comando focado no teste novo da task');
    }

    for (const [field, label] of [['implementation_files', 'Implementation files'], ['test_files', 'Test files']] as const) {
      const files = asJsonArray(task[field]).map(String);
      if (files.length === 0) {
        add(`FIND-FILES-MISSING-${taskId}-${field}`, taskId, `Task ${taskId} não declara ${label}`, 'Declarar os arquivos concretos que o audit congela no baseline', 'coverage_gap');
      }
      for (const file of files) {
        const reason = placeholderPathReason(file);
        if (reason) add(`FIND-FILES-PLACEHOLDER-${taskId}-${file}`, taskId, `${label} da task ${taskId}: ${file} ${reason}`, 'Substituir pelo caminho do arquivo concreto', 'coverage_gap');
      }
    }
  });

  return findings;
}

/** Tokens de um comando de aceitação do contrato (mesma leitura estrutural da política de shell). */
function commandTokens(command: string): string[] {
  return splitCommandLine(command.trim()) ?? command.trim().split(/\s+/);
}

/** O contrato autoriza o comando quando algum comando de aceitação é prefixo estrutural dele. */
function contractAuthorizes(contractCommands: string[], command: string): boolean {
  const tokens = commandTokens(command);
  if (tokens.length === 0) return false;
  return contractCommands.some((raw) => {
    const [program, ...args] = commandTokens(raw);
    return Boolean(program) && program === tokens[0] && args.every((arg, index) => tokens[index + 1] === arg);
  });
}

/** O AC exercita o teste congelado quando cita o arquivo ou um diretório que o contém. */
function referencesPath(command: string, filePath: string): boolean {
  const target = path.posix.normalize(filePath);
  return commandTokens(command).some((token) => {
    if (token.startsWith('-')) return false;
    const candidate = path.posix.normalize(token).replace(/\/$/, '');
    return candidate === target || target.startsWith(`${candidate}/`);
  });
}

/**
 * Semantic validation: o contrato congelado da task existe, é legível, tem escopo,
 * orçamento e risco coerentes, autoriza os ACs do plano e congela os testes de
 * aceitação exigidos pelo risco.
 */
function validateContractSemantics(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const planData = readArtifactJson(path.join(workDir, 'plan.json'));
  if (!isJsonObject(planData)) return findings;

  asJsonArray(planData.tasks).filter(isJsonObject).forEach((task) => {
    const taskId = asJsonString(task.id);
    const contractId = asJsonString(task.contract_id);
    if (!contractId) return;
    const contractPath = path.join(workDir, `${contractId}.json`);

    if (!fs.existsSync(contractPath)) {
      findings.push({
        id: `FIND-SEM-CTR-MISSING-${taskId}`,
        severity: 'high',
        type: 'traceability_gap',
        source_refs: ['plan.json'],
        target_refs: [contractId],
        description: `Contrato ${contractId} referenciado pela task ${taskId} não existe`,
        required_resolution: 'Criar o contrato ou corrigir o contract_id',
        resolution_owner: 'architect',
        status: 'open',
      });
      return;
    }

    const contract = readArtifactJson(contractPath);
    if (!isJsonObject(contract)) {
      findings.push({
        id: `FIND-SEM-CTR-UNREADABLE-${taskId}`,
        severity: 'high',
        type: 'ambiguity',
        source_refs: [contractPath],
        target_refs: [contractId],
        description: `Contrato ${contractId} da task ${taskId} não é um JSON legível`,
        required_resolution: 'Corrigir o JSON do contrato',
        resolution_owner: 'architect',
        status: 'open',
      });
      return;
    }

    // Semantic check 1: contract must have a non-empty scope
    const scope = isJsonObject(contract.scope_contract) ? contract.scope_contract : isJsonObject(contract.scope) ? contract.scope : {};
    if (asJsonArray(scope.write_allow ?? scope.writeAllow).length === 0) {
      findings.push({
        id: `FIND-SEM-CTR-SCOPE-${contractId}`,
        severity: 'medium',
        type: 'coverage_gap',
        source_refs: [contractPath, 'plan.json'],
        target_refs: [taskId],
        description: `Contrato ${contractId} não declara nenhum arquivo em write_allow — impossível verificar escopo`,
        required_resolution: 'Adicionar padrões de arquivo ao scope.write_allow',
        resolution_owner: 'architect',
        status: 'open',
      });
    }

    // Semantic check 2: contract must have budget limits
    const budget = isJsonObject(contract.budget_contract) ? contract.budget_contract : isJsonObject(contract.budget) ? contract.budget : {};
    if (!budget.max_tokens && !budget.max_cost_usd && !budget.max_duration_minutes) {
      findings.push({
        id: `FIND-SEM-CTR-BUDGET-${contractId}`,
        severity: 'medium',
        type: 'coverage_gap',
        source_refs: [contractPath],
        target_refs: [taskId],
        description: `Contrato ${contractId} não define limites de budget — sem enforcement de custo/tempo`,
        required_resolution: 'Adicionar max_tokens, max_cost_usd ou max_duration_minutes',
        resolution_owner: 'architect',
        status: 'open',
      });
    }

    // Semantic check 3: contract risk must match task complexity
    const riskLevel = (isJsonObject(contract.risk) && asJsonString(contract.risk.level)) || 'L1';
    const taskComplexity = asJsonString(task.complexity) || 'medium';
    if (['high', 'critical', 'architectural'].includes(taskComplexity) && ['L0', 'L1'].includes(riskLevel)) {
      findings.push({
        id: `FIND-SEM-CTR-RISK-${contractId}`,
        severity: 'medium',
        type: 'conflict',
        source_refs: [contractPath, 'plan.json'],
        target_refs: [taskId],
        description: `Task ${taskId} é de alta complexidade mas o contrato é risco ${riskLevel} — sub-classificação de risco`,
        required_resolution: 'Reavaliar o risco da task ou decompor em tasks menores',
        resolution_owner: 'architect',
        status: 'open',
      });
    }

    // Semantic check 4: the contract must authorize every AC of the task (work run nega o resto).
    const acceptance = isJsonObject(contract.acceptance_contract) ? contract.acceptance_contract : {};
    const contractCommands = asJsonArray(acceptance.commands).map(String).filter(Boolean);
    const acCommands = asJsonArray(task.acceptance_criteria)
      .map((ac) => (isJsonObject(ac) ? asJsonString(ac.command).trim() : ''))
      .filter(Boolean);
    acCommands.forEach((command, index) => {
      if (contractAuthorizes(contractCommands, command)) return;
      findings.push({
        id: `FIND-SEM-CTR-AC-${taskId}-${index + 1}`,
        severity: 'high',
        type: 'conflict',
        source_refs: [contractPath, 'plan.json'],
        target_refs: [taskId],
        description: `AC-${index + 1} da task ${taskId} (\`${command}\`) não é autorizado por acceptance_contract.commands do ${contractId}`,
        required_resolution: 'Incluir o comando (ou um prefixo estrutural dele) nos comandos de aceitação do contrato',
        resolution_owner: 'architect',
        status: 'open',
      });
    });

    // Semantic check 5: frozen acceptance tests (well-formed, required by risk, exercised by an AC).
    const frozenRaw = acceptance.frozen_tests;
    const frozen = asJsonArray(frozenRaw).filter(
      (entry): entry is Record<string, unknown> => isJsonObject(entry) && typeof entry.path === 'string' && /^[0-9a-f]{64}$/.test(asJsonString(entry.sha256)),
    );
    if (frozenRaw !== undefined && (!Array.isArray(frozenRaw) || frozen.length !== frozenRaw.length)) {
      findings.push({
        id: `FIND-SEM-CTR-FROZEN-INVALID-${taskId}`,
        severity: 'high',
        type: 'ambiguity',
        source_refs: [contractPath],
        target_refs: [taskId],
        description: `acceptance_contract.frozen_tests do ${contractId} tem entradas sem { path, sha256 } válidos`,
        required_resolution: 'Regenerar com pwn work contract --freeze-tests',
        resolution_owner: 'architect',
        status: 'open',
      });
    }
    if (frozenTestsRequired(riskLevel) && frozen.length === 0) {
      findings.push({
        id: `FIND-SEM-CTR-FROZEN-REQUIRED-${taskId}`,
        severity: 'high',
        type: 'unverifiable_acceptance',
        source_refs: [contractPath],
        target_refs: [taskId],
        description: `Task ${taskId} é risco ${riskLevel}: exige testes de aceitação escritos e congelados antes da implementação`,
        required_resolution: `Commitar os testes de aceitação e rodar 'pwn work contract --work <id> --task ${taskId} --freeze-tests <arquivos>'`,
        resolution_owner: 'architect',
        status: 'open',
      });
    }
    for (const entry of frozen) {
      const frozenPath = asJsonString(entry.path);
      if (acCommands.some((command) => referencesPath(command, frozenPath))) continue;
      findings.push({
        id: `FIND-SEM-CTR-FROZEN-UNUSED-${taskId}-${frozenPath}`,
        severity: 'high',
        type: 'unverifiable_acceptance',
        source_refs: [contractPath, 'plan.json'],
        target_refs: [taskId, frozenPath],
        description: `Teste congelado ${frozenPath} não é exercitado por nenhum AC da task ${taskId}`,
        required_resolution: 'Apontar um AC da task para o teste congelado (arquivo ou diretório)',
        resolution_owner: 'planner',
        status: 'open',
      });
    }
  });

  return findings;
}

/**
 * Run ALL semantic validations for a Work (as mesmas que os gates aplicam:
 * PRD → GATE-REQ-PRD, cobertura → GATE-PRD-SPEC, aceitação → GATE-SPEC-PLAN,
 * contrato → GATE-PLAN-CONTRACT). A prova de execução não é checada aqui: ela é
 * a atestação assinada do audit, conferida pelo status.
 */
export function validateSemanticTraceability(workDir: string, workId: string): GateFinding[] {
  const findings: GateFinding[] = [];
  findings.push(...validatePRDSemantics(workDir));
  findings.push(...validateSpecCoversPRD(workDir));
  findings.push(...validatePlanAcceptance(workDir));
  findings.push(...validateContractSemantics(workDir));
  return findings;
}

// ── Atomicidade de Tasks e Cobertura Agregada ───────────────────────

/** Lê um artefato JSON do Work sem lançar: retorna null quando ausente ou ilegível. */
function readArtifactJson(filePath: string): unknown {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Artefatos são dados externos não validados aqui; normaliza-se a forma antes do uso.
function asJsonArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asJsonString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/**
 * Verifica atomicidade das tasks do plano: uma task deve mapear para UMA capability,
 * UM componente e um conjunto pequeno de arquivos. Findings são advisory (medium/low).
 */
export function validateTaskAtomicity(workDir: string): GateFinding[] {
  const planData = readArtifactJson(path.join(workDir, 'plan.json'));
  if (!isJsonObject(planData)) return [];

  const findings: GateFinding[] = [];

  asJsonArray(planData.tasks).forEach((rawTask, idx) => {
    const task = isJsonObject(rawTask) ? rawTask : {};
    const taskId = asJsonString(task.id) || String(idx + 1);

    const specRef = asJsonString(task.spec_reference).trim();
    if (specRef && /[,+]| e | and /i.test(specRef)) {
      findings.push({
        id: `FIND-ATOMIC-SPEC-${taskId}`,
        severity: 'medium',
        type: 'coverage_gap',
        source_refs: ['plan.json'],
        target_refs: [specRef],
        description: `Task ${taskId} referencia múltiplas capabilities em spec_reference ("${specRef}")`,
        required_resolution: 'Dividir a task para referenciar uma única capability',
        resolution_owner: 'planner',
        status: 'open',
      });
    }

    const components = asJsonArray(task.components);
    if (components.length > 1) {
      findings.push({
        id: `FIND-ATOMIC-COMP-${taskId}`,
        severity: 'low',
        type: 'coverage_gap',
        source_refs: ['plan.json'],
        target_refs: components.map((component) => String(component)),
        description: `Task ${taskId} cobre ${components.length} componentes (${components.join(', ')})`,
        required_resolution: 'Dividir a task por componente ou justificar o acoplamento',
        resolution_owner: 'planner',
        status: 'open',
      });
    }

    const implementationFiles = asJsonArray(task.implementation_files);
    if (implementationFiles.length > 6) {
      findings.push({
        id: `FIND-ATOMIC-FILES-${taskId}`,
        severity: 'low',
        type: 'coverage_gap',
        source_refs: ['plan.json'],
        target_refs: implementationFiles.map((file) => String(file)),
        description: `Task ${taskId} declara ${implementationFiles.length} arquivos de implementação (> 6)`,
        required_resolution: 'Dividir a task em unidades menores',
        resolution_owner: 'planner',
        status: 'open',
      });
    }

    const behavior = asJsonString(task.behavior);
    const conjunctions = behavior ? (behavior.match(/ e | and /g) || []).length : 0;
    if (conjunctions > 3) {
      findings.push({
        id: `FIND-ATOMIC-BEHAVIOR-${taskId}`,
        severity: 'low',
        type: 'coverage_gap',
        source_refs: ['plan.json'],
        target_refs: [],
        description: `Task ${taskId} descreve múltiplos comportamentos encadeados (${conjunctions} conjunções)`,
        required_resolution: 'Decompor o comportamento em tasks atômicas',
        resolution_owner: 'planner',
        status: 'open',
      });
    }
  });

  return findings;
}

/** Cobertura agregada de um Work: quantos requisitos/capabilities/tasks/contratos existem e estão vinculados. */
export function computeWorkCoverage(workDir: string): {
  requirements: number; accepted_requirements: number;
  capabilities: number; capabilities_with_rules: number;
  tasks: number; tasks_with_contract: number; tasks_with_acs: number;
} {
  const requirementsData = readArtifactJson(path.join(workDir, 'requirements.json'));
  const prdData = readArtifactJson(path.join(workDir, 'prd.json'));
  const specData = readArtifactJson(path.join(workDir, 'spec.json'));
  const planData = readArtifactJson(path.join(workDir, 'plan.json'));

  const requirements = isJsonObject(requirementsData) ? asJsonArray(requirementsData.requirements) : [];
  const acceptedRequirements = isJsonObject(prdData) ? asJsonArray(prdData.accepted_requirements) : [];
  const capabilities = isJsonObject(specData) ? asJsonArray(specData.capabilities) : [];
  const tasks = isJsonObject(planData) ? asJsonArray(planData.tasks) : [];

  return {
    requirements: requirements.length,
    accepted_requirements: acceptedRequirements.length,
    capabilities: capabilities.length,
    capabilities_with_rules: capabilities.filter((capability) => isJsonObject(capability) && asJsonArray(capability.rules).length > 0).length,
    tasks: tasks.length,
    tasks_with_contract: tasks.filter((task) => isJsonObject(task) && asJsonString(task.contract_id).length > 0).length,
    tasks_with_acs: tasks.filter((task) => isJsonObject(task) && asJsonArray(task.acceptance_criteria).length > 0).length,
  };
}

/** Roda os 5 gates na ordem canônica e devolve todos os outputs (não para no primeiro bloqueado). */
export function evaluateAllGates(workId: string, workDir: string): GateOutput[] {
  return [
    evaluateGateDiscReq(workId, workDir),
    evaluateGateReqPrd(workId, workDir),
    evaluateGatePrdSpec(workId, workDir),
    evaluateGateSpecPlan(workId, workDir),
    evaluateGatePlanContract(workId, workDir),
  ];
}
