import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

function shortHash(filePath: string): string {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex').slice(0, 12);
  } catch {
    return 'absent';
  }
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
  const verifyFile = (artifactId: string, expectedPattern: string) => {
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
    input_versions: { discovery: shortHash(discoveryPath), requirements: shortHash(requirementsPath) },
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
    input_versions: { requirements: shortHash(reqPath), prd: shortHash(prdPath) },
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
    input_versions: { prd: shortHash(prdPath), technical_decisions: shortHash(path.join(workDir, 'technical-decisions.json')), spec: shortHash(specPath) },
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
    input_versions: { plan: shortHash(planPath), task_contracts: shortHash(path.join(workDir, 'traceability-matrix.json')) },
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

/**
 * Semantic validation: verify that PRD requirements have observable acceptance criteria
 * and that each requirement is actually addressed (not just referenced).
 */
function validatePRDSemantics(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const reqPath = path.join(workDir, 'requirements.json');
  const prdPath = path.join(workDir, 'prd.json');

  if (!fs.existsSync(reqPath) || !fs.existsSync(prdPath)) return findings;

  try {
    const reqData = JSON.parse(fs.readFileSync(reqPath, 'utf8'));
    const prdData = JSON.parse(fs.readFileSync(prdPath, 'utf8'));
    const reqs = reqData.requirements || [];
    const acceptedReqs = new Set(prdData.accepted_requirements || []);

    reqs.forEach((req: any) => {
      if (!req.id) return;
      const isAccepted = acceptedReqs.has(req.id);

      // Semantic check 1: accepted requirements must have acceptance criteria
      if (isAccepted) {
        const ac = req.acceptance_criteria || [];
        const hasObservable = ac.some((c: string) =>
          /deve|deveria|should|must|shall|verificável|observável|testável|mensurável/i.test(c),
        );
        if (!hasObservable) {
          findings.push({
            id: `FIND-SEM-PRD-AC-${req.id}`,
            severity: 'medium',
            type: 'unverifiable_acceptance',
            source_refs: ['requirements.json', 'prd.json'],
            target_refs: [req.id],
            description: `Requisito aceito ${req.id} não possui critério de aceite observável/testável`,
            required_resolution: 'Reformular critérios de aceite usando linguagem observável (deve, verificável, etc.)',
            resolution_owner: 'product-owner',
            status: 'open',
          });
        }
      }

      // Semantic check 2: rejected requirements must have a rationale
      if (!isAccepted && req.status === 'rejected' && !req.rejection_rationale) {
        findings.push({
          id: `FIND-SEM-PRD-REJ-${req.id}`,
          severity: 'low',
          type: 'ambiguity',
          source_refs: ['requirements.json', 'prd.json'],
          target_refs: [req.id],
          description: `Requisito rejeitado ${req.id} não possui justificativa documentada`,
          required_resolution: 'Documentar por que o requisito foi rejeitado',
          resolution_owner: 'product-owner',
          status: 'open',
        });
      }
    });
  } catch {
    // Skip semantic validation if files are unreadable
  }

  return findings;
}

/**
 * Semantic validation: verify that SPEC capabilities actually cover PRD requirements
 * (not just that IDs match, but that the capability description references the requirement intent).
 */
function validateSpecCoversPRD(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const prdPath = path.join(workDir, 'prd.json');
  const specPath = path.join(workDir, 'spec.json');

  if (!fs.existsSync(prdPath) || !fs.existsSync(specPath)) return findings;

  try {
    const prdData = JSON.parse(fs.readFileSync(prdPath, 'utf8'));
    const specData = JSON.parse(fs.readFileSync(specPath, 'utf8'));
    const acceptedReqs = prdData.accepted_requirements || [];
    const caps = specData.capabilities || [];

    // Build a map of requirement ID -> capabilities that claim to cover it
    const reqCoverage: Record<string, string[]> = {};
    for (const reqId of acceptedReqs) reqCoverage[reqId] = [];

    caps.forEach((cap: any) => {
      if (!cap.id || !cap.covered_requirements) return;
      for (const reqId of cap.covered_requirements) {
        if (reqCoverage[reqId]) reqCoverage[reqId].push(cap.id);
      }
    });

    // Semantic check: each accepted requirement must be covered by at least one capability
    for (const [reqId, coveringCaps] of Object.entries(reqCoverage)) {
      if (coveringCaps.length === 0) {
        findings.push({
          id: `FIND-SEM-SPEC-COVER-${reqId}`,
          severity: 'high',
          type: 'coverage_gap',
          source_refs: ['prd.json', 'spec.json'],
          target_refs: [reqId],
          description: `Requisito aceito ${reqId} não é coberto por nenhuma capacidade técnica no spec.json`,
          required_resolution: `Adicionar capacidade que implemente o requisito ${reqId} ou remover do escopo aceito`,
          resolution_owner: 'architect',
          status: 'open',
        });
      }
    }

    // Semantic check: capabilities must have at least one rule or implementation detail
    caps.forEach((cap: any) => {
      if (!cap.id) return;
      const hasImplementation = (cap.rules && cap.rules.length > 0) ||
        (cap.api_endpoints && cap.api_endpoints.length > 0) ||
        (cap.data_models && cap.data_models.length > 0);
      if (!hasImplementation) {
        findings.push({
          id: `FIND-SEM-SPEC-IMPL-${cap.id}`,
          severity: 'medium',
          type: 'coverage_gap',
          source_refs: ['spec.json'],
          target_refs: [cap.id],
          description: `Capacidade ${cap.id} não possui regras, endpoints ou modelos de dados — é apenas um título`,
          required_resolution: 'Especificar como a capacidade será implementada',
          resolution_owner: 'architect',
          status: 'open',
        });
      }
    });
  } catch {
    // Skip
  }

  return findings;
}

/**
 * Semantic validation: verify that the contract has executable constraints
 * (budget, scope, invariants) compatible with the task described in the plan.
 */
function validateContractSemantics(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const planPath = path.join(workDir, 'plan.json');

  if (!fs.existsSync(planPath)) return findings;

  try {
    const planData = JSON.parse(fs.readFileSync(planPath, 'utf8'));
    const tasks = planData.tasks || [];

    tasks.forEach((task: any) => {
      if (!task.contract_id) return;
      const contractPath = path.join(workDir, `${task.contract_id}.json`);

      if (!fs.existsSync(contractPath)) {
        findings.push({
          id: `FIND-SEM-CTR-MISSING-${task.id}`,
          severity: 'high',
          type: 'traceability_gap',
          source_refs: ['plan.json'],
          target_refs: [task.contract_id],
          description: `Contrato ${task.contract_id} referenciado pela task ${task.id} não existe`,
          required_resolution: 'Criar o contrato ou corrigir o contract_id',
          resolution_owner: 'architect',
          status: 'open',
        });
        return;
      }

      try {
        const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));

        // Semantic check 1: contract must have a non-empty scope
        const scope = contract.scope_contract || contract.scope || {};
        const writeAllow = scope.write_allow || scope.writeAllow || [];
        if (writeAllow.length === 0) {
          findings.push({
            id: `FIND-SEM-CTR-SCOPE-${task.contract_id}`,
            severity: 'medium',
            type: 'coverage_gap',
            source_refs: [contractPath, 'plan.json'],
            target_refs: [task.id],
            description: `Contrato ${task.contract_id} não declara nenhum arquivo em write_allow — impossível verificar escopo`,
            required_resolution: 'Adicionar padrões de arquivo ao scope.write_allow',
            resolution_owner: 'architect',
            status: 'open',
          });
        }

        // Semantic check 2: contract must have budget limits
        const budget = contract.budget_contract || contract.budget || {};
        const hasBudget = budget.max_tokens || budget.max_cost_usd || budget.max_duration_minutes;
        if (!hasBudget) {
          findings.push({
            id: `FIND-SEM-CTR-BUDGET-${task.contract_id}`,
            severity: 'medium',
            type: 'coverage_gap',
            source_refs: [contractPath],
            target_refs: [task.id],
            description: `Contrato ${task.contract_id} não define limites de budget — sem enforcement de custo/tempo`,
            required_resolution: 'Adicionar max_tokens, max_cost_usd ou max_duration_minutes',
            resolution_owner: 'architect',
            status: 'open',
          });
        }

        // Semantic check 3: contract risk must match task complexity
        const riskLevel = contract.risk?.level || 'L1';
        const taskComplexity = task.complexity || 'medium';
        const highComplexity = ['high', 'critical', 'architectural'].includes(taskComplexity);
        if (highComplexity && ['L0', 'L1'].includes(riskLevel)) {
          findings.push({
            id: `FIND-SEM-CTR-RISK-${task.contract_id}`,
            severity: 'medium',
            type: 'conflict',
            source_refs: [contractPath, 'plan.json'],
            target_refs: [task.id],
            description: `Task ${task.id} é de alta complexidade mas o contrato é risco ${riskLevel} — sub-classificação de risco`,
            required_resolution: 'Reavaliar o risco da task ou decompor em tasks menores',
            resolution_owner: 'architect',
            status: 'open',
          });
        }
      } catch {
        // Skip unreadable contract
      }
    });
  } catch {
    // Skip
  }

  return findings;
}

/**
 * Semantic validation: verify that evidence actually proves the contract's acceptance criteria.
 */
function validateEvidenceSemantics(workDir: string): GateFinding[] {
  const findings: GateFinding[] = [];
  const evidenceDir = path.join(workDir, 'evidence');

  if (!fs.existsSync(evidenceDir)) {
    findings.push({
      id: 'FIND-SEM-EVD-001',
      severity: 'high',
      type: 'coverage_gap',
      source_refs: ['evidence/'],
      target_refs: [],
      description: 'Diretório de evidências ausente — não há como verificar cumprimento do contrato',
      required_resolution: 'Criar diretório evidence/ com logs, test results ou screenshots',
      resolution_owner: 'engineer',
      status: 'open',
    });
    return findings;
  }

  try {
    const files = fs.readdirSync(evidenceDir);
    if (files.length === 0) {
      findings.push({
        id: 'FIND-SEM-EVD-002',
        severity: 'high',
        type: 'coverage_gap',
        source_refs: ['evidence/'],
        target_refs: [],
        description: 'Diretório de evidências vazio — nenhuma prova de execução disponível',
        required_resolution: 'Adicionar arquivos de evidência (test results, logs, screenshots)',
        resolution_owner: 'engineer',
        status: 'open',
      });
    }

    // Semantic check: evidence files should have content that looks like test output
    const hasTestEvidence = files.some(f =>
      /test|spec|result|log|output|coverage/i.test(f),
    );
    if (!hasTestEvidence && files.length > 0) {
      findings.push({
        id: 'FIND-SEM-EVD-003',
        severity: 'low',
        type: 'unverifiable_acceptance',
        source_refs: ['evidence/'],
        target_refs: files,
        description: 'Nenhuma evidência de teste encontrada nos arquivos de evidence/',
        required_resolution: 'Incluir resultados de testes ou logs de execução',
        resolution_owner: 'engineer',
        status: 'open',
      });
    }
  } catch {
    // Skip
  }

  return findings;
}

/**
 * Run ALL semantic validations for a Work.
 * This is the entry point for semantic traceability verification.
 */
export function validateSemanticTraceability(workDir: string, workId: string): GateFinding[] {
  const findings: GateFinding[] = [];
  findings.push(...validatePRDSemantics(workDir));
  findings.push(...validateSpecCoversPRD(workDir));
  findings.push(...validateContractSemantics(workDir));
  findings.push(...validateEvidenceSemantics(workDir));
  return findings;
}
