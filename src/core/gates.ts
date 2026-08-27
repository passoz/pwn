import fs from 'node:fs';
import path from 'node:path';

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
  input_versions: Record<string, number>;
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
    input_versions: { discovery: 1, requirements: 1 },
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
    input_versions: { requirements: 1, prd: 1 },
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
    input_versions: { prd: 1, technical_decisions: 1, spec: 1 },
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
    input_versions: { spec: 1, work_governance: 1, plan: 1 },
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
    input_versions: { plan: 1, task_contracts: 1 },
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
