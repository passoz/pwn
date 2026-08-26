import fs from 'node:fs';
import path from 'node:path';

export type GateResultStatus = 'pass' | 'pass_with_notes' | 'blocked';
export type FindingSeverity = 'low' | 'medium' | 'high' | 'critical';
export type FindingType = 'coverage_gap' | 'conflict' | 'ambiguity' | 'unverifiable_acceptance';

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
  };
  findings: GateFinding[];
}

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

      // Check if all requirements have non-empty acceptance criteria
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

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');
  const resultStatus: GateResultStatus = hasCriticalOrHigh ? 'blocked' : (findings.length > 0 ? 'pass_with_notes' : 'pass');

  return {
    gate: 'GATE-DISC-REQ',
    work_id: workId,
    input_versions: { discovery: 1, requirements: 1 },
    result: resultStatus,
    summary: {
      covered,
      gaps: findings.filter(f => f.type === 'coverage_gap').length,
      conflicts: findings.filter(f => f.type === 'conflict').length,
      ambiguities: findings.filter(f => f.type === 'ambiguity').length,
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

  const hasCriticalOrHigh = findings.some(f => (f.severity === 'critical' || f.severity === 'high') && f.status === 'open');

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
    },
    findings,
  };
}
