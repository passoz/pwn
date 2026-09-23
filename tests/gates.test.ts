import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId, getExistingWorkIds } from '../src/core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec, validateFullTraceability } from '../src/core/gates.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-gates-test-'));
}

test('getNextWorkId e getLatestWorkId calculam IDs incrementais automaticamente', () => {
  const root = fixture();
  try {
    const firstId = getNextWorkId(root);
    assert.equal(firstId, '0001');

    initWorkDirectory('0001', root);
    assert.equal(getLatestWorkId(root), '0001');
    assert.equal(getNextWorkId(root), '0002');

    initWorkDirectory('0002', root);
    assert.equal(getLatestWorkId(root), '0002');
    assert.equal(getNextWorkId(root), '0003');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('getNextWorkId ignora diretório de Work vazio (sem artefatos)', () => {
  const root = fixture();
  try {
    mkdirSync(path.join(root, '.pwn', 'work', '0001'), { recursive: true });

    assert.equal(getExistingWorkIds(root).length, 0);
    assert.equal(getLatestWorkId(root), '0001');
    assert.equal(getNextWorkId(root), '0001');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('getNextWorkId compartilha o espaço de IDs com a trilha do manifest', () => {
  const root = fixture();
  try {
    mkdirSync(path.join(root, '.work'), { recursive: true });
    writeFileSync(path.join(root, '.work', '0004.json'), '{}\n');

    // getExistingWorkIds continua restrito a .pwn/work (usado por pwn validate).
    assert.equal(getExistingWorkIds(root).length, 0);
    // Mas a numeração não pode reaproveitar um ID já reservado pelo manifest.
    assert.equal(getLatestWorkId(root), '0004');
    assert.equal(getNextWorkId(root), '0005');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('initWorkDirectory cria a estrutura completa sob .pwn/work/<work-id>/', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    assert.equal(existsSync(paths.workDir), true);
    assert.equal(existsSync(paths.intake), true);
    assert.equal(existsSync(paths.discovery), true);
    assert.equal(existsSync(paths.requirements), true);
    assert.equal(existsSync(paths.prd), true);
    assert.equal(existsSync(paths.traceabilityMatrix), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-DISC-REQ bloqueia Work sem requirements.json ou com requisitos sem critérios', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0002', root);
    const result = evaluateGateDiscReq('0002', paths.workDir);
    // Initialized template has acceptance criteria, so it should PASS
    assert.equal(result.gate, 'GATE-DISC-REQ');
    assert.equal(result.result, 'pass');
    assert.ok(typeof result.summary.traceability_gaps === 'number');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-REQ-PRD valida que o PRD contém accepted_requirements', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0003', root);
    const result = evaluateGateReqPrd('0003', paths.workDir);
    assert.equal(result.gate, 'GATE-REQ-PRD');
    assert.equal(result.result, 'pass');
    assert.equal(result.summary.covered, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PRD-SPEC bloqueia se a especificação spec.json estiver ausente', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0004', root);
    const result = evaluateGatePrdSpec('0004', paths.workDir);
    assert.equal(result.gate, 'GATE-PRD-SPEC');
    assert.equal(result.result, 'blocked');
    assert.equal(result.findings.some(f => f.type === 'coverage_gap'), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateFullTraceability detecta matriz de rastreabilidade ausente', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0005', root);
    // Remove the traceability matrix
    const matrixPath = path.join(paths.workDir, 'traceability-matrix.json');
    rmSync(matrixPath);

    const findings = validateFullTraceability(paths.workDir, '0005');
    assert.ok(findings.length > 0);
    assert.equal(findings[0].type, 'traceability_gap');
    assert.equal(findings[0].severity, 'critical');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateFullTraceability valida campos preenchidos na matriz', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0006', root);
    // Overwrite matrix with incomplete entry
    const matrixPath = path.join(paths.workDir, 'traceability-matrix.json');
    writeFileSync(matrixPath, JSON.stringify({
      work_id: '0006',
      matrix: [{
        origin: 'DISC-001',
        requirement_id: '',
        decision_id: 'TD-001',
        spec_section: 'SPEC-001',
        task_id: 'T-001',
        contract_id: '',
        evidence_id: 'EVD-001',
        status: 'planned',
      }],
    }, null, 2));

    const findings = validateFullTraceability(paths.workDir, '0006');
    // Should have findings for empty requirement_id and contract_id
    assert.ok(findings.some(f => f.description.includes('requirement_id')));
    assert.ok(findings.some(f => f.description.includes('contract_id')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── Semantic Traceability Tests ────────────────────────────────────────

import { validateSemanticTraceability } from '../src/core/gates.js';

test('validateSemanticTraceability detecta critério de aceite não observável', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0007', root);

    // PRD aceita um requisito, mas o requisito não tem critério observável
    writeFileSync(paths.requirements, JSON.stringify({
      requirements: [{
        id: 'REQ-001',
        title: 'Feature X',
        acceptance_criteria: ['A interface sera agradavel'], // sem "deve/must/shall/etc"
      }],
    }, null, 2));
    writeFileSync(paths.prd, JSON.stringify({
      accepted_requirements: ['REQ-001'],
    }, null, 2));

    const findings = validateSemanticTraceability(paths.workDir, '0007');
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-PRD-AC')),
      'deve gerar finding para critério não-observável');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateSemanticTraceability detecta requisito não coberto por capacidade', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0008', root);

    writeFileSync(paths.prd, JSON.stringify({
      accepted_requirements: ['REQ-001'],
    }, null, 2));
    writeFileSync(paths.spec, JSON.stringify({
      capabilities: [{
        id: 'CAP-001',
        title: 'Capacidade Y',
        covered_requirements: [], // não cobre REQ-001
      }],
    }, null, 2));

    const findings = validateSemanticTraceability(paths.workDir, '0008');
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-SPEC-COVER')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateSemanticTraceability detecta capacidade sem implementação', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0009', root);

    writeFileSync(paths.prd, JSON.stringify({
      accepted_requirements: ['REQ-001'],
    }, null, 2));
    writeFileSync(paths.spec, JSON.stringify({
      capabilities: [{
        id: 'CAP-001',
        title: 'Capacidade Z',
        covered_requirements: ['REQ-001'],
        // sem rules, api_endpoints ou data_models
      }],
    }, null, 2));

    const findings = validateSemanticTraceability(paths.workDir, '0009');
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-SPEC-IMPL')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateSemanticTraceability detecta contrato sem scope/budget', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0010', root);

    writeFileSync(path.join(paths.workDir, 'plan.json'), JSON.stringify({
      tasks: [{
        id: 'T-001',
        contract_id: 'CTR-001',
        complexity: 'high',
      }],
    }, null, 2));
    writeFileSync(path.join(paths.workDir, 'CTR-001.json'), JSON.stringify({
      risk: { level: 'L1' },
      scope_contract: { write_allow: [] },
      // sem budget_contract
    }, null, 2));

    const findings = validateSemanticTraceability(paths.workDir, '0010');
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-CTR-SCOPE')));
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-CTR-BUDGET')));
    assert.ok(findings.some(f => f.id.startsWith('FIND-SEM-CTR-RISK')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validateSemanticTraceability detecta evidence ausente', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0011', root);

    const findings = validateSemanticTraceability(paths.workDir, '0011');
    assert.ok(findings.some(f => f.id === 'FIND-SEM-EVD-001'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
