import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId, getExistingWorkIds } from '../src/core/work-artifacts.js';
import {
  evaluateGateDiscReq,
  evaluateGatePlanContract,
  evaluateGatePrdSpec,
  evaluateGateReqPrd,
  evaluateGateSpecPlan,
  validateFullTraceability,
  validatePlanAcceptance,
  validateSemanticTraceability,
} from '../src/core/gates.js';

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

// A checagem `FIND-SEM-EVD-*` (existência de `.pwn/work/<id>/evidence/`) foi removida:
// nenhum módulo escrevia nesse diretório (o audit grava em `.todo/evidence/<work>`), e a
// prova de execução passou a ser a atestação assinada, conferida pelo status.

// ── Aceitação amarrada ao plano (plan.json) e contrato congelado ───────
//
// `validatePlanAcceptance` roda dentro de GATE-SPEC-PLAN: RED focado, AC com
// comando executável e específico e listas de arquivos concretas. `validateContractSemantics`
// roda dentro de GATE-PLAN-CONTRACT — como não é exportada, os cenários de contrato
// observam os findings pelo gate que a aplica.

/** Task de referência: RED/AC focados, arquivos concretos e spec_reference única. */
function taskValida(override: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: '1.1',
    spec_reference: 'CAP-001',
    components: ['core'],
    acceptance_criteria: [{ command: 'bun test tests/x.test.ts', description: 'roda o teste focado do módulo x' }],
    red: { command: 'bun test tests/x.test.ts', description: 'falha antes da implementação' },
    implementation_files: ['src/x.ts'],
    test_files: ['tests/x.test.ts'],
    ...override,
  };
}

/** Contrato mínimo legível: escopo, orçamento, risco e comandos de aceitação. */
function contratoValido(override: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    risk: { level: 'L1' },
    scope_contract: { write_allow: ['src/x.ts'] },
    budget_contract: { max_tokens: 10000 },
    acceptance_contract: { commands: ['bun test tests/x.test.ts'] },
    ...override,
  };
}

function writePlan(workDir: string, plan: unknown): void {
  writeFileSync(path.join(workDir, 'plan.json'), JSON.stringify(plan, null, 2));
}

function writeContract(workDir: string, contractId: string, contract: unknown): void {
  writeFileSync(path.join(workDir, `${contractId}.json`), JSON.stringify(contract, null, 2));
}

test('validatePlanAcceptance aceita plano de referência (RED/AC focados, arquivos concretos)', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);

    // Spec que cobre o requisito aceito pelo PRD padrão e a matriz apontando para a capability.
    writeFileSync(paths.spec, JSON.stringify({
      capabilities: [{ id: 'CAP-001', title: 'Capacidade X', covered_requirements: ['FR-001'], rules: ['regra de negócio'] }],
    }, null, 2));
    writeFileSync(paths.traceabilityMatrix, JSON.stringify({
      work_id: '0001',
      matrix: [{
        origin: 'DISC-001', requirement_id: 'FR-001', decision_id: 'TD-001',
        spec_section: 'CAP-001', task_id: '1.1', contract_id: 'CTR-001', evidence_id: 'EVD-001', status: 'planned',
      }],
    }, null, 2));
    writePlan(paths.workDir, {
      tasks: [taskValida()],
      components: [{ name: 'core', regression: 'bun run check', lint: 'N/A', build: 'N/A', security: 'N/A' }],
    });

    assert.deepEqual(validatePlanAcceptance(paths.workDir), []);
    assert.equal(evaluateGateSpecPlan('0001', paths.workDir).result, 'pass');
    assert.equal(evaluateGatePrdSpec('0001', paths.workDir).result, 'pass');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validatePlanAcceptance rejeita AC que roda a suíte inteira e bloqueia GATE-SPEC-PLAN', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({ acceptance_criteria: [{ command: 'bun test', description: 'roda tudo' }] })],
    });

    const findings = validatePlanAcceptance(paths.workDir);
    const finding = findings.find((f) => f.id === 'FIND-AC-GENERIC-1.1-1');
    assert.ok(finding, 'AC `bun test` sem alvo deve gerar FIND-AC-GENERIC-1.1-1');
    assert.equal(finding.severity, 'high');
    assert.equal(finding.type, 'unverifiable_acceptance');

    assert.equal(evaluateGateSpecPlan('0001', paths.workDir).result, 'blocked');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validatePlanAcceptance rejeita RED que roda a suíte inteira', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({ red: { command: 'bun test', description: 'roda tudo' } })],
    });

    const finding = validatePlanAcceptance(paths.workDir).find((f) => f.id === 'FIND-RED-GENERIC-1.1');
    assert.ok(finding, 'RED `bun test` sem alvo deve gerar FIND-RED-GENERIC-1.1');
    assert.equal(finding.severity, 'high');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validatePlanAcceptance rejeita AC ausente, arquivos ausentes e caminho placeholder', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({ acceptance_criteria: [], implementation_files: [], test_files: ['tests/'] })],
    });

    const ids = validatePlanAcceptance(paths.workDir).map((f) => f.id);
    assert.ok(ids.includes('FIND-AC-MISSING-1.1'), 'sem AC deve gerar FIND-AC-MISSING-1.1');
    assert.ok(ids.includes('FIND-FILES-MISSING-1.1-implementation_files'), 'sem implementation_files deve gerar FIND-FILES-MISSING');
    assert.ok(ids.includes('FIND-FILES-PLACEHOLDER-1.1-tests/'), 'diretório em test_files deve gerar FIND-FILES-PLACEHOLDER');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validatePlanAcceptance rejeita AC vácuo (`true`) como critério de aceite', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({ acceptance_criteria: [{ command: 'true', description: 'passa sempre' }] })],
    });

    const finding = validatePlanAcceptance(paths.workDir).find((f) => f.id === 'FIND-AC-GENERIC-1.1-1');
    assert.ok(finding, 'AC `true` deve gerar FIND-AC-GENERIC-1.1-1');
    assert.equal(finding.severity, 'high');
    assert.match(finding.description, /não exercita comportamento/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('validatePlanAcceptance rejeita AC que apenas repete um gate global', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({ acceptance_criteria: [{ command: 'bun test', description: 'repete o gate' }] })],
      global_gates: ['`bun test` — a suíte passa'],
    });

    const finding = validatePlanAcceptance(paths.workDir).find((f) => f.id === 'FIND-AC-GENERIC-1.1-1');
    assert.ok(finding, 'AC igual a um gate global deve gerar FIND-AC-GENERIC-1.1-1');
    assert.equal(finding.severity, 'high');
    assert.match(finding.description, /repete um gate/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PLAN-CONTRACT bloqueia task cujo contract_id não existe no Work', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, { tasks: [taskValida({ contract_id: 'CTR-999' })] });

    const gate = evaluateGatePlanContract('0001', paths.workDir);
    const finding = gate.findings.find((f) => f.id === 'FIND-SEM-CTR-MISSING-1.1');
    assert.ok(finding, 'contrato ausente deve gerar FIND-SEM-CTR-MISSING-1.1');
    assert.equal(finding.severity, 'high');
    assert.equal(gate.result, 'blocked');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PLAN-CONTRACT rejeita AC não autorizado pelos comandos do contrato', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, { tasks: [taskValida({ contract_id: 'CTR-001' })] });
    writeContract(paths.workDir, 'CTR-001', contratoValido({
      acceptance_contract: { commands: ['bun run check'] },
    }));

    const findings = evaluateGatePlanContract('0001', paths.workDir).findings;
    const finding = findings.find((f) => f.id === 'FIND-SEM-CTR-AC-1.1-1');
    assert.ok(finding, 'AC fora dos comandos do contrato deve gerar FIND-SEM-CTR-AC-1.1-1');
    assert.equal(finding.severity, 'high');
    assert.equal(finding.type, 'conflict');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PLAN-CONTRACT exige frozen_tests a partir de risco L3 (e não em L2)', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, { tasks: [taskValida({ contract_id: 'CTR-001' })] });

    writeContract(paths.workDir, 'CTR-001', contratoValido({
      risk: { level: 'L3' },
      acceptance_contract: { commands: ['bun test'] },
    }));
    let findings = evaluateGatePlanContract('0001', paths.workDir).findings;
    const required = findings.find((f) => f.id === 'FIND-SEM-CTR-FROZEN-REQUIRED-1.1');
    assert.ok(required, 'risco L3 sem frozen_tests deve exigir congelamento');
    assert.equal(required.severity, 'high');

    // L2 está abaixo de FROZEN_TESTS_REQUIRED_FROM_RISK: não exige congelamento.
    writeContract(paths.workDir, 'CTR-001', contratoValido({
      risk: { level: 'L2' },
      acceptance_contract: { commands: ['bun test'] },
    }));
    findings = evaluateGatePlanContract('0001', paths.workDir).findings;
    assert.equal(findings.some((f) => f.id === 'FIND-SEM-CTR-FROZEN-REQUIRED-1.1'), false,
      'risco L2 não deve exigir frozen_tests');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PLAN-CONTRACT rejeita teste congelado que nenhum AC exercita', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, {
      tasks: [taskValida({
        contract_id: 'CTR-001',
        acceptance_criteria: [{ command: 'bun test tests/y.test.ts', description: 'aponta para outro arquivo' }],
      })],
    });
    writeContract(paths.workDir, 'CTR-001', contratoValido({
      risk: { level: 'L2' },
      acceptance_contract: {
        commands: ['bun test'],
        frozen_tests: [{ path: 'tests/x.test.ts', sha256: 'a'.repeat(64) }],
      },
    }));

    let findings = evaluateGatePlanContract('0001', paths.workDir).findings;
    const unused = findings.find((f) => f.id === 'FIND-SEM-CTR-FROZEN-UNUSED-1.1-tests/x.test.ts');
    assert.ok(unused, 'teste congelado não citado por AC deve gerar FIND-SEM-CTR-FROZEN-UNUSED');
    assert.equal(unused.severity, 'high');

    // Quando o AC cita o arquivo congelado, o finding desaparece.
    writePlan(paths.workDir, {
      tasks: [taskValida({
        contract_id: 'CTR-001',
        acceptance_criteria: [{ command: 'bun test tests/x.test.ts', description: 'exercita o teste congelado' }],
      })],
    });
    findings = evaluateGatePlanContract('0001', paths.workDir).findings;
    assert.equal(findings.some((f) => f.id === 'FIND-SEM-CTR-FROZEN-UNUSED-1.1-tests/x.test.ts'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('GATE-PLAN-CONTRACT rejeita frozen_tests malformado (sem sha256)', () => {
  const root = fixture();
  try {
    const paths = initWorkDirectory('0001', root);
    writePlan(paths.workDir, { tasks: [taskValida({ contract_id: 'CTR-001' })] });
    writeContract(paths.workDir, 'CTR-001', contratoValido({
      risk: { level: 'L2' },
      acceptance_contract: {
        commands: ['bun test'],
        frozen_tests: [{ path: 'tests/x.test.ts' }],
      },
    }));

    const finding = evaluateGatePlanContract('0001', paths.workDir).findings
      .find((f) => f.id === 'FIND-SEM-CTR-FROZEN-INVALID-1.1');
    assert.ok(finding, 'entrada sem sha256 deve gerar FIND-SEM-CTR-FROZEN-INVALID-1.1');
    assert.equal(finding.severity, 'high');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
