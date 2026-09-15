import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { scaffoldWork, scaffoldContract } from '../src/core/scaffold.js';
import { validateWorkDocuments } from '../src/core/validator.js';
import { evaluateGateDiscReq, evaluateGatePlanContract, evaluateGatePrdSpec, evaluateGateReqPrd, evaluateGateSpecPlan } from '../src/core/gates.js';
import { loadPlan, normalizeMarkers, renderTasksMarkdown } from '../src/core/plan-renderer.js';
import { loadTaskContract } from '../src/core/task-contract.js';
import { validateTasks } from '../src/core/validate_tasks.js';
import { getNextWorkId } from '../src/core/work-artifacts.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-scaffold-'));
}

test('scaffoldWork cria uma cadeia completa e válida nos schemas', () => {
  const root = fixture();
  try {
    const result = scaffoldWork({ rootDir: root, title: 'Módulo de Pagamentos PIX' });
    assert.equal(result.workId, '0001');
    const workDir = path.join(root, '.piwerness', 'work', '0001');

    for (const file of ['discovery.json', 'requirements.json', 'prd.json', 'spec.json', 'plan.json', 'CTR-001.json', 'traceability-matrix.json']) {
      assert.ok(existsSync(path.join(workDir, file)), `faltou ${file}`);
    }
    assert.ok(existsSync(path.join(root, '.todo', '0001-tasks.md')));

    const validation = validateWorkDocuments('0001', root);
    assert.equal(validation.length, 2, 'plan.json e prd.json devem ser validados');
    for (const entry of validation) {
      assert.deepEqual(entry.errors, [], `${entry.file}: ${entry.errors.join('; ')}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldWork passa nos 5 gates e no validador v3 do plano', () => {
  const root = fixture();
  try {
    scaffoldWork({ rootDir: root, title: 'Módulo de Pagamentos PIX' });
    const workDir = path.join(root, '.piwerness', 'work', '0001');

    const gates = [
      evaluateGateDiscReq('0001', workDir),
      evaluateGateReqPrd('0001', workDir),
      evaluateGatePrdSpec('0001', workDir),
      evaluateGateSpecPlan('0001', workDir),
      evaluateGatePlanContract('0001', workDir),
    ];
    for (const gate of gates) {
      assert.notEqual(gate.result, 'blocked', `${gate.gate}: ${JSON.stringify(gate.findings)}`);
    }

    const markdownPath = path.join(root, '.todo', '0001-tasks.md');
    assert.deepEqual(validateTasks(markdownPath), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldWork gera um plano que faz round-trip byte-a-byte no markdown', () => {
  const root = fixture();
  try {
    scaffoldWork({ rootDir: root, title: 'Módulo de Pagamentos PIX' });
    const plan = loadPlan('0001', root);
    assert.ok(plan);
    const markdown = readFileSync(path.join(root, '.todo', '0001-tasks.md'), 'utf8');
    assert.equal(normalizeMarkers(markdown), normalizeMarkers(renderTasksMarkdown(plan)));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldWork congela um contrato V4 carregável com comandos de aceitação', () => {
  const root = fixture();
  try {
    scaffoldWork({ rootDir: root, title: 'Módulo de Pagamentos PIX', risk: 'L3' });
    const contract = loadTaskContract('0001', '1.1', root);
    assert.equal(contract.contract_version, '4.0');
    assert.equal(contract.risk.level, 'L3');
    assert.equal(contract.validation_strategy, 'tdd-strict');
    assert.ok(contract.acceptance_contract.commands.includes('bun test'));
    assert.ok(contract.scope_contract.write_allow.length > 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldWork faz auto-incremento e não sobrescreve sem --force', () => {
  const root = fixture();
  try {
    scaffoldWork({ rootDir: root, title: 'Primeiro módulo' });
    assert.equal(getNextWorkId(root), '0002');

    const second = scaffoldWork({ rootDir: root, title: 'Segundo módulo', workId: '0001' });
    assert.equal(second.generated.length, 0);
    assert.ok(second.skipped.length > 0);

    const forced = scaffoldWork({ rootDir: root, title: 'Segundo módulo', workId: '0001', force: true });
    assert.ok(forced.generated.length > 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldWork rejeita título curto e Work ID inválido', () => {
  const root = fixture();
  try {
    assert.throws(() => scaffoldWork({ rootDir: root, title: 'abc' }), /--title/);
    assert.throws(() => scaffoldWork({ rootDir: root, title: 'Título válido', workId: '1' }), /Work ID inválido/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scaffoldContract monta a allowlist de shell a partir da aceitação', () => {
  const contract = scaffoldContract('0001', '1.1', 'Tarefa', 'L2');
  assert.deepEqual(contract.acceptance_contract.commands, ['bun test', 'bun run check']);
  assert.equal(contract.risk.level, 'L2');
});
