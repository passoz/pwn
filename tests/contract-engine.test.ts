import assert from 'node:assert/strict';
import test from 'node:test';
import { createDefaultContractV4 } from '../src/core/contract-engine.js';
import { checkFileAgainstScope, checkDiffAgainstContract } from '../src/core/contract-guard.js';
import { generateContextCapsule } from '../src/core/capsule.js';

test('createDefaultContractV4 cria contrato com 7 dimensões', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Task Teste', 'L2');
  assert.equal(contract.contract_version, '4.0');
  assert.equal(contract.task_id, 'T-001');
  assert.equal(contract.risk.level, 'L2');
  assert.ok(contract.behavioral_contract);
  assert.ok(contract.change_contract);
  assert.ok(contract.architecture_contract);
  assert.ok(contract.acceptance_contract);
  assert.ok(contract.scope_contract);
  assert.ok(contract.budget_contract);
  assert.ok(contract.escalation_contract);
});

test('checkFileAgainstScope permite arquivo dentro da allowlist e bloqueia fora', () => {
  const allow = ['src/**', 'tests/**'];
  const deny = ['.git/**', 'package.json'];

  const okResult = checkFileAgainstScope('src/cli.ts', allow, deny);
  assert.equal(okResult.allowed, true);

  const denyResult = checkFileAgainstScope('package.json', allow, deny);
  assert.equal(denyResult.allowed, false);
  assert.equal(denyResult.violationType, 'write_deny');

  const unallowedResult = checkFileAgainstScope('secret.env', allow, deny);
  assert.equal(unallowedResult.allowed, false);
  assert.equal(unallowedResult.violationType, 'not_in_write_allow');
});

test('checkDiffAgainstContract detecta violações em um lote de arquivos modificados', () => {
  const modified = ['src/cli.ts', 'package.json', 'unauthorized.js'];
  const allow = ['src/**'];
  const deny = ['package.json'];

  const report = checkDiffAgainstContract(modified, allow, deny);
  assert.equal(report.passed, false);
  assert.equal(report.violations.length, 2);
});

test('generateContextCapsule formata os limites e cenários da cápsula', () => {
  const contract = createDefaultContractV4('T-002', '0001', 'Cápsula Teste', 'L1');
  const capsule = generateContextCapsule({ task: contract });

  assert.match(capsule, /PWN TASK CONTEXT CAPSULE \(v4\.0\)/);
  assert.match(capsule, /TASK ID:\s+T-002/);
  assert.match(capsule, /WRITE ALLOW:/);
  assert.match(capsule, /WRITE DENY \(PROHIBITED\):/);
});
