import assert from 'node:assert/strict';
import test from 'node:test';
import { createDefaultContractV4, BudgetController } from '../src/core/contract-engine.js';
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

test('createDefaultContractV4 escala budget por risk level', () => {
  const l0 = createDefaultContractV4('T-001', '0001', 'Low Risk', 'L0');
  assert.equal(l0.budget_contract.max_tokens, 10_000);
  assert.equal(l0.budget_contract.max_cost_usd, 0.10);
  assert.equal(l0.budget_contract.max_attempts, 3);

  const l4 = createDefaultContractV4('T-002', '0001', 'High Risk', 'L4');
  assert.equal(l4.budget_contract.max_tokens, 200_000);
  assert.equal(l4.budget_contract.max_cost_usd, 5.00);
  assert.equal(l4.budget_contract.max_attempts, 2);
  assert.equal(l4.escalation_contract.on_budget_exceeded, 'human_review');
});

test('createDefaultContractV4 aceita overrides customizados', () => {
  const contract = createDefaultContractV4('T-003', '0001', 'Custom Task', 'L2', {
    writeAllow: ['lib/**'],
    writeDeny: ['node_modules/**'],
    invariants: ['Custom invariant'],
    scenarios: [{
      id: 'SC-001',
      given: 'Custom given',
      when: 'Custom when',
      then: 'Custom then',
    }],
  });
  assert.deepEqual(contract.scope_contract.write_allow, ['lib/**']);
  assert.deepEqual(contract.scope_contract.write_deny, ['node_modules/**']);
  assert.deepEqual(contract.architecture_contract.invariants, ['Custom invariant']);
  assert.equal(contract.behavioral_contract.scenarios[0].id, 'SC-001');
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

// ── BudgetController tests ─────────────────────────────────────────

test('BudgetController rastreia tokens, custo e tentativas', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Budget Test', 'L1');
  const budget = new BudgetController(contract);

  budget.recordTokens(1000);
  budget.recordCost(0.01);
  budget.recordAttempt();

  const usage = budget.getUsage();
  assert.equal(usage.tokens, 1000);
  assert.equal(usage.costUsd, 0.01);
  assert.equal(usage.attempts, 1);
  assert.ok(usage.durationMs >= 0);
});

test('BudgetController detecta violação de tentativas', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Budget Test', 'L1');
  const budget = new BudgetController(contract);

  // L1 default max_attempts = 3
  budget.recordAttempt();
  budget.recordAttempt();
  assert.equal(budget.checkBudget(), null); // 2/3 OK

  budget.recordAttempt();
  const violation = budget.checkBudget();
  assert.ok(violation !== null);
  assert.equal(violation!.reason, 'max_attempts');
});

test('BudgetController detecta violação de tokens', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Budget Test', 'L0');
  const budget = new BudgetController(contract);

  // L0 default max_tokens = 10000
  budget.recordTokens(9999);
  assert.equal(budget.checkBudget(), null);

  budget.recordTokens(1);
  const violation = budget.checkBudget();
  assert.ok(violation !== null);
  assert.equal(violation!.reason, 'max_tokens');
});

test('BudgetController shouldInterrupt retorna true quando limite excedido', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Budget Test', 'L0');
  const budget = new BudgetController(contract);

  assert.equal(budget.shouldInterrupt(), false);
  budget.recordTokens(10_000);
  assert.equal(budget.shouldInterrupt(), true);
});
