import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateEscalation, DEFAULT_ROUTING_TABLE, getRoutingTable, saveRoutingConfig, selectForRisk, RISK_ROLE_MAP, RISK_EXECUTION_POLICY } from '../src/core/router.js';
import { createGitWorktreeSandbox, cleanupGitWorktreeSandbox, SandboxError } from '../src/core/sandbox.js';
import { enqueueReview, listQueueItems, updateQueueStatus } from '../src/core/queue.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-executor-test-'));
}

test('evaluateEscalation recomenda escalação para agente forte em caso de violação de escrita ou contrato', () => {
  const writeEsc = evaluateEscalation('cheap', 1, 3, true, false);
  assert.equal(writeEsc.shouldEscalate, true);
  assert.equal(writeEsc.targetRole, 'strong');

  const contractEsc = evaluateEscalation('cheap', 1, 3, false, true);
  assert.equal(contractEsc.shouldEscalate, true);
  assert.equal(contractEsc.targetRole, 'strong');

  const attemptsEsc = evaluateEscalation('cheap', 3, 3, false, false);
  assert.equal(attemptsEsc.shouldEscalate, true);
  assert.equal(attemptsEsc.targetRole, 'strong');

  const normalRun = evaluateEscalation('cheap', 1, 3, false, false);
  assert.equal(normalRun.shouldEscalate, false);
  assert.equal(normalRun.targetRole, 'cheap');
});

test('evaluateEscalation com riskLevel L4 sempre escala para human review', () => {
  const result = evaluateEscalation('cheap', 1, 3, false, false, 'L4');
  assert.equal(result.shouldEscalate, true);
  assert.equal(result.targetRole, 'review');
  assert.ok(result.reason?.includes('L4'));
});

test('evaluateEscalation com riskLevel L3 escala na primeira falha', () => {
  const result = evaluateEscalation('cheap', 1, 3, false, false, 'L3');
  assert.equal(result.shouldEscalate, true);
  assert.equal(result.targetRole, 'strong');
  assert.ok(result.reason?.includes('L3'));
});

test('selectForRisk retorna role e execution policy adequados para cada risk level', () => {
  const l0 = selectForRisk('L0');
  assert.equal(l0.role, 'cheap');
  assert.equal(l0.requiresReview, false);
  assert.equal(l0.executionPolicy.canShell, true);

  const l2 = selectForRisk('L2');
  assert.equal(l2.role, 'cheap');
  assert.equal(l2.requiresReview, true);
  assert.equal(l2.executionPolicy.canNetwork, false);

  const l4 = selectForRisk('L4');
  assert.equal(l4.role, 'strong');
  assert.equal(l4.requiresReview, true);
  assert.equal(l4.executionPolicy.canWrite, false);
  assert.equal(l4.executionPolicy.maxFileWrites, 0);
});

test('RISK_ROLE_MAP e RISK_EXECUTION_POLICY definem mapeamentos consistentes', () => {
  const levels = ['L0', 'L1', 'L2', 'L3', 'L4'] as const;
  for (const level of levels) {
    assert.ok(RISK_ROLE_MAP[level], `RISK_ROLE_MAP missing for ${level}`);
    assert.ok(RISK_EXECUTION_POLICY[level], `RISK_EXECUTION_POLICY missing for ${level}`);
    assert.ok(['cheap', 'strong'].includes(RISK_ROLE_MAP[level].initialRole));
    assert.equal(typeof RISK_EXECUTION_POLICY[level].requiresReview, 'boolean');
  }
});

test('DEFAULT_ROUTING_TABLE possui modelos configurados para cada papel', () => {
  assert.ok(DEFAULT_ROUTING_TABLE.cheap.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.strong.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.review.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.plan.defaultModel);
});

test('getRoutingTable e saveRoutingConfig suportam arquivo de configuracao e variaveis de ambiente', () => {
  const root = fixture();
  try {
    saveRoutingConfig({
      cheap: { defaultModel: 'custom-cheap-model', baseUrl: 'http://localhost:11434/v1', provider: 'ollama', apiKeyEnv: 'OLLAMA_API_KEY', apiKey: 'secret-ollama-key' },
      strong: { defaultModel: 'custom-strong-model', baseUrl: 'https://api.anthropic.com/v1', provider: 'anthropic' },
    }, root);

    const table = getRoutingTable(root);
    assert.equal(table.cheap.defaultModel, 'custom-cheap-model');
    assert.equal(table.cheap.baseUrl, 'http://localhost:11434/v1');
    assert.equal(table.cheap.provider, 'ollama');
    assert.equal(table.cheap.apiKeyEnv, 'OLLAMA_API_KEY');
    assert.equal(table.cheap.apiKey, 'secret-ollama-key');
    assert.equal(table.strong.defaultModel, 'custom-strong-model');
    assert.equal(table.strong.baseUrl, 'https://api.anthropic.com/v1');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('createGitWorktreeSandbox lança SandboxError quando worktree falha', () => {
  // Non-git directory → worktree will fail → should throw SandboxError
  const root = fixture();
  try {
    assert.throws(
      () => createGitWorktreeSandbox('test-run-fail', root),
      (err: any) => err instanceof SandboxError,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('createGitWorktreeSandbox e cleanupGitWorktreeSandbox gerenciam o isolamento do sandbox', () => {
  const session = createGitWorktreeSandbox('test-run-001');
  assert.ok(session.runId);
  assert.ok(session.worktreePath);
  assert.equal(session.created, true);

  cleanupGitWorktreeSandbox(session);
});

test('enqueueReview, listQueueItems e updateQueueStatus gerenciam a fila AFK queue/review/', () => {
  const root = fixture();
  try {
    const item = enqueueReview({
      runId: 'RUN-001',
      workId: '0001',
      taskId: 'T-001',
      title: 'Review de Teste',
      pausedAtStep: 'task_execution',
      reason: 'Risco L4 exige aprovação humana',
      riskLevel: 'L4',
    }, root);

    assert.equal(item.status, 'pending_review');

    const list = listQueueItems(root);
    assert.equal(list.length, 1);
    assert.equal(list[0].runId, 'RUN-001');

    const updated = updateQueueStatus('RUN-001', 'approved', root);
    assert.equal(updated?.status, 'approved');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
