import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateEscalation, DEFAULT_ROUTING_TABLE } from '../src/core/router.js';
import { createGitWorktreeSandbox, cleanupGitWorktreeSandbox } from '../src/core/sandbox.js';
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

test('DEFAULT_ROUTING_TABLE possui modelos configurados para cada papel', () => {
  assert.ok(DEFAULT_ROUTING_TABLE.cheap.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.strong.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.review.defaultModel);
  assert.ok(DEFAULT_ROUTING_TABLE.plan.defaultModel);
});

test('createGitWorktreeSandbox e cleanupGitWorktreeSandbox gerenciam o isolamento do sandbox', () => {
  const session = createGitWorktreeSandbox('test-run-001');
  assert.ok(session.runId);
  assert.ok(session.worktreePath);

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
