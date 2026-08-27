import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { recordMetrics, readMetrics, generateOptimizationSuggestions } from '../src/core/metrics.js';
import { addLearning, readLearnings } from '../src/core/learnings.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-metrics-test-'));
}

test('recordMetrics e readMetrics gravam e lêem métricas JSONL em .piwerness/metrics.jsonl', () => {
  const root = fixture();
  try {
    recordMetrics({
      timestamp: new Date().toISOString(),
      runId: 'RUN-100',
      workId: '0001',
      taskId: 'T-001',
      agentRole: 'cheap',
      model: 'qwen3.5:27b',
      tokensInput: 1000,
      tokensOutput: 500,
      costUSD: 0.002,
      durationMs: 1200,
      status: 'success',
      attempts: 1,
    }, root);

    const entries = readMetrics(root);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].runId, 'RUN-100');
    assert.equal(entries[0].costUSD, 0.002);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('generateOptimizationSuggestions sugere otimizações de routing sem alterar arquivos', () => {
  const root = fixture();
  try {
    recordMetrics({
      timestamp: new Date().toISOString(),
      runId: 'RUN-200',
      workId: '0001',
      taskId: 'T-002',
      agentRole: 'strong',
      model: 'claude-3-7-sonnet',
      tokensInput: 5000,
      tokensOutput: 2000,
      costUSD: 0.05,
      durationMs: 3000,
      status: 'success',
      attempts: 1,
    }, root);

    const suggestions = generateOptimizationSuggestions(root);
    assert.ok(suggestions.length > 0);
    assert.equal(suggestions[0].recommendedRole, 'cheap');
    assert.ok(suggestions[0].estimatedSavingsPercent > 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('addLearning e readLearnings persistem lições aprendidas (Teach Skills)', () => {
  const root = fixture();
  try {
    const lrn = addLearning({
      category: 'architecture',
      title: 'Usar ES Modules (.js) no Node/Bun',
      description: 'Ao importar módulos locais em TypeScript/Bun compilados para ESM, usar extensões .js no import.',
      tags: ['esm', 'typescript', 'bun'],
    }, root);

    assert.ok(lrn.id);
    const learnings = readLearnings(root);
    assert.equal(learnings.length, 1);
    assert.equal(learnings[0].title, 'Usar ES Modules (.js) no Node/Bun');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
