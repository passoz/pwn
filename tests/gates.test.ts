import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId } from '../src/core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec } from '../src/core/gates.js';

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

test('initWorkDirectory cria a estrutura completa sob .piwerness/work/<work-id>/', () => {
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
