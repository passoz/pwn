import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TARGET_CAPABILITY_MATRIX, validateTargetSupport } from '../src/core/target-materializer.js';
import { materializePiTarget } from '../src/targets/pi.js';
import { materializeOpenCodeTarget } from '../src/targets/opencode.js';
import { materializeOmpTarget } from '../src/targets/omp.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-targets-test-'));
}

test('TARGET_CAPABILITY_MATRIX define matriz de capacidades para pi, opencode, omp e raw', () => {
  assert.ok(TARGET_CAPABILITY_MATRIX.pi);
  assert.ok(TARGET_CAPABILITY_MATRIX.opencode);
  assert.ok(TARGET_CAPABILITY_MATRIX.omp);
  assert.ok(TARGET_CAPABILITY_MATRIX.raw);

  assert.equal(TARGET_CAPABILITY_MATRIX.pi.supportsContractV4, true);
  assert.equal(TARGET_CAPABILITY_MATRIX.omp.supportsContractV4, false);
});

test('validateTargetSupport valida requisitos mínimos de um target', () => {
  const piCheck = validateTargetSupport('pi', ['supportsContractV4', 'supportsToolCalling']);
  assert.equal(piCheck.valid, true);

  const ompCheck = validateTargetSupport('omp', ['supportsContractV4', 'supportsToolCalling']);
  assert.equal(ompCheck.valid, false);
  assert.equal(ompCheck.missing.length, 2);
});

test('materializePiTarget gera artefatos específicos do Pi', () => {
  const root = fixture();
  try {
    const res = materializePiTarget(root);
    assert.equal(res.success, true);
    assert.ok(existsSync(path.join(root, 'AGENTS.md')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('materializeOpenCodeTarget gera opencode.jsonc e AGENTS.md', () => {
  const root = fixture();
  try {
    const res = materializeOpenCodeTarget(root);
    assert.equal(res.success, true);
    assert.ok(existsSync(path.join(root, 'AGENTS.md')));
    assert.ok(existsSync(path.join(root, 'opencode.jsonc')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('materializeOmpTarget gera omp.json e reporta degradação graciosa', () => {
  const root = fixture();
  try {
    const res = materializeOmpTarget(root);
    assert.equal(res.success, true);
    assert.ok(existsSync(path.join(root, 'omp.json')));
    assert.ok(res.unsupportedCapabilities.includes('supportsContractV4'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
