import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadManifest, reserveWork, WORK_MANIFEST_STATES } from '../src/core/work-manifest.js';
import { syncWorkManifest } from '../src/core/manifest-sync.js';

const MANIFEST_STATES: readonly string[] = WORK_MANIFEST_STATES;

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-sync-'));
}

test('syncWorkManifest projeta o panorama no vocabulário canônico do manifest', () => {
  const root = fixture();
  try {
    const manifest = reserveWork(root);
    mkdirSync(path.join(root, '.todo'), { recursive: true });
    // Plano estruturalmente inválido → panorama "INVALID PLAN".
    writeFileSync(path.join(root, manifest.artifacts.plan), '# Tasks: broken\n', 'utf8');

    const state = syncWorkManifest(manifest.work_id, root);
    assert.ok(MANIFEST_STATES.includes(state), `estado fora do vocabulário do manifest: ${state}`);
    assert.equal(state, 'active');

    const written = JSON.parse(readFileSync(path.join(root, '.work', `${manifest.work_id}.json`), 'utf8'));
    assert.equal(written.state, state);
    // O estado gravado é aceito pelo vocabulário oficial (updateManifest não rejeitaria).
    assert.ok(MANIFEST_STATES.includes(written.state));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('syncWorkManifest retorna manifest-ausente quando não há manifest', () => {
  const root = fixture();
  try {
    assert.equal(syncWorkManifest('0001', root), 'manifest-ausente');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('manifest legado com state fora do vocabulário é lido como invalid e reparável', () => {
  const root = fixture();
  try {
    const manifest = reserveWork(root);
    const manifestFile = path.join(root, '.work', `${manifest.work_id}.json`);
    const legacy = JSON.parse(readFileSync(manifestFile, 'utf8'));
    legacy.state = 'in_progress'; // vocabulário antigo, escrito pelo sync pré-correção
    writeFileSync(manifestFile, JSON.stringify(legacy, null, 2), 'utf8');

    assert.equal(loadManifest(root, manifest.work_id).state, 'invalid');

    mkdirSync(path.join(root, '.todo'), { recursive: true });
    writeFileSync(path.join(root, manifest.artifacts.plan), '# Tasks: broken\n', 'utf8');
    assert.equal(syncWorkManifest(manifest.work_id, root), 'active');
    assert.equal(loadManifest(root, manifest.work_id).state, 'active');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
