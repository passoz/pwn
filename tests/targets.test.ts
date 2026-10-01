import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  TARGET_CAPABILITY_MATRIX,
  deriveUnsupportedCapabilities,
  validateTargetSupport,
  TargetContractContext,
} from '../src/core/target-materializer.js';
import { materializePiTarget } from '../src/targets/pi.js';
import { materializeOpenCodeTarget } from '../src/targets/opencode.js';
import { materializeOmpTarget } from '../src/targets/omp.js';

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-targets-test-'));
}

const scopeContext: TargetContractContext = {
  writeAllow: ['src/**'],
  writeDeny: ['schemas/**'],
  acceptanceCommands: ['bun test'],
  riskLevel: 'L2',
  taskCount: 1,
};

test('TARGET_CAPABILITY_MATRIX define matriz de capacidades para pi, opencode, omp e raw', () => {
  assert.ok(TARGET_CAPABILITY_MATRIX.pi);
  assert.ok(TARGET_CAPABILITY_MATRIX.opencode);
  assert.ok(TARGET_CAPABILITY_MATRIX.omp);
  assert.ok(TARGET_CAPABILITY_MATRIX.raw);

  assert.equal(TARGET_CAPABILITY_MATRIX.pi.supportsContractV4, true);
  assert.equal(TARGET_CAPABILITY_MATRIX.opencode.supportsContractV4, true);
  assert.equal(TARGET_CAPABILITY_MATRIX.omp.supportsContractV4, true);
  assert.equal(TARGET_CAPABILITY_MATRIX.raw.supportsContractV4, false);
});

test('omp (oh my pi) declara suporte a tools, subagentes, skills e worktree', () => {
  const omp = TARGET_CAPABILITY_MATRIX.omp;
  assert.equal(omp.name, 'omp (oh my pi) Coding Agent');
  assert.equal(omp.supportsToolCalling, true);
  assert.equal(omp.supportsSubagents, true);
  assert.equal(omp.supportsSkills, true);
  assert.equal(omp.supportsWorktreeSandbox, true);
  assert.equal(omp.promptFileFormat, 'AGENTS.md');
});

test('validateTargetSupport valida requisitos mínimos de um target', () => {
  const piCheck = validateTargetSupport('pi', ['supportsContractV4', 'supportsToolCalling']);
  assert.equal(piCheck.valid, true);

  const ompCheck = validateTargetSupport('omp', ['supportsContractV4', 'supportsToolCalling']);
  assert.equal(ompCheck.valid, true);

  const rawCheck = validateTargetSupport('raw', ['supportsContractV4', 'supportsToolCalling']);
  assert.equal(rawCheck.valid, false);
  assert.equal(rawCheck.missing.length, 2);
});

test('deriveUnsupportedCapabilities deriva a degradação da matriz (sem array hard-coded)', () => {
  assert.deepEqual(deriveUnsupportedCapabilities('pi'), []);
  assert.deepEqual(deriveUnsupportedCapabilities('opencode'), []);
  assert.deepEqual(deriveUnsupportedCapabilities('omp'), []);

  const raw = deriveUnsupportedCapabilities('raw');
  assert.ok(raw.includes('supportsToolCalling'));
  assert.ok(raw.includes('supportsContractV4'));
});

test('materializePiTarget gera artefatos específicos do Pi', () => {
  const root = fixture();
  try {
    const res = materializePiTarget(root);
    assert.equal(res.success, true);
    assert.ok(existsSync(path.join(root, 'AGENTS.md')));
    assert.ok(res.notes.some((n) => n.includes('Instale')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('materializeOpenCodeTarget gera opencode.jsonc válido e AGENTS.md', () => {
  const root = fixture();
  try {
    const res = materializeOpenCodeTarget(root);
    assert.equal(res.success, true);
    assert.ok(existsSync(path.join(root, 'AGENTS.md')));
    assert.ok(existsSync(path.join(root, 'opencode.jsonc')));

    const config = JSON.parse(readFileSync(path.join(root, 'opencode.jsonc'), 'utf8'));
    assert.equal(config.$schema, 'https://opencode.ai/config.json');
    assert.equal(config.agent, undefined);
    assert.equal(config.version, undefined);
    assert.equal(config.sandbox, undefined);
    assert.equal(config.permission.edit, 'allow');
    assert.equal(config.permission.bash, 'allow');
    assert.ok(res.notes.some((n) => n.includes('Instale')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('materializeOmpTarget gera AGENTS.md e .omp/config.yml', () => {
  const root = fixture();
  try {
    const res = materializeOmpTarget(root);
    assert.equal(res.success, true);
    assert.deepEqual(res.unsupportedCapabilities, []);

    const agentsPath = path.join(root, 'AGENTS.md');
    const configPath = path.join(root, '.omp', 'config.yml');
    assert.ok(existsSync(agentsPath));
    assert.ok(existsSync(configPath));

    const config = readFileSync(configPath, 'utf8');
    assert.match(config, /^tools:/m);
    assert.match(config, /^\s+approvalMode: yolo$/m);
    assert.ok(res.notes.some((n) => n.includes('.omp/config.yml')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('escopo do contrato é injetado sem perda nos 3 targets (paridade)', () => {
  for (const materialize of [materializePiTarget, materializeOpenCodeTarget, materializeOmpTarget]) {
    const root = fixture();
    try {
      materialize(root, scopeContext);
      const content = readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
      assert.ok(content.includes('WRITE ALLOW'));
      assert.ok(content.includes('src/**'));
      assert.ok(content.includes('WRITE DENY'));
      assert.ok(content.includes('schemas/**'));
      assert.ok(content.includes('VALIDATION COMMANDS'));
      assert.ok(content.includes('bun test'));
      assert.ok(content.includes('RISK LEVEL: L2'));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});
