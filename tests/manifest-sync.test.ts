import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, parsePlanTask, taskDefinitionDigest } from '../src/core/acceptance.js';
import { collectPlanStatus } from '../src/core/project_status.js';
import { loadManifest, reserveWork, WORK_MANIFEST_STATES } from '../src/core/work-manifest.js';
import { syncWorkManifest } from '../src/core/manifest-sync.js';

const MANIFEST_STATES: readonly string[] = WORK_MANIFEST_STATES;

function fixture() {
  return mkdtempSync(path.join(tmpdir(), 'pwn-sync-'));
}

/** Bloco de task v3 estruturalmente válido com arquivos concretos e RED/AC focados. */
function taskBlock(id: string, marker: string, requirementId: string, title: string): string {
  return `### [${marker}] [${id}] ${title}

**Requirement:** ${requirementId}
**Depends on:** none
**Behavior:** ${title} produz um resultado observável.
**Components:** core
**Files:** src/${id}.ts, tests/${id}.test.ts
**Implementation files:** src/${id}.ts
**Test files:** tests/${id}.test.ts

**RED:**
- \`bun test tests/${id}.test.ts\` — exit não-zero nomeando a nova asserção.

**Implementation:**
1. Implemente apenas o resultado observável declarado.

**ACs:**
- [ ] \`bun test tests/${id}.test.ts\` — exit 0 verificando o resultado observável.

**Visual:** N/A

**Documentation:** N/A
`;
}

/** Plano v3 válido com um gate global pendente (declarado, sem evidência assinada). */
function planText(tasks: string[], workId: string): string {
  return `# Tasks: manifest sync

**Contract version:** 3
**Work ID:** ${workId}

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| \`core\` | \`.\` | \`bun test\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` |

## Global gates
- [ ] \`bun test\` — a suíte passa.

${tasks.join('\n')}`;
}

/** Evidência TDD GREEN mínima reconhecida pelo status: snapshots vazios + verify PASS. */
function writeGreenEvidence(root: string, workId: string, taskId: string): void {
  const stateDirectory = path.join(root, '.todo', 'evidence', workId, 'state');
  const evidenceDirectory = path.join(root, '.todo', 'evidence', workId);
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(path.join(stateDirectory, `${taskId}.json`), JSON.stringify({
    task: taskId,
    baseline_implementation: {},
    baseline_tests: {},
    red_tests: {},
    green_implementation: {},
    green_tests: {},
  }), 'utf8');
  writeFileSync(path.join(evidenceDirectory, `${taskId}-verify.log`), 'VERDICT: PASS\n', 'utf8');
}

/** Atestação de aceitação v3 assinada, como `pwn work audit candidate` a emitiria. */
function writeAttestation(root: string, workId: string, plan: string, taskId: string): void {
  const key = 'manifest-sync-test-key';
  mkdirSync(path.join(root, '.pwn'), { recursive: true });
  writeFileSync(path.join(root, '.pwn', '.verifier_key'), key, 'utf8');

  const task = parsePlanTask(plan, taskId);
  assert.ok(task, `a task ${taskId} precisa existir no plano do fixture`);
  const subject = {
    version: 3,
    kind: 'task-acceptance-candidate',
    harness_version: '0.1.0',
    gate_version: '1',
    work_id: workId,
    task_id: taskId,
    result: 'pass',
    plan: { task_definition_sha256: taskDefinitionDigest(plan, task) },
    implementation: {},
    tests: {},
    frozen_tests: [],
    generated_at: new Date().toISOString(),
  };
  const signature = createHmac('sha256', key).update(canonicalJson(subject)).digest('hex');
  const directory = path.join(root, '.todo', 'attestations', workId);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, `${taskId}-candidate.json`), `${JSON.stringify({ ...subject, signature }, null, 2)}\n`, 'utf8');
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

test('tasks todas aceitas com gate global pendente mantêm o manifest em active', () => {
  const root = fixture();
  try {
    const manifest = reserveWork(root);
    const workId = manifest.work_id;
    const plan = planText([
      taskBlock('1.1', 'x', 'FR-001', 'Criar conta'),
      taskBlock('1.2', 'x', 'FR-002', 'Rejeitar conta duplicada'),
    ], workId);
    mkdirSync(path.join(root, '.todo'), { recursive: true });
    writeFileSync(path.join(root, manifest.artifacts.plan), plan, 'utf8');

    for (const taskId of ['1.1', '1.2']) {
      writeGreenEvidence(root, workId, taskId);
      writeAttestation(root, workId, plan, taskId);
    }

    // Precondição observável: o panorama é "TASKS COMPLETE" (tudo aceito, gate sem evidência),
    // não "COMPLETE" — é exatamente esse estado que não pode virar manifest "completed".
    const panorama = collectPlanStatus(workId, root).panorama;
    assert.equal(panorama?.state, 'TASKS COMPLETE');
    assert.equal(panorama?.counts.unverifiedChecked, 0);

    const state = syncWorkManifest(workId, root);
    assert.ok(MANIFEST_STATES.includes(state), `estado fora do vocabulário do manifest: ${state}`);
    assert.equal(state, 'active');

    const written = JSON.parse(readFileSync(path.join(root, '.work', `${workId}.json`), 'utf8'));
    assert.equal(written.state, 'active');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
