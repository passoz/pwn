import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync, readFileSync, lstatSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { runOrchestrated, prepareSandbox, modifiedFiles, EXIT_SUSPENDED } from '../src/core/run-orchestrator.js';

function git(cwd: string, ...args: string[]) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
}

function fixture(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-orch-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'Test');
  // Arquivo commitado que escreve FORA do escopo quando executado.
  writeFileSync(path.join(root, 'out-of-scope.js'), "require('fs').writeFileSync('forbidden.txt','x');\n", 'utf8');
  git(root, 'add', '.');
  git(root, 'commit', '-qm', 'seed');
  return root;
}

function writeWork(root: string, acceptanceCommand: string) {
  const workDir = path.join(root, '.piwerness', 'work', '0001');
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, 'plan.json'), JSON.stringify({
    work_id: '0001',
    title: 't',
    components: [{ name: 'core', purpose: 'nucleo' }],
    global_gates: ['suite'],
    tasks: [
      {
        id: '1.1',
        title: 'Task',
        requirement_id: 'FR-001',
        spec_reference: 'CAP-001',
        contract_id: 'CTR-001',
        depends_on: [],
        components: ['core'],
        files: ['out-of-scope.js'],
        implementation_files: ['out-of-scope.js'],
        test_files: ['out-of-scope.js'],
        red: { command: 'node out-of-scope.js', description: 'falha esperada' },
        implementation_steps: ['step'],
        acceptance_criteria: [{ command: 'node out-of-scope.js', description: 'passa' }],
      },
    ],
  }), 'utf8');
  writeFileSync(path.join(workDir, 'CTR-001.json'), JSON.stringify({
    contract_version: '4.0',
    task_id: '1.1',
    work_id: '0001',
    title: 'Task',
    risk: { level: 'L2', reasons: ['teste'] },
    validation_strategy: 'tdd-strict',
    behavioral_contract: { scenarios: [] },
    change_contract: { target_files: [], affected_components: [] },
    architecture_contract: { invariants: [] },
    acceptance_contract: { commands: [acceptanceCommand], required_evidence: [] },
    scope_contract: { write_allow: ['allowed.txt'], write_deny: [] },
    budget_contract: { max_agent_attempts: 3, max_shell_executions: 10 },
    escalation_contract: { on_write_violation: 'block_and_escalate', on_budget_exceeded: 'escalate_to_strong_agent', on_attempt_failed: 'retry_with_strong' },
  }), 'utf8');
}

test('runOrchestrated detecta escrita fora do escopo e limpa o sandbox', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'out-of-scope.js'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.diffViolations.length > 0, true, 'deve reportar violação de diff');
    assert.match(result.diffViolations[0], /forbidden\.txt/);
    assert.equal(result.status, 1);

    // Sandbox removido após a execução.
    const sandboxes = path.join(root, '.piwerness', 'sandboxes');
    const leftovers = existsSync(sandboxes) ? spawnSync('bash', ['-c', `ls -A '${sandboxes}'`], { encoding: 'utf8' }).stdout.trim() : '';
    assert.equal(leftovers, '', 'sandbox deve ser removido após a run');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('runOrchestrated nega comando fora da allowlist da política', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['echo', 'hi'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /allowlist|negado|policy/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('prepareSandbox linka node_modules e copia bunfig.toml', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-prep-'));
  const sandbox = mkdtempSync(path.join(tmpdir(), 'pwn-prep-sb-'));
  try {
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'bunfig.toml'), '[test]\nroot = "tests"\n', 'utf8');

    prepareSandbox(sandbox, root);

    assert.equal(lstatSync(path.join(sandbox, 'node_modules')).isSymbolicLink(), true, 'node_modules deve ser symlink');
    assert.equal(existsSync(path.join(sandbox, 'bunfig.toml')), true, 'bunfig.toml deve ser copiado');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(sandbox, { recursive: true, force: true });
  }
});

test('runOrchestrated suspende e enfileira tarefas L4 sem executar', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    // Sobrescreve o contrato para risco L4.
    const ctrPath = path.join(root, '.piwerness', 'work', '0001', 'CTR-001.json');
    const ctr = JSON.parse(readFileSync(ctrPath, 'utf8'));
    ctr.risk = { level: 'L4', reasons: ['teste'] };
    writeFileSync(ctrPath, JSON.stringify(ctr), 'utf8');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'out-of-scope.js'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.suspended, true);
    assert.equal(result.status, EXIT_SUSPENDED);
    assert.equal(existsSync(path.join(root, 'queue', 'review', `${result.runId}.json`)), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('runOrchestrated não reporta node_modules injetado pelo harness como violação de escopo', () => {
  const root = fixture();
  try {
    // Formato canônico de .gitignore (com barra): não cobre o symlink que o harness cria.
    writeFileSync(path.join(root, '.gitignore'), 'node_modules/\n', 'utf8');
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'ok.js'), "require('fs').writeFileSync('allowed.txt','x');\n", 'utf8');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'ignore + in-scope script');
    writeWork(root, 'node ok.js');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'ok.js'],
      timeoutSeconds: 10,
      isolated: true,
      rootDir: root,
    });

    assert.deepEqual(result.diffViolations, [], 'artefato do próprio harness não é escrita do agente');
    assert.equal(result.status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('modifiedFiles resolve o destino de renames e ignora artefatos injetados', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-diff-parse-'));
  try {
    git(root, 'init', '-q');
    git(root, 'config', 'user.email', 'test@example.invalid');
    git(root, 'config', 'user.name', 'Test');
    writeFileSync(path.join(root, 'old.txt'), 'x\n', 'utf8');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'seed');

    git(root, 'mv', 'old.txt', 'new.txt');
    writeFileSync(path.join(root, 'forbidden.txt'), 'x\n', 'utf8');
    mkdirSync(path.join(root, 'node_modules'), { recursive: true });
    symlinkSync(path.join(tmpdir(), 'whatever'), path.join(root, 'bunfig.toml'));

    const files = modifiedFiles(root);
    assert.ok(files.includes('new.txt'), 'rename deve ser reportado pelo destino');
    assert.ok(!files.includes('old.txt'), 'rename não deve ser reportado pela origem');
    assert.ok(files.includes('forbidden.txt'), 'escrita real fora do escopo continua detectada');
    assert.ok(!files.includes('node_modules'), 'node_modules injetado é ignorado');
    assert.ok(!files.includes('bunfig.toml'), 'bunfig.toml injetado é ignorado');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
