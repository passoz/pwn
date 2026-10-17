import { describe, expect, test } from 'bun:test';
import { spawn } from 'bun';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createGitWorktreeSandbox, cleanupGitWorktreeSandbox, SandboxError } from '../src/core/sandbox.js';

// Estes testes sobem subprocessos REAIS: o PWN paraleliza por processo, e a exclusão
// mútua só é observável com 2+ processos disputando o mesmo arquivo/repositório.
const SRC = path.resolve(import.meta.dirname, '..', 'src', 'core');
const FS_LOCK = path.join(SRC, 'fs-lock.ts');
const METRICS = path.join(SRC, 'metrics.ts');
const ORCHESTRATOR = path.join(SRC, 'run-orchestrator.ts');

interface WorkerResult {
  status: number;
  stdout: string;
  stderr: string;
}

interface RunSummary {
  status: number;
  runId: string;
  stderr: string;
}

/**
 * Prelude comum dos workers: com os imports estáticos já resolvidos, anuncia `READY` e
 * bloqueia em `readFileSync(0)` até o pai fechar o stdin. O pai fecha os N stdins em
 * sequência apertada, então os processos entram na seção crítica quase no mesmo instante
 * em vez de escalonados pelo boot do bun — sem polling nem espera por tempo.
 * `pause` só alarga janelas de corrida DENTRO do worker.
 */
const WORKER_PRELUDE = `
import fs from 'node:fs';
const index = Number(process.env.PWN_TEST_INDEX);
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
fs.writeSync(1, 'READY\\n');
fs.readFileSync(0);
`;

/** Lê o stream até o fim; `onText` recebe o acumulado a cada chunk (para detectar `READY`). */
async function drain(stream: ReadableStream<Uint8Array>, onText: (accumulated: string) => void): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let accumulated = '';
  for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
    accumulated += decoder.decode(chunk.value, { stream: true });
    onText(accumulated);
  }
  return accumulated + decoder.decode();
}

/** Executa `script` (ESM, via `bun -e`) em `count` processos liberados simultaneamente. */
async function runWorkers(count: number, script: string, env: Record<string, string>): Promise<WorkerResult[]> {
  const workers = Array.from({ length: count }, (_, index) => {
    const proc = spawn([process.execPath, '-e', script], {
      env: { ...process.env, ...env, PWN_TEST_INDEX: String(index) },
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const ready = Promise.withResolvers<void>();
    const result = Promise.all([
      drain(proc.stdout, (text) => {
        if (text.includes('READY\n')) ready.resolve();
      }),
      new Response(proc.stderr).text(),
      proc.exited,
    ]).then(([stdout, stderr, status]): WorkerResult => {
      ready.resolve(); // worker que morreu antes do READY não pode travar o pai
      return { status, stdout, stderr };
    });
    return { proc, ready: ready.promise, result };
  });

  try {
    await Promise.all(workers.map((worker) => worker.ready));
    for (const { proc } of workers) proc.stdin.end();
    return await Promise.all(workers.map((worker) => worker.result));
  } finally {
    for (const { proc } of workers) proc.kill();
  }
}

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout;
}

function gitFixture(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-conc-repo-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'Test');
  writeFileSync(path.join(root, 'noop.js'), '// nada a fazer\n', 'utf8');
  git(root, 'add', '.');
  git(root, 'commit', '-qm', 'seed');
  return root;
}

/** `runId` de cada linha não vazia de um JSONL de métricas. */
function readRunIds(file: string): string[] {
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const entry: { runId: string } = JSON.parse(line);
      return entry.runId;
    });
}

/** Work mínimo (plan.json + contrato L2) cujo único comando de aceitação é `node noop.js`. */
function writeWork(root: string): void {
  const workDir = path.join(root, '.pwn', 'work', '0001');
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
        files: ['noop.js'],
        implementation_files: ['noop.js'],
        test_files: ['noop.js'],
        red: { command: 'node noop.js', description: 'falha esperada' },
        implementation_steps: ['step'],
        acceptance_criteria: [{ command: 'node noop.js', description: 'passa' }],
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
    acceptance_contract: { commands: ['node noop.js'], required_evidence: [] },
    scope_contract: { write_allow: ['allowed.txt'], write_deny: [] },
    budget_contract: { max_agent_attempts: 3, max_shell_executions: 10 },
    escalation_contract: { on_write_violation: 'block_and_escalate', on_budget_exceeded: 'escalate_to_strong_agent', on_attempt_failed: 'retry_with_strong' },
  }), 'utf8');
}

describe('concorrência entre processos', () => {
  test('8 processos appendando em metrics.jsonl: nenhuma linha perdida e todas JSON válido', async () => {
    const root = mkdtempSync(path.join(tmpdir(), 'pwn-conc-metrics-'));
    const workers = 8;
    const perWorker = 25;
    try {
      const script = `
import { recordMetrics } from ${JSON.stringify(METRICS)};
${WORKER_PRELUDE}
for (let i = 0; i < ${perWorker}; i++) {
  recordMetrics({
    timestamp: new Date().toISOString(),
    runId: 'W' + index + '-' + i,
    workId: '0001',
    taskId: 'T-001',
    agentRole: 'cheap',
    // Linha grande: um append sem exclusão tem espaço para intercalar com o de outro processo.
    model: 'm'.repeat(4000),
    tokensInput: 1,
    tokensOutput: 1,
    costUSD: 0,
    durationMs: 1,
    status: 'success',
    attempts: 1,
    isolated: false,
  }, process.env.PWN_TEST_ROOT);
}
`;
      const results = await runWorkers(workers, script, { PWN_TEST_ROOT: root });
      for (const result of results) expect(result.stderr).toBe('');
      expect(results.map((result) => result.status)).toEqual(Array(workers).fill(0));

      const runIds = readRunIds(path.join(root, '.pwn', 'metrics.jsonl'));
      expect(runIds).toHaveLength(workers * perWorker);
      expect(new Set(runIds).size).toBe(workers * perWorker);
      expect(existsSync(path.join(root, '.pwn', 'metrics.jsonl.lock'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  test('withFileLock exclui mutuamente: contador lido-incrementado-escrito por N processos termina em N', async () => {
    const root = mkdtempSync(path.join(tmpdir(), 'pwn-conc-lock-'));
    const workers = 6;
    const perWorker = 15;
    const counter = path.join(root, 'counter.txt');
    writeFileSync(counter, '0', 'utf8');
    try {
      const script = `
import { withFileLock } from ${JSON.stringify(FS_LOCK)};
${WORKER_PRELUDE}
const counter = process.env.PWN_TEST_COUNTER;
for (let i = 0; i < ${perWorker}; i++) {
  withFileLock(counter, () => {
    const value = Number(fs.readFileSync(counter, 'utf8'));
    // Alarga a janela ler→escrever: sem exclusão mútua o resultado final perde incrementos.
    pause(1);
    fs.writeFileSync(counter, String(value + 1));
  }, { retryMs: 2 });
}
`;
      const results = await runWorkers(workers, script, { PWN_TEST_COUNTER: counter });
      for (const result of results) expect(result.stderr).toBe('');
      expect(results.map((result) => result.status)).toEqual(Array(workers).fill(0));
      expect(Number(readFileSync(counter, 'utf8'))).toBe(workers * perWorker);
      expect(existsSync(`${counter}.lock`)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  test('runs orquestradas no mesmo ms não colidem: runIds distintos, sem sobra de worktree/branch', async () => {
    const root = gitFixture();
    const workers = 4;
    try {
      writeWork(root);
      // Date.now congelado: o timestamp do runId é IDÊNTICO entre os processos, então só o
      // sufixo aleatório os distingue — o pior caso do mesmo milissegundo, de forma determinística.
      const script = `
import { runOrchestrated } from ${JSON.stringify(ORCHESTRATOR)};
${WORKER_PRELUDE}
const frozen = Date.now();
Date.now = () => frozen;
const result = runOrchestrated({
  workId: '0001',
  taskId: '1.1',
  command: ['node', 'noop.js'],
  timeoutSeconds: 30,
  isolated: true,
  rootDir: process.env.PWN_TEST_ROOT,
});
console.log('RESULT:' + JSON.stringify({ status: result.status, runId: result.runId, stderr: result.stderr }));
`;
      const results = await runWorkers(workers, script, { PWN_TEST_ROOT: root });
      const runs = results.map((result): RunSummary => {
        const line = result.stdout.split('\n').find((candidate) => candidate.startsWith('RESULT:'));
        if (!line) throw new Error(`worker sem RESULT (status ${result.status}): ${result.stderr}`);
        return JSON.parse(line.slice('RESULT:'.length));
      });

      for (const run of runs) expect(run.status, run.stderr).toBe(0);
      expect(new Set(runs.map((run) => run.runId)).size).toBe(workers);
      for (const run of runs) expect(run.runId).toMatch(/^RUN-[a-z0-9]+-[0-9a-f]{8}$/);

      const sandboxes = path.join(root, '.pwn', 'sandboxes');
      expect(existsSync(sandboxes) ? readdirSync(sandboxes) : []).toEqual([]);
      expect(git(root, 'worktree', 'list', '--porcelain').match(/^worktree /gm)).toHaveLength(1);
      expect(git(root, 'branch', '--list', 'pwn-sandbox-*').trim()).toBe('');
      expect(existsSync(path.join(root, '.pwn', 'git-worktree.lock'))).toBe(false);

      const metricsRunIds = readRunIds(path.join(root, '.pwn', 'metrics.jsonl'));
      expect(metricsRunIds).toHaveLength(workers);
      expect(new Set(metricsRunIds).size).toBe(workers);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);

  test('createGitWorktreeSandbox trata worktree já existente como colisão em vez de adotá-lo', () => {
    const root = gitFixture();
    try {
      const first = createGitWorktreeSandbox('RUN-colisao', root);
      try {
        let caught: unknown = null;
        try {
          createGitWorktreeSandbox('RUN-colisao', root);
        } catch (error) {
          caught = error;
        }
        expect(caught).toBeInstanceOf(SandboxError);
        expect(caught).toMatchObject({ reason: expect.stringContaining('collision') });
        // O worktree original segue intacto e utilizável.
        expect(existsSync(path.join(first.worktreePath, 'noop.js'))).toBe(true);
      } finally {
        cleanupGitWorktreeSandbox(first, root);
      }
      expect(existsSync(first.worktreePath)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
