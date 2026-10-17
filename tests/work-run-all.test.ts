import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'bun';
import { aggregateExitCodes, buildRunAllJobs, findScopeOverlaps, parseRunAllArgs } from '../src/commands/work.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(REPO_ROOT, 'src', 'cli.ts');

function contract(...writeAllow: string[]) {
  return { scope_contract: { write_allow: writeAllow } };
}

test('buildRunAllJobs monta um `work run` por Work, repassa flags e preserva o `--`', () => {
  const jobs = buildRunAllJobs(
    ['--works', '0001,0002', '--jobs', '2', '--timeout-seconds', '30', '--no-gate', '--', 'bun', 'test', '--bail'],
    ['0001', '0002'],
  );
  assert.equal(jobs.length, 2);
  assert.deepEqual(jobs.map((job) => job.id), ['0001', '0002']);
  for (const job of jobs) {
    const [bin, cli, ...rest] = job.command;
    assert.equal(bin, process.execPath);
    assert.equal(path.basename(cli), 'cli.ts');
    assert.deepEqual(rest, ['work', 'run', '--work', job.id, '--no-gate', '--timeout-seconds', '30', '--', 'bun', 'test', '--bail']);
  }
});

test('buildRunAllJobs sem --no-gate não o repassa; timeout default 600; --jobs/--works não vazam', () => {
  const [job] = buildRunAllJobs(['--jobs', '4', '--', 'bun', 'test'], ['0007']);
  assert.deepEqual(job.command.slice(2), ['work', 'run', '--work', '0007', '--timeout-seconds', '600', '--', 'bun', 'test']);
});

test('buildRunAllJobs não confunde flags do comando de aceitação com as do run-all', () => {
  const [job] = buildRunAllJobs(['--', 'bun', 'test', '--no-gate', '--jobs', '9'], ['0001']);
  assert.ok(!job.command.slice(2, job.command.indexOf('--')).includes('--no-gate'));
  assert.deepEqual(job.command.slice(job.command.indexOf('--') + 1), ['bun', 'test', '--no-gate', '--jobs', '9']);
});

test('parseRunAllArgs valida --jobs e --timeout-seconds e deduplica --works', () => {
  assert.deepEqual(parseRunAllArgs(['--works', '0001, 0002,0001', '--', 'x']).works, ['0001', '0002']);
  assert.equal(parseRunAllArgs(['--', 'x']).works, null);
  assert.throws(() => parseRunAllArgs(['--jobs', '0', '--', 'x']), /--jobs inválido/);
  assert.throws(() => parseRunAllArgs(['--jobs', '--', 'x']), /--jobs exige/);
  assert.throws(() => parseRunAllArgs(['--timeout-seconds', 'abc', '--', 'x']), /--timeout-seconds inválido/);
  assert.throws(() => parseRunAllArgs(['--works', '--', 'x']), /--works exige/);
});

test('findScopeOverlaps detecta globs sobrepostos entre Works', () => {
  const overlaps = findScopeOverlaps({
    '0001': [contract('src/**', 'tests/**')],
    '0002': [contract('src/auth/**')],
  });
  assert.equal(overlaps.length, 1);
  assert.deepEqual(overlaps[0].works, ['0001', '0002']);
  assert.deepEqual(overlaps[0].patterns, [['src/**', 'src/auth/**']]);
});

test('findScopeOverlaps detecta caminho literal coberto por glob e glob idêntico', () => {
  assert.equal(findScopeOverlaps({ a: [contract('src/a/x.ts')], b: [contract('src/**')] }).length, 1);
  assert.equal(findScopeOverlaps({ a: [contract('docs/**')], b: [contract('docs/**')] }).length, 1);
  assert.equal(findScopeOverlaps({ a: [contract('src/a/x.ts')], b: [contract('src/a/x.ts')] }).length, 1);
});

test('findScopeOverlaps não acusa globs disjuntos', () => {
  const overlaps = findScopeOverlaps({
    '0001': [contract('src/a/**', 'docs/a.md')],
    '0002': [contract('src/b/**', 'docs/b.md')],
    '0003': [contract('lib/**'), contract('scripts/*.sh')],
  });
  assert.deepEqual(overlaps, []);
});

test('findScopeOverlaps une os write_allow de todos os contratos do Work e cobre pares', () => {
  const overlaps = findScopeOverlaps({
    '0001': [contract('src/a/**'), contract('docs/**')],
    '0002': [contract('src/b/**')],
    '0003': [contract('docs/guide.md')],
  });
  assert.deepEqual(overlaps.map((o) => o.works), [['0001', '0003']]);
});

test('aggregateExitCodes: 0 só se todos 0; senão o maior não-zero; timeout conta 124', () => {
  assert.equal(aggregateExitCodes([]), 0);
  assert.equal(aggregateExitCodes([{ status: 0, timedOut: false }, { status: 0, timedOut: false }]), 0);
  assert.equal(aggregateExitCodes([{ status: 0, timedOut: false }, { status: 3, timedOut: false }, { status: 1, timedOut: false }]), 3);
  assert.equal(aggregateExitCodes([{ status: 137, timedOut: true }, { status: 1, timedOut: false }]), 124);
});

// ── Concorrência real: 2 subprocessos `work run`, cada um em worktree próprio ──

function git(cwd: string, ...args: string[]) {
  const proc = spawnSync('git', ['-c', 'user.name=pwn-test', '-c', 'user.email=pwn@test.local', ...args], { cwd, encoding: 'utf8' });
  assert.equal(proc.status, 0, `git ${args.join(' ')}: ${proc.stderr}`);
  return proc.stdout;
}

async function runCli(args: string[], cwd: string, env: Record<string, string> = {}) {
  const proc = spawn(['bun', CLI, ...args], { cwd, stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { status: await proc.exited, stdout, stderr };
}

test('run-all executa 2 Works em worktrees distintos, remove-os e sai com 0', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-run-all-'));
  try {
    git(dir, 'init', '-q');
    writeFileSync(path.join(dir, 'README.md'), 'repo temporário\n', 'utf8');
    mkdirSync(path.join(dir, 'tests'), { recursive: true });
    // `bun test` é o comando de aceitação permitido pelo contrato do scaffold.
    writeFileSync(
      path.join(dir, 'tests', 'ok.test.ts'),
      "import { test } from 'bun:test';\ntest('ok', () => {});\n",
      'utf8',
    );
    for (const title of ['Alpha modulo', 'Beta modulo']) {
      const scaffold = await runCli(['work', 'scaffold', '--title', title], dir);
      assert.equal(scaffold.status, 0, scaffold.stderr);
    }
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'init');

    const result = await runCli(['work', 'run-all', '--works', '0001,0002', '--no-gate', '--jobs', '2', '--', 'bun', 'test'], dir);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /Possível conflito de merge entre Works 0001 e 0002/);
    assert.match(result.stdout, /\[0001\] /);
    assert.match(result.stdout, /\[0002\] /);
    assert.match(result.stdout, /✓ Work 0001: exit 0/);
    assert.match(result.stdout, /✓ Work 0002: exit 0/);

    // Cada subprocesso gravou o log do próprio run (.pwn/RUN-*.jsonl) com o worktree que criou.
    const sandboxes = readdirSync(path.join(dir, '.pwn'))
      .filter((name) => /^RUN-.*\.jsonl$/.test(name))
      .map((name) => /Sandbox criado: (\S+)/.exec(readFileSync(path.join(dir, '.pwn', name), 'utf8'))?.[1]);
    assert.equal(sandboxes.length, 2, `esperava 2 runs, obtive: ${sandboxes.join(', ')}`);
    assert.ok(sandboxes.every(Boolean));
    assert.notEqual(sandboxes[0], sandboxes[1], 'os dois Works devem rodar em worktrees distintos');
    for (const sandbox of sandboxes) {
      assert.notEqual(path.resolve(sandbox!), path.resolve(dir), 'worktree não pode ser o repo principal');
      assert.ok(!existsSync(sandbox!), `worktree ${sandbox} deveria ter sido removido`);
    }

    // Só o worktree principal permanece registrado.
    const worktrees = git(dir, 'worktree', 'list', '--porcelain').split('\n').filter((line) => line.startsWith('worktree '));
    assert.equal(worktrees.length, 1, worktrees.join('\n'));

    // Métricas: um run por Work.
    const metrics = readFileSync(path.join(dir, '.pwn', 'metrics.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line) as { workId: string; runId: string });
    assert.deepEqual(metrics.map((m) => m.workId).sort(), ['0001', '0002']);
    assert.notEqual(metrics[0].runId, metrics[1].runId);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('run-all propaga o maior exit code não-zero quando um Work falha', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-run-all-fail-'));
  try {
    git(dir, 'init', '-q');
    writeFileSync(path.join(dir, 'README.md'), 'x\n', 'utf8');
    const scaffold = await runCli(['work', 'scaffold', '--title', 'Alpha modulo'], dir);
    assert.equal(scaffold.status, 0, scaffold.stderr);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'init');

    // 0001 existe; 0099 não → falha. Resumo lista ambos.
    const result = await runCli(['work', 'run-all', '--works', '0001,0099', '--no-gate', '--jobs', '2', '--', 'bun', 'test'], dir);
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /✗ Work 0099: exit [1-9]/);
    assert.match(result.stdout, /Work 0001: exit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('run-all sem comando de aceitação falha com uso acionável', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-run-all-nocmd-'));
  try {
    const result = await runCli(['work', 'run-all', '--works', '0001'], dir);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /pwn work run-all/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
