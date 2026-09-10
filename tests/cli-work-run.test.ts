import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'bun';

// O dispatch do CLI chama process.exit — por isso o teste cobre o fluxo via subprocesso.
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(REPO_ROOT, 'src', 'cli.ts');

interface CliResult {
  status: number;
  stdout: string;
  stderr: string;
}

async function runCli(args: string[], cwd: string): Promise<CliResult> {
  const proc = spawn(['bun', CLI, ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { status: await proc.exited, stdout, stderr };
}

function fixtureWork(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-cli-run-'));
  const workDir = path.join(dir, '.piwerness', 'work', '0001');
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, 'discovery.json'), JSON.stringify({ work_id: '0001', problem: 'p' }), 'utf8');
  writeFileSync(path.join(workDir, 'requirements.json'), JSON.stringify({ requirements: [{ id: 'REQ-1', acceptance_criteria: ['c1'] }] }), 'utf8');
  writeFileSync(path.join(workDir, 'prd.json'), JSON.stringify({ accepted_requirements: ['REQ-1'] }), 'utf8');
  return dir;
}

test('work run bloqueia Work inexistente com exit 1 e mensagem de gate', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-cli-none-'));
  const { status, stderr } = await runCli(['work', 'run', '--work', '9999'], dir);
  assert.equal(status, 1);
  assert.match(stderr, /GATE BLOCKED/);
  rmSync(dir, { recursive: true, force: true });
});

test('work run bloqueia Work cuja cadeia de gates não passou (fail-closed)', async () => {
  const dir = fixtureWork(); // sem spec.json/plan.json → GATE-PRD-SPEC bloqueia
  const { status, stderr } = await runCli(['work', 'run', '--work', '0001'], dir);
  assert.equal(status, 1);
  assert.match(stderr, /GATE BLOCKED/);
  rmSync(dir, { recursive: true, force: true });
});

test('--no-gate não bypassa enforcement: Work sem contratos falha com erro claro', async () => {
  // --no-gate pula a cadeia de gates, mas a execução continua sob contrato:
  // sem plan.json/contratos, o orquestrador bloqueia com erro acionável.
  const { status, stderr } = await runCli(
    ['work', 'run', '--no-gate', '--work', '9999', '--timeout-seconds', '10', '--', 'echo', 'ok'],
    REPO_ROOT,
  );
  assert.equal(status, 1);
  assert.match(stderr, /CONTRACT ERROR|plan\.json não encontrado/);
});

test('work audit não envia mais a ação inválida --audit ao task_evidence', async () => {
  const dir = fixtureWork();
  // Work 0001 não tem baseline registrado → task_evidence responde com o erro real
  // (e não "unknown or missing action" do parse de --audit).
  const { stdout } = await runCli(['work', 'audit', '--work', '0001', '--task', '1.1'], dir);
  assert.match(stdout, /FAIL: baseline not found|verify|=== \[pwn work audit\]/);
  rmSync(dir, { recursive: true, force: true });
});
