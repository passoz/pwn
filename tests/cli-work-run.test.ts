import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
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

test('run suspensa por risco L4 não sincroniza o manifest', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-cli-l4-'));
  const workDir = path.join(dir, '.piwerness', 'work', '0001');
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, 'plan.json'), JSON.stringify({
    work_id: '0001',
    title: 't',
    components: [{ name: 'core', purpose: 'nucleo' }],
    global_gates: ['suite'],
    tasks: [{
      id: '1.1', title: 'Task', requirement_id: 'FR-001', spec_reference: 'CAP-001', contract_id: 'CTR-001',
      depends_on: [], components: ['core'], files: ['src/a.ts', 'tests/a.test.ts'],
      implementation_files: ['src/a.ts'], test_files: ['tests/a.test.ts'],
      red: { command: 'bun test', description: 'falha esperada' },
      implementation_steps: ['step'],
      acceptance_criteria: [{ command: 'bun test', description: 'passa' }],
    }],
  }), 'utf8');
  writeFileSync(path.join(workDir, 'CTR-001.json'), JSON.stringify({
    contract_version: '4.0', task_id: '1.1', work_id: '0001', title: 'Task',
    risk: { level: 'L4', reasons: ['teste de suspensao'] },
    validation_strategy: 'tdd-strict',
    behavioral_contract: { scenarios: [] },
    change_contract: { target_files: [], affected_components: [] },
    architecture_contract: { invariants: [] },
    acceptance_contract: { commands: ['bun test'], required_evidence: [] },
    scope_contract: { write_allow: ['src/a.ts'], write_deny: [] },
    budget_contract: { max_agent_attempts: 3, max_shell_executions: 10 },
    escalation_contract: { on_write_violation: 'block_and_escalate', on_budget_exceeded: 'escalate_to_strong_agent', on_attempt_failed: 'retry_with_strong' },
  }), 'utf8');

  mkdirSync(path.join(dir, '.work'), { recursive: true });
  const manifestPath = path.join(dir, '.work', '0001.json');
  writeFileSync(manifestPath, JSON.stringify({
    version: 1, work_id: '0001', state: 'planned',
    origin: { type: 'local', reference: null },
    artifacts: {
      manifest: '.work/0001.json', source: '.sources/0001.md', prompt: '.prompts/0001.md',
      plan: '.todo/0001-tasks.md', evidence: '.todo/evidence/0001', diagnostics: '.todo/diagnostics/0001',
      screenshots: '.todo/screenshots/0001', attestations: '.todo/attestations/0001',
    },
    created_at: '2026-09-10T00:00:00Z', updated_at: '2026-09-10T00:00:00Z',
  }), 'utf8');

  const { status, stderr } = await runCli(
    ['work', 'run', '--no-gate', '--work', '0001', '--task', '1.1', '--timeout-seconds', '10', '--', 'echo', 'ok'],
    dir,
  );

  assert.equal(status, 0);
  assert.match(stderr, /suspensa|L4/);

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.state, 'planned', 'manifest não deve ser sincronizado em run suspensa');
  rmSync(dir, { recursive: true, force: true });
});
