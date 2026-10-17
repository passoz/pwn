import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { currentApproval } from '../src/core/acceptance-approval.js';
import { createDefaultContractV4 } from '../src/core/contract-engine.js';
import { DeciderUnavailable, validateResponse, type DeciderAnswer } from '../src/core/decider/contract.js';
import { decisionSignatureIsValid, readDecision } from '../src/core/decider/ledger.js';
import { taskApprovalPolicy } from '../src/core/decider/policies/approve.js';
import { queuePolicy } from '../src/core/decider/policies/queue.js';
import { riskRaises } from '../src/core/decider/policies/risk.js';
import { renderTasksMarkdown, type Plan } from '../src/core/plan-renderer.js';
import { listQueueItems, updateQueueStatus } from '../src/core/queue.js';
import { EXIT_SUSPENDED, runOrchestrated } from '../src/core/run-orchestrator.js';

const RUNTIME = process.execPath;
const CLI = path.resolve(import.meta.dirname, '../src/cli.ts');
const KEY = 'test-key-123';

// ── servidor Jev falso (processo separado) ─────────────────────────

const serverDir = mkdtempSync(path.join(tmpdir(), 'pwn-fake-jev-'));
const replyFile = path.join(serverDir, 'reply.json');
const logFile = path.join(serverDir, 'requests.jsonl');
let server: ReturnType<typeof Bun.spawn> | null = null;
let endpoint = '';

beforeAll(async () => {
  writeFileSync(replyFile, '{"status":500,"body":{}}');
  writeFileSync(logFile, '');
  server = Bun.spawn([RUNTIME, path.resolve(import.meta.dirname, 'fixtures/fake-jev.ts')], {
    env: { ...process.env, FAKE_JEV_REPLY: replyFile, FAKE_JEV_LOG: logFile },
    stdout: 'pipe',
  });
  const reader = (server.stdout as ReadableStream<Uint8Array>).getReader();
  const { value } = await reader.read();
  endpoint = `http://127.0.0.1:${new TextDecoder().decode(value).trim()}/v1/systemone`;
});

afterAll(() => {
  server?.kill();
  rmSync(serverDir, { recursive: true, force: true });
});

function reply(status: number, body: unknown): void {
  writeFileSync(replyFile, JSON.stringify({ status, body }));
}

function requests(): Array<{ authorization: string; body: { model: string; state: { artifacts: Record<string, unknown> }; questions: Record<string, unknown> } }> {
  return readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

const noul = (value: number): DeciderAnswer => ({ type: 'noul', noul: value });
const choice = (picked: string, confidence: number): DeciderAnswer => ({ type: 'choice', choice: picked, probabilities: { [picked]: confidence }, confidence });
const score = (value: number): DeciderAnswer => ({ type: 'score', score: value, probabilities: { '2': 1 }, confidence: 0.9 });

function approvalAnswers(overrides: Partial<Record<string, DeciderAnswer>> = {}): Record<string, DeciderAnswer> {
  return {
    covers_behavior: noul(0.95),
    passes_without_requirement: noul(0.05),
    specificity: score(2.6),
    scope: choice('adequate', 0.85),
    ...overrides,
  } as Record<string, DeciderAnswer>;
}

// ── fixture: Work 0001 com uma task L3 e teste de aceitação congelado ─

interface Fixture {
  root: string;
  verifier: string;
  env: NodeJS.ProcessEnv;
}

const ACCEPTANCE = 'import { expect, test } from "bun:test";\nimport { a } from "../src/a.js";\ntest("a vale 2", () => { expect(a).toBe(2); });\n';

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`);
  return result.stdout;
}

function fixture(): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-decider-'));
  const verifier = mkdtempSync(path.join(tmpdir(), 'pwn-decider-verifier-'));
  const plan: Plan = {
    work_id: '0001',
    title: 'Decisor',
    components: [{ name: 'alpha', root: '.', regression: `${RUNTIME} test`, lint: 'N/A', build: 'N/A', security: 'N/A', dev: 'N/A', health: 'N/A', purpose: 'componente' }],
    global_gates: [`\`${RUNTIME} --version\` — o runtime responde.`],
    tasks: [{
      id: '1.1',
      title: 'Entrega a',
      requirement_id: 'FR-001',
      depends_on: [],
      behavior: 'a passa a valer 2.',
      components: ['alpha'],
      files: ['src/a.js', 'tests/a.test.js'],
      implementation_files: ['src/a.js'],
      test_files: ['tests/a.test.js'],
      red: { command: `${RUNTIME} test tests/a.test.js`, description: 'A-RED-001 falha antes da implementação' },
      implementation_steps: ['Implementar o resultado observável.'],
      acceptance_criteria: [{ command: `${RUNTIME} test tests/a.acceptance.test.js`, description: 'a vale 2' }],
      visual: 'N/A',
      documentation: 'N/A',
      spec_reference: 'CAP-001',
      contract_id: 'CTR-001',
      complexity: 'standard',
      status: 'pending',
    }],
  };
  const workDir = path.join(root, '.pwn', 'work', '0001');
  for (const dir of [workDir, path.join(root, 'src'), path.join(root, 'tests'), path.join(root, '.todo')]) mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(workDir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`);
  writeFileSync(path.join(root, '.todo', '0001-tasks.md'), renderTasksMarkdown(plan));
  writeFileSync(path.join(root, 'src', 'a.js'), 'export const a = 1;\n');
  writeFileSync(path.join(root, 'tests', 'a.acceptance.test.js'), ACCEPTANCE);
  const contract = createDefaultContractV4('1.1', '0001', 'Entrega a', 'L3');
  contract.scope_contract.write_allow = ['src/a.js', 'tests/a.test.js'];
  contract.acceptance_contract.frozen_tests = [{ path: 'tests/a.acceptance.test.js', sha256: createHash('sha256').update(ACCEPTANCE).digest('hex') }];
  writeFileSync(path.join(workDir, 'CTR-001.json'), `${JSON.stringify(contract, null, 2)}\n`);
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'decider@example.invalid');
  git(root, 'config', 'user.name', 'Decider');
  git(root, 'add', '--', '.', ':(exclude).todo');
  git(root, 'commit', '-qm', 'baseline');
  const env: NodeJS.ProcessEnv = { ...process.env, PWN_VERIFIER_HOME: verifier, TYPESAFE_API_KEY: KEY };
  delete env.PWN_OPERATOR;
  return { root, verifier, env };
}

function pwn(fx: Fixture, args: string[], env: NodeJS.ProcessEnv = fx.env) {
  return spawnSync(RUNTIME, [CLI, ...args], { cwd: fx.root, env, encoding: 'utf8' });
}

function configure(fx: Fixture, ...extra: string[]): void {
  const set = pwn(fx, ['decider', 'set', '--decider', 'jev:jev-latest', '--decider-endpoint', endpoint, ...extra]);
  if (set.status !== 0) throw new Error(set.stderr);
}

function cleanup(fx: Fixture): void {
  rmSync(fx.root, { recursive: true, force: true });
  rmSync(fx.verifier, { recursive: true, force: true });
}

const APPROVE = ['verify', 'approve', '--work', '0001', '--task', '1.1'];

describe('verify approve com decisor', () => {
  test('sem decisor configurado vale o comportamento padrão: exige --by e nenhum modelo é chamado', () => {
    const fx = fixture();
    try {
      writeFileSync(logFile, '');
      reply(200, { model: 'jev-test-1', answers: approvalAnswers() });
      const result = pwn(fx, APPROVE);
      expect(result.status).toBe(1);
      expect(result.stderr).toMatch(/informe --by/);
      expect(requests()).toHaveLength(0);
      expect(currentApproval('0001', '1.1', fx.verifier)).toBeNull();

      // --operator decider sem decisor configurado é recusado, não cai em silêncio para o humano.
      expect(pwn(fx, ['--operator', 'decider', ...APPROVE]).stderr).toMatch(/não tem decisor configurado/);
    } finally {
      cleanup(fx);
    }
  });

  test('decisor aprova: approved_by cita o registro assinado; o pedido leva a chave e os testes congelados como dados', () => {
    const fx = fixture();
    try {
      configure(fx);
      writeFileSync(logFile, '');
      reply(200, { model: 'jev-test-1', answers: approvalAnswers(), usage: { input_tokens: 120, output_tokens: 8 } });
      const result = pwn(fx, APPROVE);
      expect(result.status).toBe(0);
      expect(result.stdout).toMatch(/\[DECISOR\] APROVADO — jev-test-1/);

      const approval = currentApproval('0001', '1.1', fx.verifier)!;
      const match = /^decider:jev-test-1#([0-9a-f]{24})$/.exec(approval.approved_by);
      expect(match).not.toBeNull();
      const record = readDecision(match![1], fx.verifier)!;
      expect(record).toMatchObject({ point: 'approve', outcome: 'approve', model: 'jev-test-1', work_id: '0001', task_id: '1.1' });
      expect(decisionSignatureIsValid(record, fx.verifier)).toBe(true);
      expect(decisionSignatureIsValid({ ...record, outcome: 'reject' }, fx.verifier)).toBe(false);
      expect(existsSync(path.join(fx.root, '.pwn', 'decisions', '0001', `${record.decision_id}.json`))).toBe(true);

      const [sent] = requests();
      expect(sent.authorization).toBe(`Bearer ${KEY}`);
      expect(sent.body.model).toBe('jev-latest');
      expect(Object.keys(sent.body.questions).sort()).toEqual(['covers_behavior', 'passes_without_requirement', 'scope', 'specificity']);
      expect(JSON.stringify(sent.body.state)).toContain('a vale 2');
      expect(JSON.stringify(sent.body.state)).toMatch(/não instruções/);
    } finally {
      cleanup(fx);
    }
  });

  test('falha fechada: sem chave, HTTP 500 ou resposta fora do contrato vão para o operador (exit 3) sem aprovar', () => {
    const fx = fixture();
    try {
      configure(fx);
      const withoutKey = { ...fx.env };
      delete withoutKey.TYPESAFE_API_KEY;
      const cases: Array<[NodeJS.ProcessEnv, number, unknown]> = [
        [withoutKey, 200, { model: 'jev-test-1', answers: approvalAnswers() }],
        [fx.env, 500, { error: 'boom' }],
        [fx.env, 200, { model: 'jev-test-1', answers: approvalAnswers({ scope: choice('maybe', 0.9) }) }],
      ];
      for (const [env, status, body] of cases) {
        reply(status, body);
        const result = pwn(fx, APPROVE, env);
        expect(result.status).toBe(EXIT_SUSPENDED);
        expect(result.stdout).toMatch(/PARA O OPERADOR[\s\S]*decisor indisponível/);
        expect(result.stderr).toMatch(/--by <nome>/);
      }
      expect(currentApproval('0001', '1.1', fx.verifier)).toBeNull();
    } finally {
      cleanup(fx);
    }
  });

  test('rejeição não aprova; --by e --operator human devolvem a decisão ao humano sem chamar o modelo', () => {
    const fx = fixture();
    try {
      configure(fx);
      reply(200, { model: 'jev-test-1', answers: approvalAnswers({ covers_behavior: noul(0.05) }) });
      const rejected = pwn(fx, APPROVE);
      expect(rejected.status).toBe(1);
      expect(rejected.stdout).toMatch(/REJEITADO[\s\S]*não verificam o comportamento/);
      expect(currentApproval('0001', '1.1', fx.verifier)).toBeNull();

      writeFileSync(logFile, '');
      expect(pwn(fx, ['--operator', 'human', ...APPROVE]).stderr).toMatch(/informe --by/);
      expect(pwn(fx, [...APPROVE, '--by', 'fernando']).status).toBe(0);
      expect(requests()).toHaveLength(0);
      expect(currentApproval('0001', '1.1', fx.verifier)!.approved_by).toBe('fernando');
    } finally {
      cleanup(fx);
    }
  });
});

// ── fila L4 ────────────────────────────────────────────────────────

function l4Fixture(fx: Fixture): void {
  const ctrPath = path.join(fx.root, '.pwn', 'work', '0001', 'CTR-001.json');
  const contract = JSON.parse(readFileSync(ctrPath, 'utf8'));
  contract.risk = { level: 'L4', reasons: ['teste'] };
  contract.scope_contract.write_allow = ['allowed.txt'];
  contract.acceptance_contract.commands = ['node ok.js'];
  writeFileSync(ctrPath, JSON.stringify(contract));
  writeFileSync(path.join(fx.root, 'ok.js'), "require('fs').writeFileSync('allowed.txt','x');\n");
  git(fx.root, 'add', '.');
  git(fx.root, 'commit', '-qm', 'L4');
}

function runL4(fx: Fixture) {
  const saved = { home: process.env.PWN_VERIFIER_HOME, key: process.env.TYPESAFE_API_KEY, operator: process.env.PWN_OPERATOR };
  process.env.PWN_VERIFIER_HOME = fx.verifier;
  process.env.TYPESAFE_API_KEY = KEY;
  delete process.env.PWN_OPERATOR;
  try {
    return runOrchestrated({ workId: '0001', taskId: '1.1', command: ['node', 'ok.js'], timeoutSeconds: 20, rootDir: fx.root });
  } finally {
    for (const [name, value] of [['PWN_VERIFIER_HOME', saved.home], ['TYPESAFE_API_KEY', saved.key], ['PWN_OPERATOR', saved.operator]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

describe('fila L4 com decisor', () => {
  test('sem decisor: suspende; aprovação na fila destrava o mesmo comando, e só enquanto o contrato não muda', () => {
    const fx = fixture();
    try {
      l4Fixture(fx);
      const first = runL4(fx);
      expect(first.status).toBe(EXIT_SUSPENDED);
      expect(updateQueueStatus(first.runId, 'approved', fx.root)).not.toBeNull();

      const resumed = runL4(fx);
      expect(resumed.suspended).toBe(false);
      expect(resumed.status).toBe(0);

      const ctrPath = path.join(fx.root, '.pwn', 'work', '0001', 'CTR-001.json');
      writeFileSync(ctrPath, JSON.stringify({ ...JSON.parse(readFileSync(ctrPath, 'utf8')), title: 'outro escopo' }));
      expect(runL4(fx).status).toBe(EXIT_SUSPENDED);
    } finally {
      cleanup(fx);
    }
  }, 60_000);

  test('teto L3 mantém L4 com o humano; com teto L4 o decisor aprova ou devolve efeito destrutivo ao operador', () => {
    const fx = fixture();
    try {
      l4Fixture(fx);
      configure(fx);
      writeFileSync(logFile, '');
      expect(runL4(fx).status).toBe(EXIT_SUSPENDED);
      expect(requests()).toHaveLength(0);

      configure(fx, '--decider-max-risk', 'L4');
      reply(200, { model: 'jev-test-1', answers: { destructive: noul(0.6), matches_task: noul(0.95) } });
      const destructive = runL4(fx);
      expect(destructive.status).toBe(EXIT_SUSPENDED);
      const pending = listQueueItems(fx.root).find((item) => item.runId === destructive.runId)!;
      expect(pending.status).toBe('pending_review');
      expect(pending.reason).toMatch(/efeito destrutivo possível/);

      reply(200, { model: 'jev-test-1', answers: { destructive: noul(0.02), matches_task: noul(0.95) } });
      const approved = runL4(fx);
      expect(approved.suspended).toBe(false);
      expect(approved.status).toBe(0);
      const item = listQueueItems(fx.root).find((entry) => entry.runId === approved.runId)!;
      expect(item.status).toBe('approved');
      expect(readDecision(item.payload.decision_id, fx.verifier)).toMatchObject({ point: 'queue', outcome: 'approve' });
    } finally {
      cleanup(fx);
    }
  }, 60_000);
});

// ── políticas puras ────────────────────────────────────────────────

describe('políticas do decisor', () => {
  test('aprovação: aprova só com todos os limiares; rejeita testes vazios; o resto vai para o operador', () => {
    expect(taskApprovalPolicy.judge(approvalAnswers()).outcome).toBe('approve');
    expect(taskApprovalPolicy.judge(approvalAnswers({ covers_behavior: noul(0.8) })).outcome).toBe('escalate');
    expect(taskApprovalPolicy.judge(approvalAnswers({ covers_behavior: noul(0.81) })).outcome).toBe('approve');
    expect(taskApprovalPolicy.judge(approvalAnswers({ specificity: score(1.9) })).outcome).toBe('escalate');
    expect(taskApprovalPolicy.judge(approvalAnswers({ scope: choice('adequate', 0.6) })).outcome).toBe('escalate');
    expect(taskApprovalPolicy.judge(approvalAnswers({ scope: choice('too_broad', 0.95) })).outcome).toBe('escalate');
    expect(taskApprovalPolicy.judge(approvalAnswers({ passes_without_requirement: noul(0.9) })).outcome).toBe('reject');
    expect(taskApprovalPolicy.judge(approvalAnswers({ covers_behavior: noul(0.1) })).outcome).toBe('reject');
  });

  test('fila L4: comando que não corresponde à task é rejeitado; efeito destrutivo nunca é aprovado', () => {
    expect(queuePolicy.judge({ destructive: noul(0.01), matches_task: noul(0.1) }).outcome).toBe('reject');
    expect(queuePolicy.judge({ destructive: noul(0.5), matches_task: noul(0.99) }).outcome).toBe('escalate');
    expect(queuePolicy.judge({ destructive: noul(0.05), matches_task: noul(0.9) }).outcome).toBe('approve');
  });

  test('--risk auto: o decisor só sobe o risco, até L3, com confiança mínima', () => {
    const tasks = [
      { id: '1.1', deterministic: 'L2' as const },
      { id: '1.2', deterministic: 'L3' as const },
      { id: '1.3', deterministic: 'L1' as const },
      { id: '1.4', deterministic: 'L1' as const },
    ];
    const raises = riskRaises(
      {
        'risk:1.1': choice('L3', 0.9),
        'risk:1.2': choice('L1', 0.99),
        'risk:1.3': choice('L3', 0.5),
        'risk:1.4': choice('L4', 0.99),
      },
      tasks,
    );
    expect(raises).toEqual([{ task: '1.1', from: 'L2', to: 'L3', confidence: 0.9 }]);
  });

  test('resposta fora do contrato é indisponibilidade, nunca resposta', () => {
    const request = { state: {}, questions: { a: { type: 'noul' as const, instructions: 'x' }, b: { type: 'score' as const, instructions: 'y', criteria: ['0', '1'] } } };
    const ok = { model: 'm', answers: { a: { type: 'noul', noul: 0.5 }, b: { type: 'score', score: 1, probabilities: { '1': 1 }, confidence: 1 } } };
    expect(validateResponse(request, ok).model).toBe('m');
    for (const answers of [
      { a: { type: 'noul', noul: 1.5 }, b: ok.answers.b },
      { a: ok.answers.a },
      { a: { type: 'choice', choice: 'x' }, b: ok.answers.b },
      { a: ok.answers.a, b: { ...ok.answers.b, score: 2 } },
    ]) {
      expect(() => validateResponse(request, { model: 'm', answers })).toThrow(DeciderUnavailable);
    }
  });
});

test('registros do decisor ficam na raiz do verificador, por decisão', () => {
  // Guarda contra regressão de layout: `pwn decider log` lê daqui.
  const fx = fixture();
  try {
    configure(fx);
    reply(200, { model: 'jev-test-1', answers: approvalAnswers() });
    expect(pwn(fx, APPROVE).status).toBe(0);
    expect(readdirSync(path.join(fx.verifier, 'decisions'))).toHaveLength(1);
    expect(pwn(fx, ['decider', 'log', '--work', '0001']).stdout).toMatch(/approve\s+0001\/1\.1\s+approve[\s\S]*assinatura ok/);
  } finally {
    cleanup(fx);
  }
});
