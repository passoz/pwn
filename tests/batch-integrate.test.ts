import { describe, expect, test } from 'bun:test';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createApproval } from '../src/core/acceptance-approval.js';
import { readBatch } from '../src/core/batch.js';
import { createDefaultContractV4 } from '../src/core/contract-engine.js';
import { renderTasksMarkdown, type Plan } from '../src/core/plan-renderer.js';
import { collectProjectStatus } from '../src/core/project_status.js';
import { isBwrapSupported } from '../src/core/sandbox.js';
import { initializeVerifierHome } from '../src/core/verifier-home.js';

const RUNTIME = process.execPath;
const CLI = path.resolve(import.meta.dirname, '../src/cli.ts');

interface Spec {
  id: string;
  key: string;
  contract: string;
  component: string;
  dependsOn: string[];
}

const SPECS: Spec[] = [
  { id: '1.1', key: 'a', contract: 'CTR-001', component: 'alpha', dependsOn: [] },
  { id: '1.2', key: 'b', contract: 'CTR-002', component: 'beta', dependsOn: [] },
  // Mesmo componente de 1.1, mas dependente: entra só no lote seguinte.
  { id: '1.3', key: 'c', contract: 'CTR-003', component: 'alpha', dependsOn: ['1.1'] },
];

const sha = (text: string): string => createHash('sha256').update(text).digest('hex');
const acceptanceTest = (key: string): string =>
  `import { expect, test } from "bun:test";\nimport { ${key} } from "../src/${key}.js";\ntest("${key} aceito", () => { expect(${key}).toBe(2); });\n`;

interface Fixture {
  root: string;
  verifierRoot: string;
  env: NodeJS.ProcessEnv;
}

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`);
  return result.stdout;
}

/** Work 0001 com 3 tasks L3: testes de aceitação congelados e aprovações feitas ANTES de qualquer implementação. */
function fixture(options: { cross?: boolean } = {}): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-batch-'));
  const verifierRoot = mkdtempSync(path.join(tmpdir(), 'pwn-batch-verifier-'));
  const plan: Plan = {
    work_id: '0001',
    title: 'Lote paralelo',
    components: ['alpha', 'beta'].map((name) => ({ name, root: '.', regression: options.cross ? `${RUNTIME} test tests/cross.test.js` : `${RUNTIME} test`, lint: 'N/A', build: 'N/A', security: 'N/A', dev: 'N/A', health: 'N/A', purpose: `componente ${name}` })),
    global_gates: [`\`${RUNTIME} --version\` — o runtime responde.`],
    tasks: SPECS.map((spec, index) => ({
      id: spec.id,
      title: `Entrega ${spec.key}`,
      requirement_id: `FR-00${index + 1}`,
      depends_on: spec.dependsOn,
      behavior: `${spec.key} passa a valer 2.`,
      components: [spec.component],
      files: [`src/${spec.key}.js`, `tests/${spec.key}.test.js`],
      implementation_files: [`src/${spec.key}.js`],
      test_files: [`tests/${spec.key}.test.js`],
      red: { command: `${RUNTIME} test tests/${spec.key}.test.js`, description: `a asserção ${spec.key.toUpperCase()}-RED-001 falha antes da implementação` },
      implementation_steps: ['Implementar só o resultado observável declarado.'],
      acceptance_criteria: [{ command: `${RUNTIME} test tests/${spec.key}.acceptance.test.js`, description: `${spec.key} vale 2` }],
      visual: 'N/A' as const,
      documentation: 'N/A' as const,
      spec_reference: 'CAP-001',
      contract_id: spec.contract,
      complexity: 'standard',
      status: 'pending' as const,
    })),
  };
  const workDir = path.join(root, '.pwn', 'work', '0001');
  mkdirSync(workDir, { recursive: true });
  mkdirSync(path.join(root, 'src'));
  mkdirSync(path.join(root, 'tests'));
  mkdirSync(path.join(root, '.todo'));
  writeFileSync(path.join(workDir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`);
  writeFileSync(path.join(root, '.todo', '0001-tasks.md'), renderTasksMarkdown(plan));
  for (const spec of SPECS) {
    writeFileSync(path.join(root, 'src', `${spec.key}.js`), `export const ${spec.key} = 1;\n`);
    writeFileSync(path.join(root, 'tests', `${spec.key}.test.js`), '// teste focado: escrito pelo agente depois do baseline\n');
    writeFileSync(path.join(root, 'tests', `${spec.key}.acceptance.test.js`), acceptanceTest(spec.key));
    const contract = createDefaultContractV4(spec.id, '0001', `Entrega ${spec.key}`, 'L3');
    contract.scope_contract.write_allow = [`src/${spec.key}.js`, `tests/${spec.key}.test.js`];
    contract.acceptance_contract.frozen_tests = [{ path: `tests/${spec.key}.acceptance.test.js`, sha256: sha(acceptanceTest(spec.key)) }];
    writeFileSync(path.join(workDir, `${spec.contract}.json`), `${JSON.stringify(contract, null, 2)}\n`);
  }
  if (options.cross) {
    // Passa com zero ou uma das entregas (a+b = 2 ou 3); quebra com as duas (4).
    writeFileSync(
      path.join(root, 'tests', 'cross.test.js'),
      'import { expect, test } from "bun:test";\nimport { a } from "../src/a.js";\nimport { b } from "../src/b.js";\ntest("a e b não somam 4", () => { expect(a + b).not.toBe(4); });\n',
    );
  }
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'batch@example.invalid');
  git(root, 'config', 'user.name', 'Batch');
  // `.todo/` fica fora do Git, como num projeto real.
  git(root, 'add', '--', '.', ':(exclude).todo');
  git(root, 'commit', '-qm', 'baseline');

  initializeVerifierHome(verifierRoot);
  for (const spec of SPECS) {
    createApproval({ rootDir: root, workId: '0001', taskId: spec.id, approvedBy: 'operador', verifierRootDir: verifierRoot });
  }
  return { root, verifierRoot, env: { ...process.env, PWN_VERIFIER_HOME: verifierRoot } };
}

function pwn(fx: Fixture, cwd: string, ...args: string[]) {
  return spawnSync(RUNTIME, [CLI, ...args], { cwd, env: fx.env, encoding: 'utf8' });
}

function expectOk(result: SpawnSyncReturns<string>, label: string): void {
  if (result.status !== 0) throw new Error(`${label} saiu ${result.status}:\n${result.stdout}\n${result.stderr}`);
}

/** O que um agente faz no worktree: baseline → RED → implementação → GREEN → verify. */
function deliver(fx: Fixture, worktree: string, spec: Spec): void {
  const focused = ['--', RUNTIME, 'test', `tests/${spec.key}.test.js`];
  const audit = (action: string, ...rest: string[]) => pwn(fx, worktree, 'work', 'audit', action, '--work', '0001', '--task', spec.id, ...rest);
  expectOk(audit('baseline'), `baseline ${spec.id}`);
  writeFileSync(
    path.join(worktree, 'tests', `${spec.key}.test.js`),
    `import { test } from "bun:test";\nimport { ${spec.key} } from "../src/${spec.key}.js";\ntest("${spec.key} focado", () => { if (${spec.key} !== 2) throw new Error("${spec.key.toUpperCase()}-RED-001"); });\n`,
  );
  expectOk(audit('red', '--expect', `${spec.key.toUpperCase()}-RED-001`, ...focused), `red ${spec.id}`);
  writeFileSync(path.join(worktree, 'src', `${spec.key}.js`), `export const ${spec.key} = 2;\n`);
  expectOk(audit('green', ...focused), `green ${spec.id}`);
  expectOk(audit('verify', ...focused), `verify ${spec.id}`);
}

function mainStatus(fx: Fixture) {
  const previous = process.env.PWN_VERIFIER_HOME;
  process.env.PWN_VERIFIER_HOME = fx.verifierRoot;
  try {
    return collectProjectStatus(path.join(fx.root, '.todo', '0001-tasks.md'));
  } finally {
    if (previous === undefined) delete process.env.PWN_VERIFIER_HOME;
    else process.env.PWN_VERIFIER_HOME = previous;
  }
}

const stageOf = (fx: Fixture, id: string) => mainStatus(fx).tasks.find((task) => task.id === id)!.evidence;

describe('pwn work batch', () => {
  test('lotes em worktrees integram sem invalidar evidência local e a árvore final é aceita numa única verificação', () => {
    const fx = fixture();
    try {
      const prepared = pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001');
      expectOk(prepared, 'prepare 1');
      expect(prepared.stdout).toMatch(/1\.3 — depende de 1\.1, ainda não integrada/);
      const first = readBatch(fx.root)!;
      expect(first.tasks.map((task) => task.id)).toEqual(['1.1', '1.2']);

      const worktreeOf = (id: string) => first.tasks.find((task) => task.id === id)!.worktree;
      deliver(fx, worktreeOf('1.1'), SPECS[0]);
      deliver(fx, worktreeOf('1.2'), SPECS[1]);
      // Escrita fora do write_allow em 1.1: só ela fica retida; 1.2 entra mesmo assim.
      writeFileSync(path.join(worktreeOf('1.1'), 'notes.txt'), 'rascunho fora do escopo\n');

      const partial = pwn(fx, fx.root, 'work', 'batch', 'integrate');
      expect(partial.status).toBe(1);
      expect(partial.stdout).toMatch(/✓ 1\.2 → commit/);
      expect(partial.stderr).toMatch(/DIFF VIOLATION notes\.txt/);
      expect(readBatch(fx.root)!.tasks.map((task) => task.id)).toEqual(['1.1']);

      // Corrigida no worktree, 1.1 integra sobre o HEAD que já avançou com 1.2.
      unlinkSync(path.join(worktreeOf('1.1'), 'notes.txt'));
      expectOk(pwn(fx, fx.root, 'work', 'batch', 'integrate'), 'integrate 1.1');
      expect(readBatch(fx.root)).toBeNull();
      expect(git(fx.root, 'log', '--format=%s').trim().split('\n')).toEqual([
        'pwn batch 0001/1.1: Entrega a',
        'pwn batch 0001/1.2: Entrega b',
        'baseline',
      ]);
      // Evidência local veio junto e continua válida depois das duas integrações.
      expect(existsSync(path.join(fx.root, '.todo', 'evidence', '0001', 'state', '1.1.json'))).toBe(true);
      expect(stageOf(fx, '1.1')).toMatchObject({ stage: 'VERIFIED', stale: false });
      expect(stageOf(fx, '1.2')).toMatchObject({ stage: 'VERIFIED', stale: false });
      expect(git(fx.root, 'worktree', 'list').trim().split('\n')).toHaveLength(1);
      expect(git(fx.root, 'branch', '--list', 'pwn-sandbox-*').trim()).toBe('');

      expectOk(pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001'), 'prepare 2');
      const second = readBatch(fx.root)!;
      expect(second.tasks.map((task) => task.id)).toEqual(['1.3']);
      deliver(fx, second.tasks[0].worktree, SPECS[2]);
      const last = pwn(fx, fx.root, 'work', 'batch', 'integrate');
      expectOk(last, 'integrate 1.3');
      expect(last.stdout).toMatch(/verify run-all --work 0001/);
      for (const spec of SPECS) expect(stageOf(fx, spec.id)).toMatchObject({ stage: 'VERIFIED', stale: false });

      if (!isBwrapSupported()) return;
      // Uma única verificação independente, na árvore integrada, aceita todas as tasks:
      // nenhuma precisou ser reverificada por causa da integração das outras.
      expectOk(pwn(fx, fx.root, 'verify', 'run-all', '--work', '0001'), 'verify run-all');
      for (const spec of SPECS) expect(stageOf(fx, spec.id).stage).toBe('ACCEPTED');
    } finally {
      rmSync(fx.root, { recursive: true, force: true });
      rmSync(fx.verifierRoot, { recursive: true, force: true });
    }
  }, 120_000);

  test('prepare recusa árvore principal suja e task sem aprovação prévia', () => {
    const fx = fixture();
    try {
      writeFileSync(path.join(fx.root, 'src', 'a.js'), 'export const a = 99;\n');
      const dirty = pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001');
      expect(dirty.status).toBe(1);
      expect(dirty.stderr).toMatch(/alterações não commitadas \(src\/a\.js\)/);
      git(fx.root, 'checkout', '--', 'src/a.js');

      // Sem raiz de verificador não há aprovação: nada vira lote e nenhum worktree nasce.
      const unapproved = spawnSync(RUNTIME, [CLI, 'work', 'batch', 'prepare', '--work', '0001'], {
        cwd: fx.root,
        env: { ...process.env, PWN_VERIFIER_HOME: mkdtempSync(path.join(tmpdir(), 'pwn-batch-empty-')) },
        encoding: 'utf8',
      });
      expect(unapproved.status).toBe(1);
      expect(unapproved.stderr).toMatch(/1\.1 — sem aprovação vigente/);
      expect(readBatch(fx.root)).toBeNull();
      expect(git(fx.root, 'worktree', 'list').trim().split('\n')).toHaveLength(1);
    } finally {
      rmSync(fx.root, { recursive: true, force: true });
      rmSync(fx.verifierRoot, { recursive: true, force: true });
    }
  }, 60_000);

  test('regressão no HEAD integrado retém só a task que quebra a suíte; a árvore principal não é tocada', () => {
    const fx = fixture({ cross: true });
    try {
      expectOk(pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001'), 'prepare');
      const batch = readBatch(fx.root)!;
      deliver(fx, batch.tasks[0].worktree, SPECS[0]);
      deliver(fx, batch.tasks[1].worktree, SPECS[1]);

      // O comando precisa ser o declarado no plano; qualquer outro é recusado antes de qualquer efeito.
      const undeclared = pwn(fx, fx.root, 'work', 'batch', 'integrate', '--', RUNTIME, 'test', 'tests/a.test.js');
      expect(undeclared.status).toBe(1);
      expect(undeclared.stderr).toMatch(/comando de regressão diverge do plano/);
      expect(readBatch(fx.root)!.tasks).toHaveLength(2);

      // a+b: 2 → 3 (só 1.1) passa; → 4 (com 1.2) quebra o teste cruzado.
      const gated = pwn(fx, fx.root, 'work', 'batch', 'integrate', '--', RUNTIME, 'test', 'tests/cross.test.js');
      expect(gated.status).toBe(1);
      expect(gated.stdout).toMatch(/✓ 1\.1 → commit/);
      expect(gated.stderr).toMatch(/✗ 1\.2[\s\S]*regressão falhou com a entrega aplicada[\s\S]*a árvore principal não foi tocada/);
      expect(readFileSync(path.join(fx.root, 'src', 'b.js'), 'utf8')).toBe('export const b = 1;\n');
      expect(git(fx.root, 'log', '--format=%s').trim().split('\n')).toEqual(['pwn batch 0001/1.1: Entrega a', 'baseline']);
      expect(readBatch(fx.root)!.tasks.map((task) => task.id)).toEqual(['1.2']);
      // O worktree temporário do gate não sobra: só a árvore principal e o worktree de 1.2.
      expect(git(fx.root, 'worktree', 'list').trim().split('\n')).toHaveLength(2);
      expect(git(fx.root, 'branch', '--list', 'pwn-sandbox-*-regression').trim()).toBe('');

      expectOk(pwn(fx, fx.root, 'work', 'batch', 'abort'), 'abort');
      expect(git(fx.root, 'worktree', 'list').trim().split('\n')).toHaveLength(1);
    } finally {
      rmSync(fx.root, { recursive: true, force: true });
      rmSync(fx.verifierRoot, { recursive: true, force: true });
    }
  }, 120_000);

  test('rebase refaz a task sobre o HEAD novo: conflito fica no worktree e a evidência é reavaliada', () => {
    const fx = fixture();
    try {
      expectOk(pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001'), 'prepare');
      const batch = readBatch(fx.root)!;
      deliver(fx, batch.tasks[0].worktree, SPECS[0]);
      deliver(fx, batch.tasks[1].worktree, SPECS[1]);

      // Simula o que a heurística de escopo deveria impedir: o HEAD andou por uma mudança
      // em src/a.js, o arquivo que 1.1 também alterou. O manifesto é ajustado à mão porque
      // `integrate` recusa commits externos; aqui só interessa o caminho de recuperação.
      writeFileSync(path.join(fx.root, 'src', 'a.js'), 'export const a = 5;\n');
      git(fx.root, 'commit', '-qam', 'mudança concorrente em a.js');
      writeFileSync(path.join(fx.root, '.pwn', 'batch.json'), `${JSON.stringify({ ...batch, head: git(fx.root, 'rev-parse', 'HEAD').trim() }, null, 2)}\n`);

      // A task que não conflita entra; a que não aplica fica retida com a saída apontada.
      const first = pwn(fx, fx.root, 'work', 'batch', 'integrate');
      expect(first.status).toBe(1);
      expect(first.stdout).toMatch(/✓ 1\.2 → commit/);
      expect(first.stderr).toMatch(/✗ 1\.1[\s\S]*o diff não aplica sobre o HEAD[\s\S]*rebase 1\.1/);
      const oldWorktree = readBatch(fx.root)!.tasks[0].worktree;

      const rebased = pwn(fx, fx.root, 'work', 'batch', 'rebase', '1.1');
      expect(rebased.status).toBe(1);
      expect(rebased.stdout).toMatch(/Conflitos em 1 arquivo\(s\)[\s\S]*src\/a\.js/);
      expect(rebased.stdout).toMatch(/Evidência local caducou/);
      const redone = readBatch(fx.root)!.tasks[0];
      expect(redone.worktree).not.toBe(oldWorktree);
      expect(existsSync(oldWorktree)).toBe(false);
      expect(existsSync(`${redone.worktree}.delivery.patch`)).toBe(true);
      expect(readFileSync(path.join(redone.worktree, 'src', 'a.js'), 'utf8')).toMatch(/^<{7} /m);

      // Marcadores de conflito nunca entram: o harness não escolhe a resolução.
      const blocked = pwn(fx, fx.root, 'work', 'batch', 'integrate');
      expect(blocked.status).toBe(1);
      expect(blocked.stderr).toMatch(/conflito não resolvido/);

      // Resolvida pelo agente com o conteúdo que a evidência provou, a task integra.
      writeFileSync(path.join(redone.worktree, 'src', 'a.js'), 'export const a = 2;\n');
      git(redone.worktree, 'add', 'src/a.js');
      expectOk(pwn(fx, fx.root, 'work', 'batch', 'integrate'), 'integrate 1.1 refeita');
      expect(readBatch(fx.root)).toBeNull();
      expect(readFileSync(path.join(fx.root, 'src', 'a.js'), 'utf8')).toBe('export const a = 2;\n');
      expect(git(fx.root, 'log', '--format=%s').trim().split('\n')).toEqual([
        'pwn batch 0001/1.1: Entrega a',
        'pwn batch 0001/1.2: Entrega b',
        'mudança concorrente em a.js',
        'baseline',
      ]);
      expect(stageOf(fx, '1.1')).toMatchObject({ stage: 'VERIFIED', stale: false });
      expect(git(fx.root, 'worktree', 'list').trim().split('\n')).toHaveLength(1);
    } finally {
      rmSync(fx.root, { recursive: true, force: true });
      rmSync(fx.verifierRoot, { recursive: true, force: true });
    }
  }, 120_000);

  test('com decisor no projeto, task retida só por base desatualizada é refeita automaticamente (regra registrada)', () => {
    const fx = fixture();
    try {
      expectOk(pwn(fx, fx.root, 'decider', 'set', '--decider', 'jev:jev-latest'), 'decider set');
      expectOk(pwn(fx, fx.root, 'work', 'batch', 'prepare', '--work', '0001'), 'prepare');
      const batch = readBatch(fx.root)!;
      deliver(fx, batch.tasks[0].worktree, SPECS[0]);
      deliver(fx, batch.tasks[1].worktree, SPECS[1]);
      writeFileSync(path.join(fx.root, 'src', 'a.js'), 'export const a = 5;\n');
      git(fx.root, 'commit', '-qam', 'mudança concorrente em a.js');
      writeFileSync(path.join(fx.root, '.pwn', 'batch.json'), `${JSON.stringify({ ...batch, head: git(fx.root, 'rev-parse', 'HEAD').trim() }, null, 2)}\n`);

      const integrated = pwn(fx, fx.root, 'work', 'batch', 'integrate');
      expect(integrated.status).toBe(1);
      expect(integrated.stdout).toMatch(/✓ 1\.2 → commit/);
      expect(integrated.stdout).toMatch(/\[DECISOR\] APROVADO \(rebase\) — rule[\s\S]*Conflitos em 1 arquivo\(s\)[\s\S]*src\/a\.js/);
      expect(readBatch(fx.root)!.tasks[0].worktree).not.toBe(batch.tasks[0].worktree);
      const records = readdirSync(path.join(fx.verifierRoot, 'decisions')).map((file) => JSON.parse(readFileSync(path.join(fx.verifierRoot, 'decisions', file), 'utf8')));
      expect(records).toEqual([expect.objectContaining({ point: 'batch', task_id: '1.1', decider: 'rule', action: 'rebase' })]);
    } finally {
      rmSync(fx.root, { recursive: true, force: true });
      rmSync(fx.verifierRoot, { recursive: true, force: true });
    }
  }, 120_000);
});
