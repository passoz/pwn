import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createApproval } from '../src/core/acceptance-approval.js';
import { evaluateAllGates } from '../src/core/gates.js';
import { detectChanges, readReconciliation, reconcileChanges } from '../src/core/reconcile.js';
import { freezeAcceptanceTests, loadTaskContract } from '../src/core/task-contract.js';
import { getWorkArtifactsPaths } from '../src/core/work-artifacts.js';

function git(root: string, ...args: string[]): string {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`);
  return result.stdout.trim();
}

function write(root: string, file: string, content: string): void {
  mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  writeFileSync(path.join(root, file), content, 'utf8');
}

/** Repo com um commit-base; o operador depois muda `src/add.ts` e cria um teste, tudo fora do pwn. */
function fixture(): { root: string; base: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-reconcile-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'r@example.invalid');
  git(root, 'config', 'user.name', 'Reconcile');
  write(root, 'package.json', '{"name":"x"}\n');
  write(root, 'src/add.ts', 'export const add = (a: number, b: number) => a - b;\n');
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '-m', 'base');
  const base = git(root, 'rev-parse', 'HEAD');
  write(root, 'src/add.ts', 'export const add = (a: number, b: number) => a + b;\n');
  write(root, 'tests/add.test.ts', "import { test } from 'bun:test';\ntest('soma', () => {});\n");
  return { root, base, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

describe('detectChanges', () => {
  test('lista tracked + novos, classifica teste/código e ignora governança e segredos', () => {
    const fx = fixture();
    try {
      write(fx.root, '.env.local', 'SECRET=1\n');
      write(fx.root, '.todo/0001-tasks.md', 'x\n');
      write(fx.root, 'queue/review/a.json', '{}\n');
      const detected = detectChanges({ rootDir: fx.root });
      expect(detected.baseCommit).toBe(fx.base);
      expect(detected.changes.map((c) => [c.path, c.status, c.kind])).toEqual([
        ['src/add.ts', 'M', 'implementation'],
        ['tests/add.test.ts', 'A', 'test'],
      ]);
      expect(detected.skipped.map((s) => s.path)).toEqual(['.env.local']);
    } finally {
      fx.cleanup();
    }
  });

  test('--paths restringe por prefixo e --since inclui commits já feitos fora do pwn', () => {
    const fx = fixture();
    try {
      git(fx.root, 'add', '-A');
      git(fx.root, 'commit', '-q', '-m', 'fora do pwn');
      expect(detectChanges({ rootDir: fx.root }).changes).toEqual([]);

      const since = detectChanges({ rootDir: fx.root, since: fx.base, paths: ['src'] });
      expect(since.baseCommit).toBe(fx.base);
      expect(since.changes.map((c) => c.path)).toEqual(['src/add.ts']);
      expect(() => detectChanges({ rootDir: fx.root, since: 'nao-existe' })).toThrow(/--since inválido/);
    } finally {
      fx.cleanup();
    }
  });

  test('arquivo removido entra como D sem hash', () => {
    const fx = fixture();
    try {
      rmSync(path.join(fx.root, 'src/add.ts'));
      const removed = detectChanges({ rootDir: fx.root }).changes.find((c) => c.path === 'src/add.ts');
      expect(removed).toMatchObject({ status: 'D', sha256: null });
    } finally {
      fx.cleanup();
    }
  });
});

describe('reconcileChanges', () => {
  test('cria um Work que passa nos 5 gates, com escopo exato e base registrada', () => {
    const fx = fixture();
    try {
      const result = reconcileChanges({ rootDir: fx.root, title: 'Corrige soma do add' });
      expect(result.workId).toBe('0001');
      expect(result.tasks).toEqual([{ id: '1.1', implementationFiles: ['src/add.ts'], testFiles: ['tests/add.test.ts'], testsToWrite: false }]);

      const contract = loadTaskContract('0001', '1.1', fx.root);
      expect(contract.scope_contract.write_allow).toEqual(['src/add.ts', 'tests/add.test.ts']);
      expect(contract.scope_contract.write_deny).toContain('package.json');

      const record = readReconciliation(fx.root, '0001')!;
      expect(record.base_commit).toBe(fx.base);
      expect(record.files.map((f) => f.path)).toEqual(['src/add.ts', 'tests/add.test.ts']);

      const gates = evaluateAllGates('0001', getWorkArtifactsPaths('0001', fx.root).workDir);
      expect(gates.map((g) => g.result)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);

      // Teste ainda não commitado: congelar fica pendente, nunca é fingido.
      expect(result.frozen).toEqual([]);
      expect(result.pendingFreeze[0].task).toBe('1.1');
    } finally {
      fx.cleanup();
    }
  });

  test('congela os testes quando já estão commitados e a aprovação usa a base, não o HEAD', () => {
    const fx = fixture();
    try {
      git(fx.root, 'add', '-A');
      git(fx.root, 'commit', '-q', '-m', 'fora do pwn');
      const result = reconcileChanges({ rootDir: fx.root, since: fx.base });
      expect(result.frozen).toEqual(['1.1']);
      expect(loadTaskContract(result.workId!, '1.1', fx.root).acceptance_contract.frozen_tests?.[0].path).toBe('tests/add.test.ts');

      const verifierRootDir = mkdtempSync(path.join(tmpdir(), 'pwn-reconcile-verifier-'));
      try {
        const record = readReconciliation(fx.root, result.workId!)!;
        const approval = createApproval({
          rootDir: fx.root, workId: result.workId!, taskId: '1.1', approvedBy: 'teste', verifierRootDir,
          baselineCommit: record.base_commit,
        });
        expect(approval.baseline_commit).toBe(fx.base);
        expect(approval.baseline_commit).not.toBe(git(fx.root, 'rev-parse', 'HEAD'));
        expect(() => createApproval({
          rootDir: fx.root, workId: result.workId!, taskId: '1.1', approvedBy: 'teste', verifierRootDir,
          baselineCommit: '0'.repeat(40),
        })).toThrow();
      } finally {
        rmSync(verifierRootDir, { recursive: true, force: true });
      }
    } finally {
      fx.cleanup();
    }
  });

  test('não reconcilia duas vezes o mesmo conteúdo', () => {
    const fx = fixture();
    try {
      reconcileChanges({ rootDir: fx.root });
      expect(() => reconcileChanges({ rootDir: fx.root })).toThrow(/já conciliado no Work 0001/);

      // Um arquivo alterado de novo volta a ser mudança não gerenciada.
      write(fx.root, 'src/add.ts', 'export const add = (a: number, b: number) => b + a;\n');
      const again = reconcileChanges({ rootDir: fx.root, tests: ['tests/add.test.ts'], dryRun: true });
      expect(again.changes.map((c) => c.path)).toEqual(['src/add.ts']);
    } finally {
      fx.cleanup();
    }
  });

  test('mudança sem teste vira task com o teste a escrever depois, sob o contrato', () => {
    const fx = fixture();
    try {
      rmSync(path.join(fx.root, 'tests'), { recursive: true });
      const result = reconcileChanges({ rootDir: fx.root });
      expect(result.tasks).toEqual([{ id: '1.1', implementationFiles: ['src/add.ts'], testFiles: ['tests/add.test.ts'], testsToWrite: true }]);
      expect(result.frozen).toEqual([]);
      expect(result.pendingFreeze[0].reason).toMatch(/teste a escrever/);
      // O pwn não escreve no projeto: o teste ainda não existe, mas o contrato já o autoriza.
      expect(existsSync(path.join(fx.root, 'tests/add.test.ts'))).toBe(false);
      expect(loadTaskContract('0001', '1.1', fx.root).scope_contract.write_allow).toContain('tests/add.test.ts');
      const gates = evaluateAllGates('0001', getWorkArtifactsPaths('0001', fx.root).workDir);
      expect(gates.map((g) => g.result)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);

      // Depois: o teste é escrito e commitado, congela, e a aprovação usa a base da conciliação.
      write(fx.root, 'tests/add.test.ts', "import { test } from 'bun:test';\ntest('soma', () => {});\n");
      git(fx.root, 'add', '-A');
      git(fx.root, 'commit', '-q', '-m', 'teste escrito depois');
      freezeAcceptanceTests({ workId: '0001', taskId: '1.1', paths: ['tests/add.test.ts'], rootDir: fx.root });
      const verifierRootDir = mkdtempSync(path.join(tmpdir(), 'pwn-reconcile-verifier-'));
      try {
        const approval = createApproval({
          rootDir: fx.root, workId: '0001', taskId: '1.1', approvedBy: 'teste', verifierRootDir,
          baselineCommit: readReconciliation(fx.root, '0001')!.base_commit,
        });
        expect(approval.baseline_commit).toBe(fx.base);
      } finally {
        rmSync(verifierRootDir, { recursive: true, force: true });
      }
    } finally {
      fx.cleanup();
    }
  });

  test('o teste a escrever nunca reaproveita um caminho existente; --tests declara um existente', () => {
    const fx = fixture();
    try {
      git(fx.root, 'add', 'tests');
      git(fx.root, 'commit', '-q', '-m', 'teste existente');
      const fresh = reconcileChanges({ rootDir: fx.root, dryRun: true });
      expect(fresh.tasks[0]).toMatchObject({ testFiles: ['tests/add-reconcile.test.ts'], testsToWrite: true });

      const declared = reconcileChanges({ rootDir: fx.root, tests: ['tests/add.test.ts'], dryRun: true });
      expect(declared.tasks[0]).toMatchObject({ testFiles: ['tests/add.test.ts'], testsToWrite: false });
    } finally {
      fx.cleanup();
    }
  });

  test('divide em tasks de no máximo 6 arquivos de implementação e todas passam nos gates', () => {
    const fx = fixture();
    try {
      for (let index = 0; index < 8; index += 1) write(fx.root, `src/mod${index}.ts`, `export const v${index} = ${index};\n`);
      const result = reconcileChanges({ rootDir: fx.root, title: 'Muitos modulos' });
      expect(result.tasks.map((t) => t.implementationFiles.length)).toEqual([6, 3]);
      expect(result.tasks.map((t) => t.id)).toEqual(['1.1', '1.2']);
      const gates = evaluateAllGates(result.workId!, getWorkArtifactsPaths(result.workId!, fx.root).workDir);
      expect(gates.map((g) => g.result)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);
    } finally {
      fx.cleanup();
    }
  });

  test('só testes alterados não geram Work e dry-run não escreve nada', () => {
    const fx = fixture();
    try {
      expect(() => reconcileChanges({ rootDir: fx.root, paths: ['tests'] })).toThrow(/só há arquivos de teste/);
      reconcileChanges({ rootDir: fx.root, dryRun: true });
      expect(() => readFileSync(path.join(fx.root, '.pwn/work/0001/plan.json'))).toThrow();
    } finally {
      fx.cleanup();
    }
  });
});
