import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { placeholderPathReason } from './acceptance.js';
import type { RiskLevel } from './contract-engine.js';
import { scaffoldWork, type ScaffoldTaskSpec } from './scaffold.js';
import { freezeAcceptanceTests } from './task-contract.js';
import { getExistingWorkIds, getWorkArtifactsPaths } from './work-artifacts.js';

// ── Pós-conciliação ────────────────────────────────────────────────
//
// O operador altera o repositório SEM o pwn e pede para a governança absorver a
// mudança depois do fato. A conciliação NÃO inventa evidência: ela cria um Work
// cujo escopo é exatamente o conjunto de arquivos alterados e registra o commit de
// referência (`base_commit`). A conclusão continua vindo só de `pwn verify`: o
// verificador reverte a implementação a esse commit e exige que o teste congelado
// falhe lá — não há RED/GREEN observado, então o recibo é a única prova.

export const RECONCILIATION_FILE = 'reconciliation.json';

/** Raízes que pertencem à governança/dependências: nunca são "mudança não gerenciada". */
const GOVERNANCE_ROOTS: Record<string, true> = {
  '.git': true,
  '.pwn': true,
  '.todo': true,
  '.work': true,
  '.prompts': true,
  '.sources': true,
  queue: true,
  '.pwn-verifier': true,
  node_modules: true,
};

/** Máximo de arquivos de implementação por task (limite de atomicidade do GATE-SPEC-PLAN). */
const MAX_IMPLEMENTATION_FILES = 6;

const TEST_PATH = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|(^|\/)test_[^/]+\.py$/;

export type ChangeStatus = 'A' | 'M' | 'D';

export interface ReconcileChange {
  path: string;
  status: ChangeStatus;
  /** `null` para arquivo removido. */
  sha256: string | null;
  kind: 'implementation' | 'test';
}

export interface ReconcileSkip {
  path: string;
  reason: string;
}

export interface ReconcileOptions {
  rootDir: string;
  /** Referência git de onde a mudança parte; sem ela, vale o HEAD (árvore de trabalho não commitada). */
  since?: string;
  /** Restringe aos arquivos iguais ou abaixo destes prefixos (sem glob). */
  paths?: string[];
  /** Testes existentes que cobrem a mudança mesmo sem terem sido alterados. */
  tests?: string[];
  title?: string;
  workId?: string;
  risk?: RiskLevel;
  force?: boolean;
  dryRun?: boolean;
}

export interface ReconcileTask {
  id: string;
  implementationFiles: string[];
  testFiles: string[];
  /** `true` quando a mudança não tem teste: `testFiles` é o caminho a escrever depois, sob o contrato. */
  testsToWrite: boolean;
}

export interface ReconcileResult {
  dryRun: boolean;
  /** `null` em dry-run. */
  workId: string | null;
  baseCommit: string;
  headCommit: string;
  changes: ReconcileChange[];
  skipped: ReconcileSkip[];
  tasks: ReconcileTask[];
  generated: string[];
  /** Tasks cujos testes foram congelados no contrato. */
  frozen: string[];
  /** Tasks que ainda precisam congelar testes, com o motivo. */
  pendingFreeze: Array<{ task: string; reason: string }>;
}

export interface Reconciliation {
  version: 1;
  work_id: string;
  reconciled_at: string;
  base_commit: string;
  head_commit: string;
  since: string | null;
  files: Array<{ path: string; status: ChangeStatus; sha256: string | null; kind: ReconcileChange['kind'] }>;
  declared_tests: string[];
  skipped: ReconcileSkip[];
  tasks: ReconcileTask[];
  note: string;
}

function runGit(rootDir: string, args: string[]): string {
  const result = spawnSync('git', args, { cwd: rootDir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} falhou: ${(result.stderr || result.error?.message || '').trim()}`);
  }
  return result.stdout ?? '';
}

function gitSucceeds(rootDir: string, args: string[]): boolean {
  return spawnSync('git', args, { cwd: rootDir, encoding: 'utf8' }).status === 0;
}

function normalizePrefix(value: string): string {
  return path.posix.normalize(value.replace(/\\/g, '/')).replace(/^\.\//, '').replace(/\/+$/, '');
}

/** `path → sha256|null` de tudo que Works anteriores já conciliaram (ignora o Work informado). */
function alreadyReconciled(rootDir: string, ignoreWorkId: string | undefined): Map<string, { workId: string; sha256: string | null }[]> {
  const known = new Map<string, { workId: string; sha256: string | null }[]>();
  for (const workId of getExistingWorkIds(rootDir)) {
    if (workId === ignoreWorkId) continue;
    const record = readReconciliation(rootDir, workId);
    if (!record) continue;
    for (const file of record.files) {
      const entries = known.get(file.path) ?? [];
      entries.push({ workId, sha256: file.sha256 });
      known.set(file.path, entries);
    }
  }
  return known;
}

/** Conciliação registrada de um Work, ou `null` quando o Work não nasceu de uma conciliação. */
export function readReconciliation(rootDir: string, workId: string): Reconciliation | null {
  const file = path.join(getWorkArtifactsPaths(workId, rootDir).workDir, RECONCILIATION_FILE);
  if (!fs.existsSync(file)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Reconciliation;
    return parsed && parsed.version === 1 && typeof parsed.base_commit === 'string' && Array.isArray(parsed.files) ? parsed : null;
  } catch {
    return null;
  }
}

interface Detected {
  baseCommit: string;
  headCommit: string;
  changes: ReconcileChange[];
  skipped: ReconcileSkip[];
}

/** Lê o que mudou entre a referência e a árvore de trabalho (tracked + novos não ignorados). */
export function detectChanges(options: Pick<ReconcileOptions, 'rootDir' | 'since' | 'paths' | 'workId'>): Detected {
  const { rootDir } = options;
  if (!gitSucceeds(rootDir, ['rev-parse', '--git-dir'])) throw new Error(`${rootDir} não é um repositório git`);
  if (!gitSucceeds(rootDir, ['rev-parse', '--verify', 'HEAD^{commit}'])) {
    throw new Error('o repositório não tem nenhum commit: conciliar exige um commit de referência');
  }
  const headCommit = runGit(rootDir, ['rev-parse', 'HEAD']).trim();

  let baseCommit = headCommit;
  if (options.since) {
    if (!gitSucceeds(rootDir, ['rev-parse', '--verify', `${options.since}^{commit}`])) {
      throw new Error(`--since inválido: ${options.since} não é um commit`);
    }
    baseCommit = runGit(rootDir, ['rev-parse', `${options.since}^{commit}`]).trim();
    if (!gitSucceeds(rootDir, ['merge-base', '--is-ancestor', baseCommit, headCommit])) {
      throw new Error(`--since ${options.since} não é ancestral do HEAD`);
    }
  }

  const status = new Map<string, ChangeStatus>();
  const tracked = runGit(rootDir, ['diff', '--name-status', '--no-renames', '-z', baseCommit]).split('\0').filter(Boolean);
  for (let index = 0; index + 1 < tracked.length; index += 2) {
    const code = tracked[index][0];
    status.set(tracked[index + 1], code === 'A' ? 'A' : code === 'D' ? 'D' : 'M');
  }
  for (const untracked of runGit(rootDir, ['ls-files', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean)) {
    status.set(untracked, 'A');
  }

  const prefixes = (options.paths ?? []).map(normalizePrefix);
  const known = alreadyReconciled(rootDir, options.workId);
  const changes: ReconcileChange[] = [];
  const skipped: ReconcileSkip[] = [];

  for (const [file, changeStatus] of [...status].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (GOVERNANCE_ROOTS[file.split('/')[0]]) continue;
    if (prefixes.length > 0 && !prefixes.some((prefix) => file === prefix || file.startsWith(`${prefix}/`))) continue;
    if (/^\.env/.test(path.posix.basename(file))) {
      skipped.push({ path: file, reason: 'segredo (.env*): nunca é conciliado' });
      continue;
    }
    const placeholder = placeholderPathReason(file);
    if (placeholder) {
      skipped.push({ path: file, reason: `caminho ${placeholder}: o plano só declara arquivos concretos` });
      continue;
    }
    const absolute = path.resolve(rootDir, file);
    if (changeStatus !== 'D' && !(fs.existsSync(absolute) && fs.statSync(absolute).isFile())) {
      skipped.push({ path: file, reason: 'não é um arquivo regular' });
      continue;
    }
    const sha256 = changeStatus === 'D' ? null : createHash('sha256').update(fs.readFileSync(absolute)).digest('hex');
    const previous = known.get(file)?.find((entry) => entry.sha256 === sha256);
    if (previous) {
      skipped.push({ path: file, reason: `já conciliado no Work ${previous.workId}` });
      continue;
    }
    changes.push({ path: file, status: changeStatus, sha256, kind: TEST_PATH.test(file) ? 'test' : 'implementation' });
  }
  return { baseCommit, headCommit, changes, skipped };
}

function chunk<T>(values: T[], size: number): T[][] {
  const groups: T[][] = [];
  for (let index = 0; index < values.length; index += size) groups.push(values.slice(index, index + size));
  return groups;
}

/**
 * Concilia as mudanças feitas fora do pwn: descobre o que mudou, cria o Work
 * (cadeia completa + contrato por task com o escopo EXATO dos arquivos) e grava
 * `reconciliation.json` com o commit de referência. Não toca em nenhum arquivo do projeto.
 */
export function reconcileChanges(options: ReconcileOptions): ReconcileResult {
  const { rootDir } = options;
  const risk = options.risk ?? 'L2';
  const detected = detectChanges(options);
  const { baseCommit, headCommit, skipped } = detected;
  const changes = detected.changes;

  if (changes.length === 0) {
    throw new Error(
      skipped.length > 0
        ? `nada a conciliar: todas as mudanças foram ignoradas (${skipped.map((entry) => `${entry.path}: ${entry.reason}`).join('; ')})`
        : 'nada a conciliar: nenhuma mudança fora da governança desde a referência',
    );
  }

  const implementation = changes.filter((change) => change.kind === 'implementation');
  if (implementation.length === 0) {
    throw new Error('só há arquivos de teste alterados: não há implementação a conciliar (testes entram como cobertura da implementação)');
  }

  const declared = [...new Set((options.tests ?? []).map(normalizePrefix))];
  for (const test of declared) {
    const reason = placeholderPathReason(test);
    if (reason) throw new Error(`--tests ${test} ${reason}`);
    const absolute = path.resolve(rootDir, test);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) throw new Error(`--tests ${test} não existe`);
  }
  const testFiles = [...new Set([
    ...changes.filter((change) => change.kind === 'test' && change.status !== 'D').map((change) => change.path),
    ...declared,
  ])].sort();

  const title = options.title ?? `Conciliação de ${changes.length} arquivo(s) alterado(s) fora do pwn desde ${baseCommit.slice(0, 7)}`;
  const groups = chunk(implementation.map((change) => change.path), MAX_IMPLEMENTATION_FILES);
  const denied = ['.git/**', '.env*', ...(changes.some((change) => change.path === 'package.json') ? [] : ['package.json'])];

  // Sem teste algum, cada task declara o arquivo de teste a escrever depois, sob o contrato (o
  // `write_allow` já o autoriza). Nunca reaproveita um caminho que já existe nem cria o arquivo.
  const testsToWrite = testFiles.length === 0;
  const reserved = new Set<string>(changes.map((change) => change.path));
  const skeletonFor = (files: string[]): string => {
    const stem = path.posix.basename(files[0]).replace(/\.[^.]*$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'task';
    for (let attempt = 1; ; attempt += 1) {
      const suffix = attempt === 1 ? '' : attempt === 2 ? '-reconcile' : `-reconcile-${attempt - 1}`;
      const candidate = `tests/${stem}${suffix}.test.ts`;
      if (!reserved.has(candidate) && !fs.existsSync(path.resolve(rootDir, candidate))) {
        reserved.add(candidate);
        return candidate;
      }
    }
  };

  const specs: ScaffoldTaskSpec[] = groups.map((files, index) => {
    const tests = testsToWrite ? [skeletonFor(files)] : testFiles;
    return {
      title: groups.length > 1 ? `${title} — parte ${index + 1}/${groups.length}` : title,
      implementationFiles: files,
      testFiles: tests,
      behavior: `registra e aceita a mudança feita fora do pwn em ${files.length} arquivo(s) de implementação`,
      writeAllow: [...files, ...tests],
      writeDeny: denied,
    };
  });
  const tasks: ReconcileTask[] = specs.map((spec, index) => ({
    id: `1.${index + 1}`,
    implementationFiles: spec.implementationFiles,
    testFiles: spec.testFiles,
    testsToWrite,
  }));

  if (options.dryRun) {
    return { dryRun: true, workId: null, baseCommit, headCommit, changes, skipped, tasks, generated: [], frozen: [], pendingFreeze: [] };
  }

  if (options.workId && !options.force && fs.existsSync(getWorkArtifactsPaths(options.workId, rootDir).workDir)) {
    throw new Error(`Work ${options.workId} já existe (use --force para sobrescrever)`);
  }

  const scaffold = scaffoldWork({
    rootDir,
    title,
    workId: options.workId,
    risk,
    force: options.force,
    tasks: specs,
    narrative: {
      problem: `${changes.length} arquivo(s) foram alterados fora do pwn desde o commit ${baseCommit.slice(0, 7)} e precisam entrar na governança com escopo e aceitação verificáveis.`,
      solution: `Conciliar as mudanças em um Work cujo contrato V4 restringe a escrita aos arquivos alterados e cuja aceitação é o recibo independente sobre o teste congelado.`,
      objective: `Conciliar na governança a mudança feita fora do pwn sem alterar nenhum arquivo do projeto`,
      scenario: 'brownfield',
      author: 'pwn-reconcile',
    },
  });
  const workId = scaffold.workId;
  const generated = [...scaffold.generated];

  const record: Reconciliation = {
    version: 1,
    work_id: workId,
    reconciled_at: new Date().toISOString(),
    base_commit: baseCommit,
    head_commit: headCommit,
    since: options.since ?? null,
    files: changes.map(({ path: file, status, sha256, kind }) => ({ path: file, status, sha256, kind })),
    declared_tests: declared,
    skipped,
    tasks,
    note: 'Conciliação pós-fato: sem RED/GREEN observado. A aceitação vem de `pwn verify` com a implementação revertida a base_commit.',
  };
  const recordPath = path.join(getWorkArtifactsPaths(workId, rootDir).workDir, RECONCILIATION_FILE);
  fs.writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  generated.push(path.relative(rootDir, recordPath));

  const frozen: string[] = [];
  const pendingFreeze: ReconcileResult['pendingFreeze'] = [];
  for (const task of tasks) {
    if (task.testsToWrite) {
      pendingFreeze.push({ task: task.id, reason: `teste a escrever: ${task.testFiles.join(', ')} ainda não existe` });
      continue;
    }
    try {
      freezeAcceptanceTests({ workId, taskId: task.id, paths: task.testFiles, rootDir });
      frozen.push(task.id);
    } catch (error) {
      pendingFreeze.push({ task: task.id, reason: (error as Error).message });
    }
  }

  return { dryRun: false, workId, baseCommit, headCommit, changes, skipped, tasks, generated, frozen, pendingFreeze };
}
