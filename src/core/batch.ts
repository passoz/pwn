import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { commandMatches, displayCommand, regressionCommands } from './acceptance.js';
import { currentApproval } from './acceptance-approval.js';
import { DEPENDENCY_MANIFESTS, DEPENDENCY_PATHS, HARNESS_STATE_PATHS } from './candidate-snapshot.js';
import { checkDiffAgainstContract } from './contract-guard.js';
import { withFileLock, writeFileAtomic } from './fs-lock.js';
import { loadPlan, planMatchesMarkdown, tasksMarkdownPath } from './plan-renderer.js';
import { collectPlanStatus, collectProjectStatus } from './project_status.js';
import { pathFingerprint, prepareSandbox, type HarnessArtifacts } from './run-orchestrator.js';
import { cleanupGitWorktreeSandbox, createGitWorktreeSandbox, isBwrapSupported, resolveGitDir, wrapWithBwrap, type SandboxSession } from './sandbox.js';
import { globsMayOverlap } from './scope-overlap.js';
import { loadTaskContract } from './task-contract.js';

/**
 * Lotes paralelos de tasks de UM Work.
 *
 * Cada task do lote recebe um worktree próprio nascido do mesmo commit (`base`);
 * um agente implementa e roda o audit local ali. `integrateBatch` aplica cada
 * entrega na árvore principal (um commit por task) e traz a evidência local.
 *
 * Invariantes que evitam retrabalho de evidência:
 * - tasks do mesmo lote têm `write_allow` disjuntos, nenhum componente em comum e
 *   nenhuma dependência entre si: a evidência local (snapshot por arquivo declarado)
 *   continua válida depois que as outras entregas entram;
 * - a aprovação independente precisa existir ANTES do lote: o baseline aprovado é
 *   anterior à implementação, então o AC continua causal depois da integração;
 * - o recibo independente amarra a ÁRVORE INTEIRA: verificar dentro do worktree
 *   seria desperdício (a integração muda a árvore). A verificação roda uma vez,
 *   na árvore integrada, depois do último lote (`pwn verify run-all`).
 */

const MANIFEST = path.join('.pwn', 'batch.json');
/** Patch de referência da entrega original, ao lado do worktree refeito por `rebase`. */
const PATCH_SUFFIX = '.delivery.patch';
/** Estágios locais em que a implementação já está na árvore (GREEN em diante). */
const INTEGRATED_STAGES: Record<string, true> = { GREEN: true, VERIFIED: true, ACCEPTED: true };
/** Evidência local mínima para integrar: GREEN com mutation + verify PASS. */
const INTEGRABLE_STAGES: Record<string, true> = { VERIFIED: true, ACCEPTED: true };
/** Integração faz várias operações git e coleta status: o lock não pode ser tomado por "velho" no meio. */
const LOCK_OPTIONS = { timeoutMs: 5_000, staleMs: 10 * 60_000 };

export interface SchedulableTask {
  id: string;
  title: string;
  dependsOn: string[];
  components: string[];
  writeAllow: string[];
  risk: string;
  /** Marcador do plano: ' ', 'x' ou '!'. */
  marker: string;
  /** Estágio da evidência local na árvore principal (`not started`, `BASELINE`, …). */
  stage: string;
  crossWorkBlockers: string[];
  /** Aprovação independente vigente cujo baseline é ancestral do HEAD. */
  approved: boolean;
}

export interface Deferral {
  id: string;
  reason: string;
}

export interface Schedule {
  batch: SchedulableTask[];
  deferred: Deferral[];
  integrated: string[];
}

export interface BatchTask {
  id: string;
  title: string;
  run_id: string;
  worktree: string;
  branch: string;
  git_dir: string;
  /** Artefatos que o harness injetou no worktree (node_modules, bunfig.toml) com a assinatura: nunca são entrega. */
  injected: HarnessArtifacts;
  /** Commit em que o worktree foi refeito por `rebase`; ausente = base do lote. */
  base?: string;
}

export interface BatchManifest {
  version: 1;
  batch_id: string;
  work_id: string;
  /** Commit do qual todos os worktrees nasceram. */
  base: string;
  /** HEAD esperado na árvore principal (avança a cada task integrada). */
  head: string;
  created_at: string;
  tasks: BatchTask[];
}

/**
 * Por que a task ficou retida. `clash` e `stale_base` se resolvem refazendo a task sobre
 * o HEAD integrado (`rebase`); os demais exigem o agente (ou o operador).
 */
export type HoldKind = 'delivery' | 'clash' | 'stale_base' | 'regression' | 'commit' | 'interrupted';

export interface IntegrationResult {
  batchId: string;
  workId: string;
  integrated: Array<{ id: string; commit: string; files: string[] }>;
  failed: Array<{ id: string; kind: HoldKind; reasons: string[] }>;
  warnings: string[];
  remaining: string[];
}

function runGit(cwd: string, args: string[], input?: Buffer): { status: number; stdout: Buffer; stderr: string } {
  const result = spawnSync('git', args, { cwd, input, maxBuffer: 256 * 1024 * 1024 });
  const stderr = (result.stderr ?? Buffer.alloc(0)).toString('utf8').trim();
  return { status: result.status ?? 1, stdout: result.stdout ?? Buffer.alloc(0), stderr: stderr || result.error?.message || '' };
}

function gitOut(cwd: string, args: string[]): string {
  const result = runGit(cwd, args);
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} falhou: ${result.stderr}`);
  return result.stdout.toString('utf8');
}

function gitList(cwd: string, args: string[]): string[] {
  return gitOut(cwd, args).split('\0').filter(Boolean);
}

function headOf(root: string): string {
  return gitOut(root, ['rev-parse', 'HEAD']).trim();
}

function isAncestor(root: string, ancestor: string, descendant: string): boolean {
  return runGit(root, ['merge-base', '--is-ancestor', ancestor, descendant]).status === 0;
}

/**
 * Estado do harness que pode estar sujo sem afetar o lote. Artefatos de governança
 * versionados (`.pwn/work/NNNN/*`) não entram aqui: o worktree os recebe pelo HEAD,
 * então precisam estar commitados. Caches dentro deles (`.pwn/work/NNNN/.pwn/`) entram.
 */
function isHarnessState(file: string): boolean {
  if (/^(\.todo|\.work|queue)\//.test(file)) return true;
  if (!file.startsWith('.pwn/')) return false;
  return !file.startsWith('.pwn/work/') || /^\.pwn\/work\/[^/]+\/\.pwn\//.test(file);
}

/** Alterações não commitadas que impedem o lote: worktrees nascem do HEAD e a integração aplica diffs sobre ele. */
export function blockingChanges(root: string): string[] {
  const tokens = gitOut(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']).split('\0');
  const files: string[] = [];
  for (let index = 0; index < tokens.length; index++) {
    const entry = tokens[index];
    if (entry.length < 4) continue;
    // Em rename/cópia o caminho de origem vem no token seguinte.
    if (entry[0] === 'R' || entry[0] === 'C') index++;
    const file = entry.slice(3);
    if (!isHarnessState(file)) files.push(file);
  }
  return files;
}

function soloReason(task: SchedulableTask): string | null {
  if (task.risk === 'L4') return 'risco L4 (revisão humana)';
  const manifest = task.writeAllow.find((pattern) => DEPENDENCY_MANIFESTS.some((file) => globsMayOverlap(pattern, file)));
  return manifest ? `escopo alcança manifesto de dependências (${manifest}); node_modules é compartilhado` : null;
}

/**
 * Próximo lote, em ordem de plano. Uma task entra quando está pronta (dependências
 * integradas, aprovação vigente, nada em andamento na árvore principal) e não conflita
 * com nenhuma task já escolhida. Conflito = `write_allow` que pode sobrepor (heurística
 * conservadora), componente em comum, ou necessidade de execução isolada.
 */
export function planNextBatch(tasks: SchedulableTask[], maxJobs: number, workId: string, only?: ReadonlySet<string>): Schedule {
  const byId = new Map(tasks.map((task) => [task.id, task]));
  const isIntegrated = (task: SchedulableTask): boolean => task.marker === 'x' || INTEGRATED_STAGES[task.stage] === true;
  const batch: SchedulableTask[] = [];
  const deferred: Deferral[] = [];
  const integrated: string[] = [];

  for (const task of tasks) {
    if (isIntegrated(task)) {
      integrated.push(task.id);
      continue;
    }
    if (only && !only.has(task.id)) continue;
    const defer = (reason: string): void => {
      deferred.push({ id: task.id, reason });
    };

    if (task.marker === '!') {
      defer('bloqueada no plano ([!])');
      continue;
    }
    if (task.stage !== 'not started') {
      defer(`já iniciada na árvore principal (evidência local: ${task.stage}); termine-a fora do lote`);
      continue;
    }
    const pendingDependency = task.dependsOn
      .map((raw) => ({ raw, id: raw.startsWith(`${workId}/`) ? raw.slice(workId.length + 1) : raw }))
      // Dependências de outro Work (NNNN/x.y) são resolvidas por crossWorkBlockers.
      .filter((dependency) => !/^\d{4}\//.test(dependency.id))
      .map((dependency) => {
        const target = byId.get(dependency.id);
        if (!target) return `depende de ${dependency.raw}, que não existe no plano`;
        return isIntegrated(target) ? null : `depende de ${dependency.raw}, ainda não integrada`;
      })
      .find((reason): reason is string => reason !== null);
    if (pendingDependency) {
      defer(pendingDependency);
      continue;
    }
    if (task.crossWorkBlockers.length) {
      defer(`dependência entre Works sem aceitação independente: ${task.crossWorkBlockers.join(', ')}`);
      continue;
    }
    if (!task.approved) {
      defer('sem aprovação vigente: rode pwn verify approve ANTES de implementar (aprovada depois, o baseline já contém a implementação e o AC falha como vácuo)');
      continue;
    }

    const solo = soloReason(task);
    const soloMember = batch.find((member) => soloReason(member));
    if (soloMember) {
      defer(`aguarda: ${soloMember.id} exige execução isolada`);
      continue;
    }
    if (solo && batch.length) {
      defer(`exige execução isolada (${solo}); entra num lote próprio`);
      continue;
    }
    let conflict: string | null = null;
    for (const member of batch) {
      const pair = task.writeAllow
        .flatMap((a) => member.writeAllow.map((b) => [a, b] as const))
        .find(([a, b]) => globsMayOverlap(a, b));
      if (pair) {
        conflict = `escopo pode sobrepor ${member.id} (${pair[0]} × ${pair[1]})`;
        break;
      }
      const component = task.components.find((name) => member.components.includes(name));
      if (component) {
        conflict = `componente compartilhado com ${member.id}: ${component}`;
        break;
      }
    }
    if (conflict) {
      defer(conflict);
      continue;
    }
    if (batch.length >= maxJobs) {
      defer(`limite de ${maxJobs} task(s) por lote`);
      continue;
    }
    batch.push(task);
  }
  return { batch, deferred, integrated };
}

/** Entradas do scheduler a partir do plano, dos contratos, do status local e das aprovações. */
export function collectSchedulableTasks(workId: string, root: string): SchedulableTask[] {
  const plan = loadPlan(workId, root);
  if (!plan) throw new Error(`plan.json ausente para o Work ${workId}`);
  const markdownPath = tasksMarkdownPath(workId, root);
  const relative = path.relative(root, markdownPath);
  if (!fs.existsSync(markdownPath)) throw new Error(`plano derivado ausente: ${relative} (rode pwn work plan --work ${workId})`);
  if (!planMatchesMarkdown(plan, fs.readFileSync(markdownPath, 'utf8'))) {
    throw new Error(`DRIFT: ${relative} diverge de plan.json; regenere com pwn work plan --work ${workId} --force`);
  }
  const status = collectPlanStatus(workId, root);
  const head = headOf(root);
  return plan.tasks.map((task) => {
    const row = status.tasks.find((entry) => entry.id === task.id);
    const contract = loadTaskContract(workId, task.id, root);
    const approval = currentApproval(workId, task.id);
    return {
      id: task.id,
      title: task.title,
      dependsOn: task.depends_on ?? [],
      components: task.components ?? [],
      writeAllow: contract.scope_contract.write_allow,
      risk: contract.risk.level,
      marker: row?.marker ?? ' ',
      stage: row?.evidence.stage ?? 'not started',
      crossWorkBlockers: status.crossWorkBlockers?.[task.id] ?? [],
      approved: approval !== null && isAncestor(root, approval.baseline_commit, head),
    };
  });
}

function manifestFile(root: string): string {
  return path.join(root, MANIFEST);
}

export function readBatch(root: string): BatchManifest | null {
  const file = manifestFile(root);
  if (!fs.existsSync(file)) return null;
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as BatchManifest;
  if (parsed?.version !== 1) throw new Error(`manifesto de lote inválido: ${file}`);
  return parsed;
}

function sessionOf(task: BatchTask): SandboxSession {
  return { runId: task.run_id, worktreePath: task.worktree, branchName: task.branch, created: true, gitDir: task.git_dir };
}

function preview(files: string[]): string {
  return files.length > 5 ? `${files.slice(0, 5).join(', ')} … +${files.length - 5}` : files.join(', ');
}

export interface PrepareOptions {
  root: string;
  workId: string;
  jobs: number;
  /** Restringe o lote a estas tasks; cada uma precisa estar pronta e compatível. */
  only?: string[];
}

/** Cria um worktree por task do próximo lote. Lote vazio devolve `manifest: null` com os motivos. */
export function prepareBatch(options: PrepareOptions): { manifest: BatchManifest | null; schedule: Schedule } {
  const { root, workId } = options;
  return withFileLock(manifestFile(root), () => {
    const active = readBatch(root);
    if (active) {
      throw new Error(`já existe um lote ativo (${active.batch_id}, Work ${active.work_id}: ${active.tasks.map((task) => task.id).join(', ')}); integre com 'pwn work batch integrate' ou descarte com 'pwn work batch abort'`);
    }
    const dirty = blockingChanges(root);
    if (dirty.length) {
      throw new Error(`a árvore principal tem alterações não commitadas (${preview(dirty)}): os worktrees nascem do HEAD e a integração aplica diffs sobre ele — commite ou descarte antes`);
    }

    const tasks = collectSchedulableTasks(workId, root);
    const only = options.only ? new Set(options.only) : undefined;
    if (only) {
      const unknown = [...only].filter((id) => !tasks.some((task) => task.id === id));
      if (unknown.length) throw new Error(`task(s) fora do plano do Work ${workId}: ${unknown.join(', ')}`);
    }
    const schedule = planNextBatch(tasks, options.jobs, workId, only);
    if (only) {
      const problems = [
        ...[...only].filter((id) => schedule.integrated.includes(id)).map((id) => `${id}: já integrada`),
        ...schedule.deferred.map((entry) => `${entry.id}: ${entry.reason}`),
      ];
      if (problems.length) throw new Error(`--tasks não forma um lote válido:\n  ${problems.join('\n  ')}`);
    }
    if (!schedule.batch.length) return { manifest: null, schedule };

    const base = headOf(root);
    const markdownPath = tasksMarkdownPath(workId, root);
    const batchId = `BATCH-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
    const entries: BatchTask[] = [];
    try {
      for (const task of schedule.batch) {
        const session = createGitWorktreeSandbox(`${batchId}-${task.id}`, root);
        const entry: BatchTask = {
          id: task.id,
          title: task.title,
          run_id: session.runId,
          worktree: session.worktreePath,
          branch: session.branchName,
          git_dir: session.gitDir,
          injected: {},
        };
        entries.push(entry);
        entry.injected = prepareSandbox(session.worktreePath, root);
        // `.todo/` não é versionado: o audit do worktree precisa do plano derivado.
        const target = path.join(session.worktreePath, path.relative(root, markdownPath));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(markdownPath, target);
      }
    } catch (error) {
      for (const entry of entries) cleanupGitWorktreeSandbox(sessionOf(entry), root);
      throw error;
    }

    const manifest: BatchManifest = {
      version: 1,
      batch_id: batchId,
      work_id: workId,
      base,
      head: base,
      created_at: new Date().toISOString(),
      tasks: entries,
    };
    writeFileAtomic(manifestFile(root), `${JSON.stringify(manifest, null, 2)}\n`);
    return { manifest, schedule };
  }, LOCK_OPTIONS);
}

function localEvidence(treeRoot: string, workId: string, taskId: string): { stage: string; stale: boolean } {
  const row = collectProjectStatus(tasksMarkdownPath(workId, treeRoot)).tasks.find((task) => task.id === taskId);
  return row ? { stage: row.evidence.stage, stale: row.evidence.stale } : { stage: 'ausente do plano', stale: false };
}

/** Evidência local de UMA task (estado, logs, cadeia, atestações): nomes `<task>.json` ou `<task>-*`. */
function copyTaskEvidence(fromRoot: string, toRoot: string, workId: string, taskId: string): void {
  const directories = [
    path.join('.todo', 'evidence', workId),
    path.join('.todo', 'evidence', workId, 'state'),
    path.join('.todo', 'attestations', workId),
  ];
  for (const directory of directories) {
    const source = path.join(fromRoot, directory);
    if (!fs.existsSync(source)) continue;
    for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
      if (!entry.isFile() || (entry.name !== `${taskId}.json` && !entry.name.startsWith(`${taskId}-`))) continue;
      fs.mkdirSync(path.join(toRoot, directory), { recursive: true });
      fs.copyFileSync(path.join(source, entry.name), path.join(toRoot, directory, entry.name));
    }
  }
}

interface Delivery {
  task: BatchTask;
  files: string[];
  patch: Buffer;
}

/** O que o agente entregou num worktree: arquivos alterados e o diff contra o base da task. */
interface Capture {
  files: string[];
  patch: Buffer;
  /** Alterações em artefatos do harness: ignoradas, não são entrega. */
  harness: string[];
}

/** Base de uma task: o do lote, ou o HEAD em que ela foi refeita por `rebase`. */
function baseOf(manifest: BatchManifest, task: BatchTask): string {
  return task.base ?? manifest.base;
}

const CONFLICT_MARKERS = [/^<{7} /m, /^={7}\r?$/m, /^>{7} /m];

/** Arquivos da entrega que ainda têm marcadores de conflito (os três marcadores presentes). */
function unresolvedConflicts(treeRoot: string, files: string[]): string[] {
  return files.filter((file) => {
    try {
      const target = path.join(treeRoot, file);
      const stats = fs.statSync(target);
      if (!stats.isFile() || stats.size > 5 * 1024 * 1024) return false;
      const text = fs.readFileSync(target, 'utf8');
      return CONFLICT_MARKERS.every((marker) => marker.test(text));
    } catch {
      return false;
    }
  });
}

/** Remove worktree, branch e o patch de referência de uma task. */
function dropTask(task: BatchTask, root: string): void {
  cleanupGitWorktreeSandbox(sessionOf(task), root);
  fs.rmSync(`${task.worktree}${PATCH_SUFFIX}`, { force: true });
}

/** Âncora do worktree + inventário e diff da entrega (commitada ou não) contra `base`. */
function captureDelivery(task: BatchTask, base: string): { capture?: Capture; reasons: string[] } {
  if (!fs.existsSync(task.worktree)) return { reasons: [`worktree ausente: ${task.worktree}`] };
  // Âncora: sem o `.git` do worktree o Git subiria para o repositório principal e o
  // `add -A` abaixo encenaria a árvore errada (mesma defesa de `modifiedFiles`).
  const gitDir = resolveGitDir(task.worktree);
  if (!gitDir || path.resolve(gitDir) !== path.resolve(task.git_dir)) {
    return { reasons: [`worktree ${task.worktree} não aponta mais para o repositório do lote (${gitDir ?? 'nenhum'}); árvore substituída — descarte o lote`] };
  }
  const replaced = Object.entries(task.injected)
    .filter(([relative, signature]) => pathFingerprint(path.join(task.worktree, relative)) !== signature)
    .map(([relative]) => relative);
  if (replaced.length) {
    return { reasons: [`artefato do harness substituído no worktree: ${replaced.join(', ')} (instalar dependências exige lote isolado, com o manifesto no write_allow)`] };
  }
  const excludes = [...HARNESS_STATE_PATHS, ...DEPENDENCY_PATHS, ...Object.keys(task.injected)].map((entry) => `:(exclude)${entry}`);
  // O índice do worktree é dele: `add -A` + `diff --cached <base>` cobre tanto o que o
  // agente commitou no branch quanto o que ficou só na working tree. `--no-renames`
  // lista a origem de um rename como remoção: mover um arquivo para fora do escopo
  // também é escrita fora do escopo.
  const added = runGit(task.worktree, ['add', '-A', '--', '.', ...excludes]);
  if (added.status !== 0) return { reasons: [`git add no worktree falhou: ${added.stderr}`] };
  const files = gitList(task.worktree, ['diff', '--cached', '--no-renames', '--name-only', '-z', base, '--', '.', ...excludes]);
  const harness = gitList(task.worktree, ['diff', '--no-renames', '--name-only', '-z', base, '--', '.pwn/work', '.work']);
  const patch = runGit(task.worktree, ['diff', '--cached', '--no-renames', '--binary', base, '--', '.', ...excludes]);
  if (patch.status !== 0) return { reasons: [`git diff no worktree falhou: ${patch.stderr}`] };
  return { capture: { files, patch: patch.stdout, harness }, reasons: [] };
}

/** Inventário da entrega de uma task e as checagens de integração. */
function inspectDelivery(root: string, manifest: BatchManifest, task: BatchTask, warnings: string[]): { delivery?: Delivery; reasons: string[] } {
  const captured = captureDelivery(task, baseOf(manifest, task));
  if (!captured.capture) return { reasons: captured.reasons };
  const { files, patch, harness } = captured.capture;
  if (harness.length) warnings.push(`${task.id}: alterações em artefatos do harness ignoradas (não são entrega): ${preview(harness)}`);
  if (!files.length) return { reasons: ['nenhuma alteração em relação ao base da task'] };

  const reasons: string[] = [];
  const unresolved = unresolvedConflicts(task.worktree, files);
  if (unresolved.length) reasons.push(`conflito não resolvido (marcadores <<<<<<< / ======= / >>>>>>>): ${preview(unresolved)}`);
  const contract = loadTaskContract(manifest.work_id, task.id, root);
  const scope = checkDiffAgainstContract(files, contract.scope_contract.write_allow, contract.scope_contract.write_deny ?? []);
  for (const violation of scope.violations) reasons.push(`DIFF VIOLATION ${violation.file}: ${violation.reason ?? violation.violationType}`);

  const evidence = localEvidence(task.worktree, manifest.work_id, task.id);
  if (!INTEGRABLE_STAGES[evidence.stage] || evidence.stale) {
    reasons.push(`evidência local insuficiente: ${evidence.stage}${evidence.stale ? ' (STALE)' : ''} — no worktree rode baseline → red → green → verify`);
  } else {
    // O green/check posteriores leem o conteúdo do baseline nesse commit: ele precisa existir
    // na árvore principal, não só num commit local do branch que a limpeza apaga.
    const state = JSON.parse(fs.readFileSync(path.join(task.worktree, '.todo', 'evidence', manifest.work_id, 'state', `${task.id}.json`), 'utf8')) as { baseline_commit?: string };
    if (!state.baseline_commit || !isAncestor(root, state.baseline_commit, manifest.head)) {
      reasons.push(`baseline do audit capturado sobre ${state.baseline_commit ?? '(nenhum commit)'}, que não está na árvore principal; refaça o baseline a partir do base do lote`);
    }
  }
  if (reasons.length) return { reasons };
  return { delivery: { task, files, patch }, reasons: [] };
}

/** Gate de regressão da integração: o comando vem do operador e precisa ser o declarado no plano. */
export interface RegressionOptions {
  command: string[];
  timeoutSeconds: number;
}

/** Executa a regressão numa árvore (sob `bwrap` quando disponível, sem rede e sem a chave do verificador). */
function runRegression(treeRoot: string, regression: RegressionOptions): { ok: boolean; tail: string } {
  const env = { ...process.env };
  delete env.PWN_VERIFIER_KEY;
  delete env.PWN_VERIFIER_HOME;
  const [executable, ...args] = regression.command;
  const wrapped = isBwrapSupported() ? wrapWithBwrap(executable, args, treeRoot) : { command: executable, args };
  const result = spawnSync(wrapped.command, wrapped.args, {
    cwd: treeRoot,
    env,
    encoding: 'utf8',
    timeout: regression.timeoutSeconds * 1000,
    killSignal: 'SIGKILL',
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`.trimEnd().split('\n').slice(-15).join('\n');
  const timedOut = (result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
  const detail = output || result.error?.message || `exit ${result.status}`;
  return { ok: result.status === 0 && !result.error, tail: timedOut ? `excedeu ${regression.timeoutSeconds}s\n${detail}` : detail };
}

/** Recusa um comando de regressão que o plano não declara: o harness nunca executa comando lido de fora do plano. */
function assertDeclaredRegression(root: string, workId: string, command: string[]): void {
  const planText = fs.readFileSync(tasksMarkdownPath(workId, root), 'utf8');
  const declared = regressionCommands(planText);
  if (!declared.some((planned) => commandMatches(planned, command))) {
    throw new Error(`comando de regressão diverge do plano (operador: \`${displayCommand(command)}\`; plano: ${declared.length ? declared.map((entry) => `\`${entry}\``).join(' | ') : 'nenhum declarado na coluna Regression nem em ## Global gates'})`);
  }
}

const APPLY_ARGS = ['apply', '--index', '--binary', '--whitespace=nowarn', '-'];
const REVERT_ARGS = ['apply', '-R', '--index', '--binary', '--whitespace=nowarn', '-'];

/**
 * Integra as entregas prontas do lote ativo: um commit por task, em ordem de plano,
 * e a evidência local copiada para a árvore principal. Tasks reprovadas continuam no
 * lote (worktree intacto) para correção; as demais entram mesmo assim — seus arquivos
 * são disjuntos, então o diff de cada uma aplica sobre o HEAD já avançado.
 *
 * Com `regression`, cada entrega é aplicada primeiro num worktree temporário que já
 * contém as anteriores do lote e roda o comando ali. Só passa para a árvore principal
 * quem passa: a task que quebra a suíte integrada é identificada na hora e nada é commitado.
 */
export function integrateBatch(options: { root: string; workId?: string | null; regression?: RegressionOptions }): IntegrationResult {
  const { root, regression } = options;
  return withFileLock(manifestFile(root), () => {
    const manifest = readBatch(root);
    if (!manifest) throw new Error("nenhum lote ativo: prepare um com 'pwn work batch prepare'");
    if (options.workId && options.workId !== manifest.work_id) {
      throw new Error(`o lote ativo é do Work ${manifest.work_id}, não do ${options.workId}`);
    }
    const head = headOf(root);
    if (head !== manifest.head) {
      throw new Error(`HEAD mudou fora do lote (esperado ${manifest.head.slice(0, 12)}, atual ${head.slice(0, 12)}): commits externos durante o lote não são integráveis com segurança — desfaça-os ou descarte o lote`);
    }
    const dirty = blockingChanges(root);
    if (dirty.length) throw new Error(`a árvore principal tem alterações não commitadas (${preview(dirty)}); a integração commita sobre ela — commite ou descarte antes`);
    if (regression) assertDeclaredRegression(root, manifest.work_id, regression.command);

    const warnings: string[] = [];
    if (!regression) {
      warnings.push("nenhuma regressão executada na árvore integrada: conflitos de comportamento entre tasks só aparecem no 'pwn verify run-all' final (use: pwn work batch integrate -- <comando de regressão do plano>)");
    }
    const failed: IntegrationResult['failed'] = [];
    const deliveries: Delivery[] = [];
    for (const task of manifest.tasks) {
      const inspected = inspectDelivery(root, manifest, task, warnings);
      if (inspected.delivery) deliveries.push(inspected.delivery);
      else failed.push({ id: task.id, kind: 'delivery', reasons: inspected.reasons });
    }

    // Escopos disjuntos garantem arquivos disjuntos; a checagem real protege contra
    // falso negativo da heurística de globs. A primeira em ordem de plano entra; a(s)
    // seguinte(s) ficam retidas e precisam de `rebase` sobre o resultado.
    const owners = new Map<string, string>();
    const clashes = new Map<string, string[]>();
    for (const delivery of deliveries) {
      for (const file of delivery.files) {
        const owner = owners.get(file);
        if (!owner) {
          owners.set(file, delivery.task.id);
          continue;
        }
        clashes.set(delivery.task.id, [...(clashes.get(delivery.task.id) ?? []), `${file} também alterado por ${owner}, que vem antes no plano; integre ${owner} e rode 'pwn work batch rebase ${delivery.task.id}'`]);
      }
    }

    const integrated: IntegrationResult['integrated'] = [];
    let interrupted: string | null = null;
    let gateTree: SandboxSession | null = null;
    try {
      if (regression) {
        gateTree = createGitWorktreeSandbox(`${manifest.batch_id}-regression`, root);
        prepareSandbox(gateTree.worktreePath, root);
      }
      for (const delivery of deliveries) {
        const { task } = delivery;
        const clash = clashes.get(task.id);
        if (clash) {
          failed.push({ id: task.id, kind: 'clash', reasons: clash });
          continue;
        }
        if (interrupted) {
          failed.push({ id: task.id, kind: 'interrupted', reasons: [`não aplicada: integração interrompida em ${interrupted}`] });
          continue;
        }
        if (gateTree && regression) {
          const staged = runGit(gateTree.worktreePath, APPLY_ARGS, delivery.patch);
          if (staged.status !== 0) {
            failed.push({ id: task.id, kind: 'stale_base', reasons: [`o diff não aplica sobre o HEAD integrado: ${staged.stderr}`, `refaça a task sobre o HEAD atual: pwn work batch rebase ${task.id}`] });
            continue;
          }
          const check = runRegression(gateTree.worktreePath, regression);
          if (!check.ok) {
            runGit(gateTree.worktreePath, REVERT_ARGS, delivery.patch);
            failed.push({ id: task.id, kind: 'regression', reasons: [`regressão falhou com a entrega aplicada sobre o HEAD integrado (\`${displayCommand(regression.command)}\`); a árvore principal não foi tocada:`, ...check.tail.split('\n').map((line) => `  | ${line}`)] });
            continue;
          }
        }
        const applied = runGit(root, APPLY_ARGS, delivery.patch);
        if (applied.status !== 0) {
          if (gateTree) runGit(gateTree.worktreePath, REVERT_ARGS, delivery.patch);
          failed.push({ id: task.id, kind: 'stale_base', reasons: [`o diff não aplica sobre o HEAD: ${applied.stderr}`, `refaça a task sobre o HEAD atual: pwn work batch rebase ${task.id}`] });
          continue;
        }
        const committed = runGit(root, ['commit', '-q', '-m', `pwn batch ${manifest.work_id}/${task.id}: ${task.title}`, '-m', `Lote ${manifest.batch_id}; base ${baseOf(manifest, task)}.`]);
        if (committed.status !== 0) {
          runGit(root, REVERT_ARGS, delivery.patch);
          if (gateTree) runGit(gateTree.worktreePath, REVERT_ARGS, delivery.patch);
          failed.push({ id: task.id, kind: 'commit', reasons: [`git commit falhou: ${committed.stderr}`] });
          interrupted = task.id;
          continue;
        }
        copyTaskEvidence(task.worktree, root, manifest.work_id, task.id);
        const after = localEvidence(root, manifest.work_id, task.id);
        if (!INTEGRABLE_STAGES[after.stage] || after.stale) {
          warnings.push(`${task.id}: evidência local na árvore principal ficou ${after.stage}${after.stale ? ' (STALE)' : ''} após integrar; refaça o audit da task`);
        }
        dropTask(task, root);
        integrated.push({ id: task.id, commit: headOf(root), files: delivery.files });
      }
    } finally {
      if (gateTree) cleanupGitWorktreeSandbox(gateTree, root);
    }

    const done = new Set(integrated.map((entry) => entry.id));
    const remaining = manifest.tasks.filter((task) => !done.has(task.id));
    if (remaining.length) {
      writeFileAtomic(manifestFile(root), `${JSON.stringify({ ...manifest, head: headOf(root), tasks: remaining }, null, 2)}\n`);
    } else {
      fs.rmSync(manifestFile(root), { force: true });
    }
    return {
      batchId: manifest.batch_id,
      workId: manifest.work_id,
      integrated,
      failed: manifest.tasks.flatMap((task) => failed.filter((entry) => entry.id === task.id)),
      warnings,
      remaining: remaining.map((task) => task.id),
    };
  }, LOCK_OPTIONS);
}

export interface RebaseResult {
  taskId: string;
  worktree: string;
  /** HEAD sobre o qual a entrega foi reaplicada. */
  base: string;
  /** Arquivos com conflito de 3-way; vazio quando a reaplicação foi limpa. */
  conflicts: string[];
  /** Evidência local avaliada no worktree novo: só vale se `VERIFIED` e sem STALE. */
  evidence: { stage: string; stale: boolean };
  /** Entrega original (diff contra o base antigo), para refazer o audit se a evidência caducou. */
  patchFile: string;
}

/**
 * Refaz uma task sobre o HEAD atual: novo worktree no HEAD, entrega reaplicada com
 * `--3way`. Conflito fica no worktree (marcadores) para o agente resolver: o harness
 * nunca decide a resolução. A evidência é copiada e REAVALIADA — se um arquivo declarado
 * mudou na mescla, ela fica STALE e o audit precisa ser refeito.
 */
export function rebaseTask(options: { root: string; taskId: string }): RebaseResult {
  const { root, taskId } = options;
  return withFileLock(manifestFile(root), () => {
    const manifest = readBatch(root);
    if (!manifest) throw new Error("nenhum lote ativo: prepare um com 'pwn work batch prepare'");
    const task = manifest.tasks.find((entry) => entry.id === taskId);
    if (!task) throw new Error(`a task ${taskId} não está no lote ativo (${manifest.tasks.map((entry) => entry.id).join(', ') || 'vazio'})`);
    const head = headOf(root);
    if (head !== manifest.head) {
      throw new Error(`HEAD mudou fora do lote (esperado ${manifest.head.slice(0, 12)}, atual ${head.slice(0, 12)}): commits externos não são suportados — desfaça-os ou descarte o lote`);
    }
    const dirty = blockingChanges(root);
    if (dirty.length) throw new Error(`a árvore principal tem alterações não commitadas (${preview(dirty)}); commite ou descarte antes`);
    const oldBase = baseOf(manifest, task);
    if (oldBase === head) throw new Error(`a task ${taskId} já está sobre o HEAD atual; não há o que refazer`);

    const captured = captureDelivery(task, oldBase);
    if (!captured.capture) throw new Error(captured.reasons.join('; '));
    if (!captured.capture.files.length) throw new Error(`a task ${taskId} não tem alterações para reaplicar`);

    const session = createGitWorktreeSandbox(`${manifest.batch_id}-${taskId}-${crypto.randomBytes(3).toString('hex')}`, root);
    const patchFile = `${session.worktreePath}${PATCH_SUFFIX}`;
    let conflicts: string[];
    try {
      const injected = prepareSandbox(session.worktreePath, root);
      const markdownPath = tasksMarkdownPath(manifest.work_id, root);
      const planTarget = path.join(session.worktreePath, path.relative(root, markdownPath));
      fs.mkdirSync(path.dirname(planTarget), { recursive: true });
      fs.copyFileSync(markdownPath, planTarget);
      copyTaskEvidence(task.worktree, session.worktreePath, manifest.work_id, taskId);
      fs.writeFileSync(patchFile, captured.capture.patch);

      const applied = runGit(session.worktreePath, ['apply', '--3way', '--binary', '--whitespace=nowarn', '-'], captured.capture.patch);
      conflicts = gitList(session.worktreePath, ['diff', '--name-only', '-z', '--diff-filter=U']);
      // Falha sem conflito (patch corrompido, caminho inexistente): nada a resolver; o worktree antigo segue intacto.
      if (applied.status !== 0 && !conflicts.length) throw new Error(`git apply --3way falhou sem gerar conflitos: ${applied.stderr}`);
      const replaced: BatchTask = {
        ...task,
        run_id: session.runId,
        worktree: session.worktreePath,
        branch: session.branchName,
        git_dir: session.gitDir,
        injected,
        base: head,
      };
      writeFileAtomic(manifestFile(root), `${JSON.stringify({ ...manifest, tasks: manifest.tasks.map((entry) => (entry.id === taskId ? replaced : entry)) }, null, 2)}\n`);
    } catch (error) {
      cleanupGitWorktreeSandbox(session, root);
      fs.rmSync(patchFile, { force: true });
      throw error;
    }
    dropTask(task, root);
    return {
      taskId,
      worktree: session.worktreePath,
      base: head,
      conflicts,
      evidence: localEvidence(session.worktreePath, manifest.work_id, taskId),
      patchFile,
    };
  }, LOCK_OPTIONS);
}

/** Descarta o lote ativo: remove worktrees e branches (o trabalho não integrado se perde). */
export function abortBatch(root: string): BatchManifest | null {
  return withFileLock(manifestFile(root), () => {
    const manifest = readBatch(root);
    if (!manifest) return null;
    for (const task of manifest.tasks) dropTask(task, root);
    fs.rmSync(manifestFile(root), { force: true });
    return manifest;
  }, LOCK_OPTIONS);
}
