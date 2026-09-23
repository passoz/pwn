import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { initRunContext, finalizeRun, verifyDiff, saveRunEvents, type RunContext } from './runner.js';
import { createDefaultContractV4, type TaskContractV4, type RiskLevel } from './contract-engine.js';
import { loadTaskContract, loadWorkContracts } from './task-contract.js';
import { DEFAULT_SHELL_POLICY, PolicyEngine, type PolicyConfig } from './policy-engine.js';
import { resolvePolicy } from './policy-config.js';
import { recordMetrics } from './metrics.js';
import { enqueueReview } from './queue.js';
import { selectForRisk } from './router.js';
import { addLearning } from './learnings.js';
import { invalidScopePattern } from './contract-guard.js';
import { resolveGitDir } from './sandbox.js';

export interface OrchestratedOptions {
  workId: string;
  taskId?: string;
  command: string[];
  timeoutSeconds: number;
  rootDir?: string;
  isolated?: boolean;
}

export interface OrchestratedResult {
  status: number;
  stdout: string;
  stderr: string;
  runId: string;
  diffViolations: string[];
  suspended: boolean;
}

/**
 * Exit code for a run suspended for human review (L4) instead of executed.
 * Distinct from 0 so unattended automation cannot mistake "never ran" for success.
 */
export const EXIT_SUSPENDED = 3;

const RISK_ORDER: RiskLevel[] = ['L0', 'L1', 'L2', 'L3', 'L4'];

function maxRisk(contracts: TaskContractV4[]): RiskLevel {
  return contracts.reduce<RiskLevel>(
    (highest, contract) => (RISK_ORDER.indexOf(contract.risk.level) > RISK_ORDER.indexOf(highest) ? contract.risk.level : highest),
    'L0',
  );
}

function aggregateContracts(workId: string, taskId: string, contracts: TaskContractV4[]): TaskContractV4 {
  const base = createDefaultContractV4(taskId, workId, `Work ${workId} — execução agregada`, maxRisk(contracts));
  base.scope_contract.write_allow = [...new Set(contracts.flatMap((c) => c.scope_contract.write_allow))];
  base.scope_contract.write_deny = [...new Set(contracts.flatMap((c) => c.scope_contract.write_deny))];
  base.acceptance_contract.commands = [...new Set(contracts.flatMap((c) => c.acceptance_contract.commands))];
  return base;
}

function buildShellPolicy(contract: TaskContractV4): PolicyConfig['shell'] {
  const allowedCommands = contract.acceptance_contract.commands
    .map((raw) => raw.trim().split(/\s+/))
    .filter((parts) => parts.length > 0 && parts[0])
    .map(([command, ...args]) => ({ command, args }));
  return {
    allowedCommands,
    deniedCommands: [...DEFAULT_SHELL_POLICY.deniedCommands],
    allowAllShell: false,
  };
}

/**
 * Overrides de política da run (shell/rede).
 *
 * Sem `.pwn/policy.json` (`source: 'defaults'`) o comportamento histórico é
 * PRESERVADO: allowlist derivada dos comandos de aceitação do contrato e denylist
 * padrão do PolicyEngine. Com arquivo válido, a política declarada o substitui.
 */
function buildPolicyOverrides(contract: TaskContractV4, rootDir: string): Partial<PolicyConfig> {
  const resolved = resolvePolicy(rootDir);
  if (resolved.source === 'file') return { shell: resolved.shell, network: resolved.network };
  return { shell: buildShellPolicy(contract) };
}

/** Resultado do inventário de mudanças: falha de detecção nunca é confundida com "sem mudanças". */
export type ModifiedFilesResult = { ok: true; files: string[] } | { ok: false; reason: string };

/** Artefatos criados pelo harness no sandbox: caminho relativo → assinatura em `prepareSandbox`. */
export type HarnessArtifacts = Record<string, string>;

/**
 * Inventaria as mudanças dentro do sandbox.
 *
 * `expectedGitDir` é o `git rev-parse --absolute-git-dir` registrado na criação do
 * sandbox. Sem essa âncora, apagar o arquivo `.git` do worktree faz o Git subir a
 * árvore e resolver o repositório-**pai**: o `git status` então "funciona" e descreve
 * outro repositório — tipicamente vazio, porque `.pwn/` costuma estar no
 * `.gitignore` — enquanto a escrita fora de escopo fica invisível. Um `git init`
 * dentro do sandbox produz o mesmo efeito por outro caminho.
 *
 * `injected` são os artefatos que o próprio harness criou (`prepareSandbox`), com a
 * assinatura de cada um. Um caminho só é desconsiderado enquanto a assinatura
 * continuar batendo: se o comando substituir o artefato, ele volta ao inventário.
 */
export function modifiedFiles(
  sandboxPath: string,
  expectedGitDir: string,
  injected: HarnessArtifacts = {},
): ModifiedFilesResult {
  const gitDir = resolveGitDir(sandboxPath);
  if (!gitDir) {
    return { ok: false, reason: `worktree ${sandboxPath} não resolve para um repositório Git` };
  }
  if (path.resolve(gitDir) !== path.resolve(expectedGitDir)) {
    return {
      ok: false,
      reason: `worktree ${sandboxPath} aponta para ${gitDir}, não para o repositório do sandbox (${expectedGitDir}) — árvore substituída durante a execução`,
    };
  }

  // `-z` desativa o C-quoting do Git: um nome de arquivo pode conter `"`, ` -> ` ou
  // espaços, e interpretar a saída texto livre deixaria a escrita real sem auditoria.
  const proc = spawnSync('git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'], {
    cwd: sandboxPath,
    encoding: 'utf8',
  });
  // Fail-closed: um `git status` que falha (worktree corrompido, índice travado, git
  // ausente) significa que NÃO sabemos o que foi escrito. Devolver uma lista vazia
  // faria o diff guard aprovar um run que ninguém inspecionou.
  if (proc.status !== 0) {
    const detail = (proc.stderr || proc.error?.message || '').trim().split('\n')[0] || `git status exited with code ${proc.status}`;
    return { ok: false, reason: `inventário de mudanças indisponível em ${sandboxPath}: ${detail}` };
  }

  const isHarnessArtifact = (filePath: string): boolean =>
    Object.hasOwn(injected, filePath) && injected[filePath] === pathFingerprint(path.join(sandboxPath, filePath));

  const tokens = (proc.stdout ?? '').split('\0');
  const files: string[] = [];
  const record = (filePath: string): void => {
    if (filePath.length > 0 && !isHarnessArtifact(filePath)) files.push(filePath);
  };

  for (let i = 0; i < tokens.length; i++) {
    const entry = tokens[i];
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    // Renomeações/cópias trazem o caminho de origem no token seguinte: mover um
    // arquivo para fora do escopo também é escrita fora do escopo, e omitir a
    // origem esconderia a remoção.
    if (status[0] === 'R' || status[0] === 'C') {
      record(entry.slice(3));
      i++;
      record(tokens[i] ?? '');
      continue;
    }
    record(entry.slice(3));
  }

  // Ponto cego do `git status`: ele não reporta um caminho ignorado nem a remoção de
  // uma entrada que nunca foi rastreada — apagar ou trocar um artefato do harness
  // some do relatório. Reconferir a assinatura de cada um fecha esse buraco.
  for (const [filePath, signature] of Object.entries(injected)) {
    if (signature !== pathFingerprint(path.join(sandboxPath, filePath)) && !files.includes(filePath)) {
      files.push(filePath);
    }
  }

  return { ok: true, files };
}

/**
 * Assinatura do que existe no caminho: tipo do inode e, para link simbólico, o alvo;
 * para arquivo, tamanho + hash do conteúdo. Filtrar artefatos do harness **por nome**
 * dá passe livre permanente: o comando pode apagar o link criado pelo harness, pôr um
 * arquivo no lugar e continuar invisível. Comparar a assinatura faz a substituição
 * aparecer como mudança real.
 */
function pathFingerprint(target: string): string {
  try {
    const stats = fs.lstatSync(target);
    if (stats.isSymbolicLink()) return `link:${fs.readlinkSync(target)}`;
    if (stats.isDirectory()) return 'dir';
    if (stats.isFile()) {
      const digest = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex').slice(0, 16);
      return `file:${stats.size}:${digest}`;
    }
    return 'other';
  } catch {
    return 'absent';
  }
}

/**
 * Preparado o worktree sandbox para rodar o comando de aceitação:
 * - linka node_modules do diretório principal (evita reinstalação);
 * - copia bunfig.toml quando não versionado.
 *
 * Devolve a assinatura de **cada** caminho que o harness criou, para que o diff
 * guard desconsidere esses artefatos e somente eles.
 */
export function prepareSandbox(sandboxPath: string, rootDir: string): HarnessArtifacts {
  const injected: HarnessArtifacts = {};

  const nmSource = path.join(rootDir, 'node_modules');
  const nmTarget = path.join(sandboxPath, 'node_modules');
  if (fs.existsSync(nmSource) && !fs.existsSync(nmTarget)) {
    fs.symlinkSync(nmSource, nmTarget, 'dir');
    injected.node_modules = pathFingerprint(nmTarget);
  }

  const bunfigSource = path.join(rootDir, 'bunfig.toml');
  const bunfigTarget = path.join(sandboxPath, 'bunfig.toml');
  if (fs.existsSync(bunfigSource) && !fs.existsSync(bunfigTarget)) {
    fs.copyFileSync(bunfigSource, bunfigTarget);
    injected['bunfig.toml'] = pathFingerprint(bunfigTarget);
  }

  return injected;
}

function failedMetrics(runId: string, options: OrchestratedOptions, startedAt: number, rootDir: string, agentRole: 'cheap' | 'strong' | 'review' | 'plan'): void {
  recordMetrics({
    timestamp: new Date().toISOString(),
    runId,
    workId: options.workId,
    taskId: options.taskId ?? 'WORK',
    agentRole,
    model: 'bun',
    tokensInput: 0,
    tokensOutput: 0,
    costUSD: 0,
    durationMs: Date.now() - startedAt,
    status: 'failed',
    attempts: 1,
    isolated: options.isolated !== false,
  }, rootDir);
}

/**
 * Run a command under contract enforcement:
 *   contract (V4) → policy → sandbox → budget → diff guard → cleanup → metrics.
 *
 * `isolated` (default true) creates a Git worktree sandbox; `false` runs in the
 * main tree with policy still enforced but without sandbox isolation or diff-guard rollback.
 */
export function runOrchestrated(options: OrchestratedOptions): OrchestratedResult {
  const rootDir = options.rootDir ?? process.cwd();
  const runId = `RUN-${Date.now().toString(36)}`;
  const startedAt = Date.now();

  const contracts = (() => {
    try {
      return options.taskId
        ? [loadTaskContract(options.workId, options.taskId, rootDir)]
        : loadWorkContracts(options.workId, rootDir);
    } catch (err) {
      return { error: (err as Error).message };
    }
  })();
  if ('error' in contracts) {
    return { status: 1, stdout: '', stderr: `[CONTRACT ERROR] ${contracts.error}`, runId, diffViolations: [], suspended: false };
  }
  const contract = aggregateContracts(options.workId, options.taskId ?? 'WORK', contracts);
  const invalidPattern = invalidScopePattern(contract.scope_contract.write_allow, contract.scope_contract.write_deny);
  if (invalidPattern) {
    return {
      status: 1,
      stdout: '',
      stderr: `[CONTRACT ERROR] padrão de escopo inválido em write_allow/write_deny: ${JSON.stringify(invalidPattern)}`,
      runId,
      diffViolations: [],
      suspended: false,
    };
  }
  const agentRole = selectForRisk(contract.risk.level).role;

  // F2.5: L4 suspende e enfileira na revisão humana, sem executar.
  if (contract.risk.level === 'L4') {
    enqueueReview({
      runId,
      workId: options.workId,
      taskId: options.taskId ?? 'WORK',
      title: contract.title,
      pausedAtStep: 'pre-execution',
      reason: 'Tarefa de risco L4 exige aprovação humana na fila AFK',
      riskLevel: 'L4',
    }, rootDir);
    console.error(`⏸  Tarefa L4 suspensa e enviada para a fila de revisão (${runId}).`);
    console.error(`   Aprove com 'pwn queue approve ${runId}' para destravar a execução (exit code ${EXIT_SUSPENDED}).`);
    return { status: EXIT_SUSPENDED, stdout: '', stderr: '', runId, diffViolations: [], suspended: true };
  }

  const policyOverrides = buildPolicyOverrides(contract, rootDir);
  const policy = new PolicyEngine(contract, policyOverrides);

  // F2.4 (não isolado): política ainda é aplicada, sem sandbox/diff guard.
  if (options.isolated === false) {
    const decision = policy.evaluate({ type: 'shell_exec', command: options.command[0], args: options.command.slice(1) });
    if (!decision.allowed) {
      failedMetrics(runId, options, startedAt, rootDir, agentRole);
      return { status: 1, stdout: '', stderr: decision.reason, runId, diffViolations: [], suspended: false };
    }
    const proc = spawnSync(options.command[0], options.command.slice(1), {
      cwd: rootDir,
      encoding: 'utf8',
      timeout: options.timeoutSeconds * 1000,
    });
    recordMetrics({
      timestamp: new Date().toISOString(),
      runId,
      workId: options.workId,
      taskId: options.taskId ?? 'WORK',
      agentRole,
      model: 'bun',
      tokensInput: 0,
      tokensOutput: 0,
      costUSD: 0,
      durationMs: Date.now() - startedAt,
      status: (proc.status ?? 1) === 0 ? 'success' : 'failed',
      attempts: 1,
      isolated: false,
    }, rootDir);
    return {
      status: proc.status ?? 1,
      stdout: proc.stdout ?? '',
      stderr: proc.stderr ?? '',
      runId,
      diffViolations: [],
      suspended: false,
    };
  }

  // F2.1/F2.4: execução mediada pela Tool API dentro do sandbox.
  let ctx: RunContext;
  try {
    ctx = initRunContext(contract, rootDir, runId, policyOverrides);
  } catch (err) {
    console.error(`[SANDBOX ABORT] ${(err as Error).message}`);
    console.error('Dica: rode com --no-isolation para executar sem sandbox (decisão explícita do operador).');
    return { status: 1, stdout: '', stderr: (err as Error).message, runId, diffViolations: [], suspended: false };
  }

  const harnessInjected = prepareSandbox(ctx.sandbox!.worktreePath, rootDir);

  const execResult = ctx.tools.exec(options.command[0], options.command.slice(1), options.timeoutSeconds * 1000);

  let stdout = '';
  let stderr = '';
  let status = 1;
  let diffViolations: string[] = [];
  let success = false;

  if (execResult.success) {
    stdout = execResult.data?.stdout ?? '';
    stderr = execResult.data?.stderr ?? '';
    status = execResult.data?.status ?? 1;
    success = status === 0;
  } else {
    stderr = execResult.error ?? 'Execução negada pela política ou orçamento.';
  }

  // F2.3: Diff Guard sobre os arquivos modificados dentro do sandbox.
  // Roda SEMPRE — inclusive quando o comando falhou, foi negado pela política ou
  // estourou o timeout: nesses casos o processo já escreveu o que escreveu antes de
  // morrer, e ignorar a árvore transformaria o guard em no-op para quem falha de propósito.
  const inventory = modifiedFiles(ctx.sandbox!.worktreePath, ctx.sandbox!.gitDir, harnessInjected);
  if (!inventory.ok) {
    diffViolations = [inventory.reason];
    status = 1;
    success = false;
    addLearning({
      category: 'gotcha',
      title: 'Diff guard não conseguiu inventariar a árvore do sandbox',
      description: `Run ${runId}: ${inventory.reason}`,
      sourceTaskId: options.taskId,
      tags: ['diff-guard', 'scope'],
    }, rootDir);
  } else {
    const report = verifyDiff(ctx, inventory.files);
    if (!report.passed) {
      diffViolations = report.violations.map((v) => `${v.file}: ${v.reason ?? v.violationType}`);
      status = 1;
      success = false;
      addLearning({
        category: 'gotcha',
        title: 'Violação de escopo detectada pelo diff guard',
        description: `Run ${runId} modificou arquivos fora do write_allow do contrato: ${diffViolations.join('; ')}`,
        sourceTaskId: options.taskId,
        tags: ['diff-guard', 'scope'],
      }, rootDir);
    }
  }

  finalizeRun(ctx, success);
  saveRunEvents(ctx, path.join(rootDir, '.pwn'));
  recordMetrics({
    timestamp: new Date().toISOString(),
    runId,
    workId: options.workId,
    taskId: options.taskId ?? 'WORK',
    agentRole,
    model: 'bun',
    tokensInput: 0,
    tokensOutput: 0,
    costUSD: 0,
    durationMs: Date.now() - startedAt,
    status: success ? 'success' : 'failed',
    attempts: 1,
    isolated: true,
  }, rootDir);

  return { status, stdout, stderr, runId, diffViolations, suspended: false };
}
