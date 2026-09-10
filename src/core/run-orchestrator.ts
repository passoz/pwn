import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { initRunContext, finalizeRun, verifyDiff, saveRunEvents, type RunContext } from './runner.js';
import { createDefaultContractV4, type TaskContractV4, type RiskLevel } from './contract-engine.js';
import { loadTaskContract, loadWorkContracts } from './task-contract.js';
import { DEFAULT_SHELL_POLICY, PolicyEngine, type PolicyConfig } from './policy-engine.js';
import { recordMetrics } from './metrics.js';
import { enqueueReview } from './queue.js';
import { selectForRisk } from './router.js';
import { addLearning } from './learnings.js';

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

function modifiedFiles(sandboxPath: string): string[] {
  const proc = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], {
    cwd: sandboxPath,
    encoding: 'utf8',
  });
  if (proc.status !== 0) return [];
  return proc.stdout
    .split('\n')
    .map((line) => (line.length > 3 ? line.slice(3).trim() : ''))
    .map((entry) => entry.split(' -> ')[0].trim())
    .filter(Boolean);
}

/**
 * Prepara o worktree sandbox para rodar o comando de aceitação:
 * - linka node_modules do diretório principal (evita reinstalação);
 * - copia bunfig.toml quando não versionado.
 */
export function prepareSandbox(sandboxPath: string, rootDir: string): void {
  const nmSource = path.join(rootDir, 'node_modules');
  const nmTarget = path.join(sandboxPath, 'node_modules');
  if (fs.existsSync(nmSource) && !fs.existsSync(nmTarget)) {
    fs.symlinkSync(nmSource, nmTarget, 'dir');
  }

  const bunfigSource = path.join(rootDir, 'bunfig.toml');
  const bunfigTarget = path.join(sandboxPath, 'bunfig.toml');
  if (fs.existsSync(bunfigSource) && !fs.existsSync(bunfigTarget)) {
    fs.copyFileSync(bunfigSource, bunfigTarget);
  }
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
    return { status: 0, stdout: '', stderr: '', runId, diffViolations: [], suspended: true };
  }

  const shellPolicy = buildShellPolicy(contract);
  const policy = new PolicyEngine(contract, { shell: shellPolicy });

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
    ctx = initRunContext(contract, rootDir, runId, { shell: shellPolicy });
  } catch (err) {
    console.error(`[SANDBOX ABORT] ${(err as Error).message}`);
    console.error('Dica: rode com --no-isolation para executar sem sandbox (decisão explícita do operador).');
    return { status: 1, stdout: '', stderr: (err as Error).message, runId, diffViolations: [], suspended: false };
  }

  prepareSandbox(ctx.sandbox!.worktreePath, rootDir);

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

    // F2.3: Diff Guard sobre os arquivos modificados dentro do sandbox.
    const report = verifyDiff(ctx, modifiedFiles(ctx.sandbox!.worktreePath));
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
  } else {
    stderr = execResult.error ?? 'Execução negada pela política ou orçamento.';
  }

  finalizeRun(ctx, success);
  saveRunEvents(ctx, path.join(rootDir, '.piwerness'));
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
  }, rootDir);

  return { status, stdout, stderr, runId, diffViolations, suspended: false };
}
