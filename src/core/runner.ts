import { spawnSync, SpawnSyncOptions } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { TaskContractV4, BudgetController, BudgetViolation } from './contract-engine.js';
import { PolicyEngine, AgentOperation, PolicyDecision } from './policy-engine.js';
import { SandboxSession, SandboxError, createGitWorktreeSandbox, cleanupGitWorktreeSandbox } from './sandbox.js';
import { checkDiffAgainstContract, ContractDiffCheckReport } from './contract-guard.js';

// ── Types ──────────────────────────────────────────────────────────

export type RunStatus = 'pending' | 'running' | 'success' | 'budget_exceeded' | 'policy_violation' | 'sandbox_error' | 'diff_violation' | 'aborted';

export interface RunEvent {
  timestamp: string;
  type: 'start' | 'step' | 'budget_check' | 'policy_check' | 'diff_check' | 'error' | 'end';
  message: string;
  detail?: any;
}

export interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

export interface RunContext {
  contract: TaskContractV4;
  rootDir: string;
  runId: string;
  sandbox?: SandboxSession;
  budget: BudgetController;
  policy: PolicyEngine;
  events: RunEvent[];
  status: RunStatus;
}

// ── Legacy: pack script runner ─────────────────────────────────────

export function runPackScript(scriptName: string, args: string[] = [], cwd: string = process.cwd()): RunResult {
  const packScriptPath = path.resolve(cwd, 'packs/software-engineering/scripts', scriptName);

  if (!fs.existsSync(packScriptPath)) {
    return {
      status: 1,
      stdout: '',
      stderr: `Script not found in pack: ${packScriptPath}`,
    };
  }

  const options: SpawnSyncOptions = {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
    },
  };

  const proc = spawnSync('node', [packScriptPath, ...args], options);

  return {
    status: proc.status ?? 1,
    stdout: proc.stdout as string || '',
    stderr: proc.stderr as string || '',
  };
}

// ── Runtime: contract-governed execution ────────────────────────────

function emitEvent(ctx: RunContext, type: RunEvent['type'], message: string, detail?: any): void {
  ctx.events.push({
    timestamp: new Date().toISOString(),
    type,
    message,
    detail,
  });
}

/**
 * Initialize a full run context: contract → policy → sandbox → budget.
 *
 * This is the entry point for contract-governed execution.
 * Throws SandboxError if the sandbox cannot be created (no fallback to rootDir).
 */
export function initRunContext(
  contract: TaskContractV4,
  rootDir: string,
  runId: string,
): RunContext {
  const budget = new BudgetController(contract);
  const policy = new PolicyEngine(contract);

  const ctx: RunContext = {
    contract,
    rootDir,
    runId,
    budget,
    policy,
    events: [],
    status: 'pending',
  };

  emitEvent(ctx, 'start', `Run ${runId} inicializado para task ${contract.task_id} (risk: ${contract.risk.level})`);

  // 1. Create sandbox — ABORT on failure, never fallback to rootDir
  try {
    const sandbox = createGitWorktreeSandbox(runId, rootDir);
    ctx.sandbox = sandbox;
    emitEvent(ctx, 'step', `Sandbox criado: ${sandbox.worktreePath} (branch: ${sandbox.branchName})`);
  } catch (err) {
    if (err instanceof SandboxError) {
      ctx.status = 'sandbox_error';
      emitEvent(ctx, 'error', err.message, { reason: err.reason });
      throw err;
    }
    throw err;
  }

  ctx.status = 'running';
  return ctx;
}

/**
 * Evaluate a proposed operation against the policy engine.
 * Returns the decision without executing anything.
 */
export function evaluateOperation(ctx: RunContext, operation: AgentOperation): PolicyDecision {
  const decision = ctx.policy.evaluate(operation);
  emitEvent(ctx, 'policy_check',
    decision.allowed
      ? `ALLOW: ${operation.type}`
      : `DENY: ${operation.type} — ${decision.reason}`,
    decision,
  );
  return decision;
}

/**
 * Check budget limits. Returns null if OK, or the violation.
 */
export function checkBudget(ctx: RunContext): BudgetViolation | null {
  const violation = ctx.budget.checkBudget();
  if (violation) {
    ctx.status = 'budget_exceeded';
    emitEvent(ctx, 'budget_check', `BUDGET EXCEEDED: ${violation.message}`, violation);
  }
  return violation;
}

/**
 * Run a shell command inside the sandbox.
 * Checks budget before execution, records attempt after.
 */
export function runInSandbox(ctx: RunContext, command: string, args: string[] = []): RunResult {
  // Pre-check budget
  const budgetViolation = checkBudget(ctx);
  if (budgetViolation) {
    return {
      status: 1,
      stdout: '',
      stderr: `BUDGET EXCEEDED: ${budgetViolation.message}`,
    };
  }

  // Pre-check policy
  const policyDecision = evaluateOperation(ctx, {
    type: 'shell_exec',
    command,
    args,
  });
  if (!policyDecision.allowed) {
    return {
      status: 1,
      stdout: '',
      stderr: `POLICY VIOLATION: ${policyDecision.reason}`,
    };
  }

  const cwd = ctx.sandbox?.worktreePath ?? ctx.rootDir;
  const options: SpawnSyncOptions = {
    cwd,
    encoding: 'utf8',
    env: { ...process.env },
  };

  const proc = spawnSync(command, args, options);
  ctx.budget.recordAttempt();

  return {
    status: proc.status ?? 1,
    stdout: proc.stdout as string || '',
    stderr: proc.stderr as string || '',
  };
}

/**
 * Verify diff against the contract scope after agent execution.
 */
export function verifyDiff(ctx: RunContext, modifiedFiles: string[]): ContractDiffCheckReport {
  const report = checkDiffAgainstContract(
    modifiedFiles,
    ctx.contract.scope_contract.write_allow,
    ctx.contract.scope_contract.write_deny,
  );

  if (!report.passed) {
    ctx.status = 'diff_violation';
    emitEvent(ctx, 'diff_check',
      `DIFF VIOLATION: ${report.violations.length} arquivo(s) fora do escopo`,
      report,
    );
  } else {
    emitEvent(ctx, 'diff_check', `DIFF OK: ${report.totalFiles} arquivo(s) verificado(s)`);
  }

  return report;
}

/**
 * Finalize a run: cleanup sandbox, emit end event.
 */
export function finalizeRun(ctx: RunContext, success: boolean): RunContext {
  ctx.status = success ? 'success' : 'aborted';
  emitEvent(ctx, 'end', `Run ${ctx.runId} finalizado: ${ctx.status}`);

  if (ctx.sandbox) {
    cleanupGitWorktreeSandbox(ctx.sandbox, ctx.rootDir);
    emitEvent(ctx, 'step', `Sandbox removido: ${ctx.sandbox.worktreePath}`);
  }

  return ctx;
}

/**
 * Save run events to a JSONL file for telemetry.
 */
export function saveRunEvents(ctx: RunContext, metricsDir: string): void {
  const dir = path.resolve(metricsDir);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const filePath = path.join(dir, `${ctx.runId}.jsonl`);
  const lines = ctx.events.map(e => JSON.stringify(e)).join('\n');
  fs.writeFileSync(filePath, lines, 'utf8');
}
