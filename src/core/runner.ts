import path from 'node:path';
import fs from 'node:fs';
import { TaskContractV4, BudgetController } from './contract-engine.js';
import { PolicyEngine, PolicyConfig } from './policy-engine.js';
import { SandboxSession, SandboxError, createGitWorktreeSandbox, cleanupGitWorktreeSandbox } from './sandbox.js';
import { checkDiffAgainstContract, ContractDiffCheckReport } from './contract-guard.js';
import { ToolAPI } from './tool-api.js';

// ── Types ──────────────────────────────────────────────────────────

export type RunStatus = 'pending' | 'running' | 'success' | 'budget_exceeded' | 'policy_violation' | 'sandbox_error' | 'diff_violation' | 'aborted';

export interface RunEvent {
  timestamp: string;
  type: 'start' | 'step' | 'budget_check' | 'policy_check' | 'diff_check' | 'error' | 'end';
  message: string;
  detail?: any;
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
  /** Mandatory Tool API — the ONLY gateway for agent operations. */
  tools: ToolAPI;
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
 * Initialize a full run context: contract → policy → sandbox → budget → tools.
 *
 * This is the entry point for contract-governed execution.
 * Throws SandboxError if the sandbox cannot be created (no fallback to rootDir).
 *
 * The returned RunContext contains `tools` — a ToolAPI instance that is the
 * ONLY authorized gateway for the agent to interact with filesystem, shell,
 * or network. Any operation bypassing `tools` violates the harness contract.
 */
export function initRunContext(
  contract: TaskContractV4,
  rootDir: string,
  runId: string,
  policyOverrides?: Partial<PolicyConfig>,
): RunContext {
  const budget = new BudgetController(contract);
  const policy = new PolicyEngine(contract, policyOverrides);

  const ctx: RunContext = {
    contract,
    rootDir,
    runId,
    budget,
    policy,
    events: [],
    status: 'pending',
    tools: null as unknown as ToolAPI, // will be set after sandbox creation
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

  // 2. Bind the mandatory Tool API to the sandbox directory
  const cwd = ctx.sandbox?.worktreePath ?? ctx.rootDir;
  ctx.tools = new ToolAPI({
    policy: ctx.policy,
    budget: ctx.budget,
    cwd,
    runCtx: ctx,
  });
  emitEvent(ctx, 'step', `Tool API vinculada ao sandbox: ${cwd}`);

  ctx.status = 'running';
  return ctx;
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
