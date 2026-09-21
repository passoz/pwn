/**
 * Tool API — Mandatory execution gateway for all agent operations.
 *
 * This is the ONLY interface through which an agent may interact with the
 * filesystem, shell, or network. Every operation is:
 *   1. Checked against the budget
 *   2. Evaluated by the Policy Engine
 *   3. Resolved and confined to the sandbox directory
 *   4. Executed only if ALLOWED
 *   5. Logged to the run context
 *
 * SECURITY GUARANTEES:
 * - Path traversal (../) is blocked by resolving and checking containment
 * - Absolute paths outside the sandbox are blocked
 * - Symlinks are resolved (realpath) and checked for containment
 * - Shell injection chars in args are detected and rejected
 * - Shell commands use spawnSync (no shell interpolation)
 * - Child processes are killed on timeout
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, SpawnSyncOptions } from 'node:child_process';
import { PolicyEngine, AgentOperation, PolicyDecision } from './policy-engine.js';
import { BudgetController, BudgetViolation } from './contract-engine.js';
import { RunContext, RunEvent } from './runner.js';
import { isBwrapSupported, wrapWithBwrap } from './sandbox.js';
// ── Result Types ───────────────────────────────────────────────────

export interface ToolResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  policyDecision?: PolicyDecision;
  budgetViolation?: BudgetViolation;
}

// ── Shell Injection Detection ──────────────────────────────────────

const SHELL_INJECTION_PATTERNS = [
  /;/,
  /&&/,
  /\|\|/,
  /\|/,
  />/,
  />>/,
  /<$/,
  /\$\(.*\)/,
  /`.*`/,
  /\$\{.*\}/,
];

function detectShellInjection(args: string[]): string | null {
  for (const arg of args) {
    for (const pattern of SHELL_INJECTION_PATTERNS) {
      if (pattern.test(arg)) {
        return arg;
      }
    }
  }
  return null;
}

// ── Path Containment ───────────────────────────────────────────────

/**
 * Resolve a relative path within the sandbox and verify it stays inside.
 * Returns the resolved absolute path or throws if the path escapes.
 *
 * Security checks:
 * 1. Resolve relative to cwd (sandbox)
 * 2. Normalize (collapses ../)
 * 3. Verify the resolved path is within the sandbox
 * 4. If the path exists and is a symlink, resolve to realpath and re-check
 */
function resolveSandboxPath(cwd: string, filePath: string): { ok: true; fullPath: string } | { ok: false; reason: string } {
  const resolved = path.resolve(cwd, filePath);
  const normalizedCwd = path.normalize(cwd);

  // Check containment: resolved path must be within cwd
  const relative = path.relative(normalizedCwd, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return {
      ok: false,
      reason: `Path escape detectado: "${filePath}" resolve para "${resolved}" que está fora do sandbox (${normalizedCwd})`,
    };
  }

  // If the file exists, check for symlink escape
  if (fs.existsSync(resolved)) {
    try {
      const real = fs.realpathSync(resolved);
      const realRelative = path.relative(normalizedCwd, real);
      if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
        return {
          ok: false,
          reason: `Symlink escape detectado: "${filePath}" resolve para "${real}" que está fora do sandbox`,
        };
      }
    } catch {
      // realpath failed — file may be a broken symlink, treat as escape
      return {
        ok: false,
        reason: `Symlink quebrado ou não resolvido: "${filePath}"`,
      };
    }
  }

  return { ok: true, fullPath: resolved };
}

// ── Tool API ───────────────────────────────────────────────────────

export class ToolAPI {
  private policy: PolicyEngine;
  private budget: BudgetController;
  private runCtx?: RunContext;
  private cwd: string;
  private isolated: boolean;

  constructor(options: {
    policy: PolicyEngine;
    budget: BudgetController;
    cwd: string;
    runCtx?: RunContext;
    isolated?: boolean;
  }) {
    this.policy = options.policy;
    this.budget = options.budget;
    this.cwd = options.cwd;
    this.runCtx = options.runCtx;
    this.isolated = options.isolated ?? true;
  }

  // ── Budget & Policy Pre-check ────────────────────────────────────

  private preCheck(): { ok: true } | { ok: false; result: ToolResult<never> } {
    const budgetViolation = this.budget.checkBudget();
    if (budgetViolation) {
      return {
        ok: false,
        result: {
          success: false,
          error: `BUDGET EXCEEDED: ${budgetViolation.message}`,
          budgetViolation,
        },
      };
    }
    return { ok: true };
  }

  private evaluateOp(op: AgentOperation): PolicyDecision {
    return this.policy.evaluate(op);
  }

  private logEvent(type: RunEvent['type'], message: string, detail?: any): void {
    if (this.runCtx) {
      this.runCtx.events.push({
        timestamp: new Date().toISOString(),
        type,
        message,
        detail,
      });
    }
  }

  /** Get the sandbox working directory. */
  getCwd(): string {
    return this.cwd;
  }

  // ── Filesystem Tools ─────────────────────────────────────────────

  writeFile(filePath: string, content: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'write_file', path: filePath };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW write_file ${filePath}` : `DENY write_file ${filePath}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    // Security: resolve and verify path containment
    const pathCheck = resolveSandboxPath(this.cwd, filePath);
    if (!pathCheck.ok) {
      this.logEvent('error', `PATH ESCAPE: ${pathCheck.reason}`);
      return {
        success: false,
        error: pathCheck.reason,
      };
    }

    const fullPath = pathCheck.fullPath;
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, content, 'utf8');
    this.budget.recordToolCall();
    this.budget.recordTokens(Math.ceil(content.length / 4));
    this.logEvent('step', `Wrote ${filePath} (${content.length} bytes)`);

    return { success: true };
  }

  readFile(filePath: string): ToolResult<string> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'read_file', path: filePath };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW read_file ${filePath}` : `DENY read_file ${filePath}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    // Security: resolve and verify path containment
    const pathCheck = resolveSandboxPath(this.cwd, filePath);
    if (!pathCheck.ok) {
      this.logEvent('error', `PATH ESCAPE: ${pathCheck.reason}`);
      return {
        success: false,
        error: pathCheck.reason,
      };
    }

    const content = fs.readFileSync(pathCheck.fullPath, 'utf8');
    this.budget.recordToolCall();
    this.logEvent('step', `Read ${filePath} (${content.length} bytes)`);

    return { success: true, data: content };
  }

  deleteFile(filePath: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'delete_file', path: filePath };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW delete_file ${filePath}` : `DENY delete_file ${filePath}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    // Security: resolve and verify path containment
    const pathCheck = resolveSandboxPath(this.cwd, filePath);
    if (!pathCheck.ok) {
      this.logEvent('error', `PATH ESCAPE: ${pathCheck.reason}`);
      return {
        success: false,
        error: pathCheck.reason,
      };
    }

    fs.unlinkSync(pathCheck.fullPath);
    this.budget.recordToolCall();
    this.logEvent('step', `Deleted ${filePath}`);

    return { success: true };
  }

  createDir(dirPath: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'create_dir', path: dirPath };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW create_dir ${dirPath}` : `DENY create_dir ${dirPath}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    // Security: resolve and verify path containment
    const pathCheck = resolveSandboxPath(this.cwd, dirPath);
    if (!pathCheck.ok) {
      this.logEvent('error', `PATH ESCAPE: ${pathCheck.reason}`);
      return {
        success: false,
        error: pathCheck.reason,
      };
    }

    fs.mkdirSync(pathCheck.fullPath, { recursive: true });
    this.budget.recordToolCall();
    this.logEvent('step', `Created dir ${dirPath}`);

    return { success: true };
  }

  /**
   * Rename or move a file within the sandbox.
   * Both source and destination must be within write_allow and within the sandbox.
   */
  renameFile(oldPath: string, newPath: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    // Evaluate both source (as read) and destination (as write)
    const destOp: AgentOperation = { type: 'write_file', path: newPath };
    const destDecision = this.evaluateOp(destOp);
    if (!destDecision.allowed) {
      this.logEvent('policy_check', `DENY rename dest ${newPath}`, destDecision);
      return {
        success: false,
        error: destDecision.reason,
        policyDecision: destDecision,
      };
    }

    // Security: resolve and verify BOTH paths
    const oldCheck = resolveSandboxPath(this.cwd, oldPath);
    if (!oldCheck.ok) {
      this.logEvent('error', `PATH ESCAPE (source): ${oldCheck.reason}`);
      return { success: false, error: oldCheck.reason };
    }

    const newCheck = resolveSandboxPath(this.cwd, newPath);
    if (!newCheck.ok) {
      this.logEvent('error', `PATH ESCAPE (destination): ${newCheck.reason}`);
      return { success: false, error: newCheck.reason };
    }

    fs.renameSync(oldCheck.fullPath, newCheck.fullPath);
    this.budget.recordToolCall();
    this.logEvent('step', `Renamed ${oldPath} → ${newPath}`);

    return { success: true };
  }

  // ── Shell Tool ───────────────────────────────────────────────────

  /**
   * Execute a shell command STRUCTURALLY (command + args).
   *
   * SECURITY:
   * - Uses spawnSync (no shell interpolation)
   * - Detects shell injection chars in args
   * - Optional timeout with child process termination
   * - The agent MUST use this method — direct child_process bypasses policy
   */
  exec(command: string, args: string[] = [], timeoutMs?: number): ToolResult<{ stdout: string; stderr: string; status: number }> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    // Security: detect shell injection attempts in args
    const injection = detectShellInjection(args);
    if (injection) {
      this.logEvent('error', `SHELL INJECTION detectado no arg: "${injection}"`);
      return {
        success: false,
        error: `Shell injection detectado: argumento contém caracteres proibidos ("${injection}"). Use args estruturais, não strings de shell.`,
      };
    }

    const op: AgentOperation = { type: 'shell_exec', command, args };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW shell_exec ${command} ${args.join(' ')}` : `DENY shell_exec ${command}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    const sanitizedEnv = { ...process.env };
    delete sanitizedEnv.PWN_VERIFIER_KEY;

    const options: SpawnSyncOptions = {
      cwd: this.cwd,
      encoding: 'utf8',
      env: sanitizedEnv,
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
    };
    let execCmd = command;
    let execArgs = args;
    if (this.isolated !== false && isBwrapSupported()) {
      const net = this.policy.networkPolicy;
      // bwrap atua no nível de namespace OS: apenas allowAllNetwork libera a interface de rede
      const allowNet = Boolean(net?.allowAllNetwork);
      const wrapped = wrapWithBwrap(command, args, this.cwd, { allowNetwork: allowNet });
      execCmd = wrapped.command;
      execArgs = wrapped.args;
    }

    const proc = spawnSync(execCmd, execArgs, options);
    // The process spawned and ran: charge the budget even if it had to be killed.
    this.budget.recordShellExecution();

    // If timed out, spawnSync reports SIGKILL (killSignal) and/or an ETIMEDOUT error.
    const timedOut = proc.signal === 'SIGKILL' || (proc.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
    if (timedOut) {
      this.logEvent('error', `Process killed by timeout (${timeoutMs}ms): ${command}`);
      return {
        success: false,
        error: `Processo morto por timeout (${timeoutMs}ms): ${command}`,
      };
    }

    this.logEvent('step', `Executed ${command} ${args.join(' ')} (exit=${proc.status})`);

    return {
      success: true,
      data: {
        stdout: proc.stdout as string || '',
        stderr: proc.stderr as string || '',
        status: proc.status ?? 1,
      },
    };
  }

  // ── Network Tools ────────────────────────────────────────────────

  httpRequest(method: string, url: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'http_request', method, url };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW http_request ${method} ${url}` : `DENY http_request ${method} ${url}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    this.budget.recordToolCall();
    this.logEvent('step', `HTTP ${method} ${url} approved by policy`);
    return { success: true };
  }

  dnsLookup(hostname: string): ToolResult<void> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

    const op: AgentOperation = { type: 'dns_lookup', hostname };
    const decision = this.evaluateOp(op);
    this.logEvent('policy_check', decision.allowed ? `ALLOW dns_lookup ${hostname}` : `DENY dns_lookup ${hostname}`, decision);

    if (!decision.allowed) {
      return {
        success: false,
        error: decision.reason,
        policyDecision: decision,
      };
    }

    this.budget.recordToolCall();
    this.logEvent('step', `DNS lookup ${hostname} approved by policy`);
    return { success: true };
  }
}
