/**
 * Tool API — Mandatory execution gateway for all agent operations.
 *
 * This is the ONLY interface through which an agent may interact with the
 * filesystem, shell, or network. Every operation is:
 *   1. Checked against the budget
 *   2. Evaluated by the Policy Engine
 *   3. Executed only if ALLOWED
 *   4. Logged to the run context
 *
 * Bypassing the Tool API (e.g. spawning a subprocess that writes files
 * directly) violates the harness contract and will be caught by the
 * Diff Guard, but the goal is PREVENTION, not just detection.
 *
 * DESIGN: The agent runner should inject this Tool API as the sole
 * available interface for filesystem/shell/network operations.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, SpawnSyncOptions } from 'node:child_process';
import { PolicyEngine, AgentOperation, PolicyDecision } from './policy-engine.js';
import { BudgetController, BudgetViolation } from './contract-engine.js';
import { RunContext, RunEvent } from './runner.js';

// ── Result Types ───────────────────────────────────────────────────

export interface ToolResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  policyDecision?: PolicyDecision;
  budgetViolation?: BudgetViolation;
}

// ── Tool API ───────────────────────────────────────────────────────

export class ToolAPI {
  private policy: PolicyEngine;
  private budget: BudgetController;
  private runCtx?: RunContext;
  private cwd: string;

  constructor(options: {
    policy: PolicyEngine;
    budget: BudgetController;
    cwd: string;
    runCtx?: RunContext;
  }) {
    this.policy = options.policy;
    this.budget = options.budget;
    this.cwd = options.cwd;
    this.runCtx = options.runCtx;
  }

  // ── Budget & Policy Pre-check ────────────────────────────────────

  private preCheck(): { ok: true } | { ok: false; result: ToolResult<never> } {
    // 1. Budget check
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

    const fullPath = path.resolve(this.cwd, filePath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, content, 'utf8');
    this.budget.recordToolCall();
    this.budget.recordTokens(Math.ceil(content.length / 4)); // rough token estimate
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

    const fullPath = path.resolve(this.cwd, filePath);
    const content = fs.readFileSync(fullPath, 'utf8');
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

    const fullPath = path.resolve(this.cwd, filePath);
    fs.unlinkSync(fullPath);
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

    const fullPath = path.resolve(this.cwd, dirPath);
    fs.mkdirSync(fullPath, { recursive: true });
    this.budget.recordToolCall();
    this.logEvent('step', `Created dir ${dirPath}`);

    return { success: true };
  }

  // ── Shell Tool ───────────────────────────────────────────────────

  /**
   * Execute a shell command STRUCTURALLY (command + args).
   *
   * IMPORTANT: The agent MUST use this method. Spawning a shell process
   * directly (e.g. via child_process) bypasses the Policy Engine and
   * violates the harness contract.
   */
  exec(command: string, args: string[] = []): ToolResult<{ stdout: string; stderr: string; status: number }> {
    const pre = this.preCheck();
    if (!pre.ok) return pre.result;

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

    const options: SpawnSyncOptions = {
      cwd: this.cwd,
      encoding: 'utf8',
      env: { ...process.env },
    };

    const proc = spawnSync(command, args, options);
    this.budget.recordShellExecution();
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

    // Network execution is NOT implemented here — the agent framework
    // should use this as the gateway. Returning success means the
    // operation is POLICY-APPROVED; the actual HTTP call happens
    // through the agent's HTTP client, which should check the same policy.
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
