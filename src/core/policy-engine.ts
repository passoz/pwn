/**
 * Policy Engine — Preventive interception layer between agent and execution surface.
 *
 * Sits between the Contract and the agent runtime, producing concrete ALLOW/DENY
 * decisions for filesystem, shell, and network operations BEFORE they execute.
 *
 * This is the key architectural piece recommended by the technical audit:
 *   Contract → Policy Engine → ALLOW/DENY → filesystem / shell / network
 *
 * DESIGN PRINCIPLE: FAIL-CLOSED
 * - Allowlists empty → DENY ALL (must be explicitly configured)
 * - Unknown operations → DENY by default
 * - To permit everything deliberately, use allowAllShell / allowAllNetwork flags
 */

import { checkFileAgainstScope, FileDiffCheckResult } from './contract-guard.js';
import { TaskContractV4 } from './contract-engine.js';

// ── Operation Types ────────────────────────────────────────────────

export type OperationDomain = 'filesystem' | 'shell' | 'network';

export type FileSystemOperation =
  | { type: 'read_file'; path: string }
  | { type: 'write_file'; path: string }
  | { type: 'delete_file'; path: string }
  | { type: 'create_dir'; path: string };

/**
 * ShellOperation with STRUCTURAL matching.
 * The command is the binary/executable, args are positional parameters.
 * No shell string parsing — prevents bypass via &&, ;, |, >, $(...)
 */
export type ShellOperation =
  | { type: 'shell_exec'; command: string; args?: string[] };

export type NetworkOperation =
  | { type: 'http_request'; method: string; url: string }
  | { type: 'dns_lookup'; hostname: string };

export type AgentOperation = FileSystemOperation | ShellOperation | NetworkOperation;

// ── Decision ───────────────────────────────────────────────────────

export type PolicyDecision = {
  allowed: true;
  domain: OperationDomain;
  operation: AgentOperation;
} | {
  allowed: false;
  domain: OperationDomain;
  operation: AgentOperation;
  reason: string;
  violationType: 'write_deny' | 'not_in_write_allow' | 'shell_denied' | 'network_denied' | 'denied_by_policy';
  contractRef?: string;
};

// ── Policy Rules ───────────────────────────────────────────────────

/**
 * Structural command rule: matches { command, args }.
 *
 * Rules are evaluated in order:
 * 1. Exact command match (command === rule.command)
 * 2. Arg prefix match (args start with rule.args)
 *
 * Example: { command: 'git', args: ['status'] } matches 'git status'
 *          { command: 'git', args: [] } matches any git command
 */
export interface CommandRule {
  command: string;
  args?: string[];  // if undefined/empty, matches any args for this command
}

export interface ShellPolicy {
  /** Allowed commands (structural). Empty → DENY ALL unless allowAllShell is true. */
  allowedCommands: CommandRule[];
  /** Blocked commands (structural). Deny always wins. */
  deniedCommands: CommandRule[];
  /** Explicitly allow ALL shell commands (use with caution). Overrides empty allowlist. */
  allowAllShell?: boolean;
}

export interface NetworkPolicy {
  /** Allowed URL prefixes / domains. Empty → DENY ALL unless allowAllNetwork is true. */
  allowedDomains: string[];
  /** Blocked URL prefixes / domains (deny overrides allow). */
  deniedDomains: string[];
  /** Explicitly allow ALL network access (use with caution). Overrides empty allowlist. */
  allowAllNetwork?: boolean;
}

export interface PolicyConfig {
  filesystem: {
    writeAllow: string[];
    writeDeny: string[];
  };
  shell: ShellPolicy;
  network: NetworkPolicy;
}

// ── Defaults ───────────────────────────────────────────────────────

export const DEFAULT_SHELL_POLICY: ShellPolicy = {
  allowedCommands: [],
  deniedCommands: [
    { command: 'rm', args: ['-rf', '/'] },
    { command: 'mkfs' },
    { command: 'dd' },
    { command: ':' },
  ],
  allowAllShell: false,
};

export const DEFAULT_NETWORK_POLICY: NetworkPolicy = {
  allowedDomains: [],
  deniedDomains: [],
  allowAllNetwork: false,
};

// ── Policy Engine ──────────────────────────────────────────────────

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(contract: TaskContractV4, overrides?: Partial<PolicyConfig>) {
    this.config = {
      filesystem: {
        writeAllow: contract.scope_contract.write_allow,
        writeDeny: contract.scope_contract.write_deny,
      },
      shell: overrides?.shell ?? { ...DEFAULT_SHELL_POLICY },
      network: overrides?.network ?? { ...DEFAULT_NETWORK_POLICY },
    };
  }
  get networkPolicy(): Readonly<NetworkPolicy> {
    return this.config.network;
  }

  get policyConfig(): Readonly<PolicyConfig> {
    return this.config;
  }

  /**
   * Evaluate a proposed operation against the policy.
   */
  evaluate(operation: AgentOperation): PolicyDecision {
    switch (operation.type) {
      case 'read_file':
        return this.evaluateFileRead(operation);
      case 'write_file':
        return this.evaluateFileWrite(operation);
      case 'delete_file':
        return this.evaluateFileDelete(operation);
      case 'create_dir':
        return this.evaluateDirCreate(operation);
      case 'shell_exec':
        return this.evaluateShell(operation);
      case 'http_request':
      case 'dns_lookup':
        return this.evaluateNetwork(operation);
      default:
        return {
          allowed: false,
          domain: 'filesystem',
          operation,
          reason: 'Operação desconhecida — bloqueada por padrão',
          violationType: 'denied_by_policy',
        };
    }
  }

  /**
   * Batch-evaluate multiple operations. Returns the first denial or all-allowed.
   */
  evaluateAll(operations: AgentOperation[]): { allAllowed: boolean; denials: PolicyDecision[] } {
    const denials: PolicyDecision[] = [];
    for (const op of operations) {
      const decision = this.evaluate(op);
      if (!decision.allowed) {
        denials.push(decision);
      }
    }
    return { allAllowed: denials.length === 0, denials };
  }

  /** Direct access for testing / external integration. */
  getConfig(): Readonly<PolicyConfig> {
    return this.config;
  }

  // ── Private evaluators ───────────────────────────────────────────

  private evaluateFileRead(op: FileSystemOperation): PolicyDecision {
    // Reads are generally allowed — only write operations are restricted.
    return { allowed: true, domain: 'filesystem', operation: op };
  }

  private evaluateFileWrite(op: FileSystemOperation): PolicyDecision {
    const result: FileDiffCheckResult = checkFileAgainstScope(
      op.path,
      this.config.filesystem.writeAllow,
      this.config.filesystem.writeDeny,
    );

    if (result.allowed) {
      return { allowed: true, domain: 'filesystem', operation: op };
    }

    return {
      allowed: false,
      domain: 'filesystem',
      operation: op,
      reason: result.reason ?? `Escrita bloqueada: ${result.file}`,
      violationType: result.violationType === 'write_deny' ? 'write_deny' : 'not_in_write_allow',
    };
  }

  private evaluateFileDelete(op: FileSystemOperation): PolicyDecision {
    // Deletions are treated as writes — same scope check.
    return this.evaluateFileWrite(op);
  }

  private evaluateDirCreate(op: FileSystemOperation): PolicyDecision {
    // Directory creation uses the same scope check.
    return this.evaluateFileWrite(op);
  }

  /**
   * Structural shell matching: command + args, not string prefix.
   *
   * FAIL-CLOSED: empty allowedCommands → DENY ALL unless allowAllShell is true.
   */
  private evaluateShell(op: ShellOperation): PolicyDecision {
    const cmd = op.command;
    const args = op.args ?? [];

    // 1. Deny check first (deny always wins)
    for (const denied of this.config.shell.deniedCommands) {
      if (this.matchesCommandRule(cmd, args, denied)) {
        return {
          allowed: false,
          domain: 'shell',
          operation: op,
          reason: `Comando bloqueado pela política: ${denied.command}${denied.args ? ' ' + denied.args.join(' ') : ''}`,
          violationType: 'shell_denied',
        };
      }
    }

    // 2. Fail-closed: empty allowlist → DENY ALL
    if (this.config.shell.allowedCommands.length === 0) {
      if (this.config.shell.allowAllShell) {
        return { allowed: true, domain: 'shell', operation: op };
      }
      return {
        allowed: false,
        domain: 'shell',
        operation: op,
        reason: `Comando shell negado — allowlist vazia (fail-closed). Use allowAllShell=true para permitir deliberadamente.`,
        violationType: 'shell_denied',
      };
    }

    // 3. Allowlist check (structural)
    for (const allowed of this.config.shell.allowedCommands) {
      if (this.matchesCommandRule(cmd, args, allowed)) {
        return { allowed: true, domain: 'shell', operation: op };
      }
    }

    return {
      allowed: false,
      domain: 'shell',
      operation: op,
      reason: `Comando ${cmd}${args.length > 0 ? ' ' + args.join(' ') : ''} não está na allowlist de shells`,
      violationType: 'shell_denied',
    };
  }

  /**
   * Structural command matching.
   * Rule matches if:
   *   1. command exactly matches
   *   2. rule.args is undefined/empty OR args start with rule.args prefix
   */
  private matchesCommandRule(command: string, args: string[], rule: CommandRule): boolean {
    if (command !== rule.command) return false;
    if (!rule.args || rule.args.length === 0) return true;
    if (args.length < rule.args.length) return false;
    for (let i = 0; i < rule.args.length; i++) {
      if (args[i] !== rule.args[i]) return false;
    }
    return true;
  }

  /**
   * Network evaluation.
   *
   * FAIL-CLOSED: empty allowedDomains → DENY ALL unless allowAllNetwork is true.
   *
   * Domain matching is STRUCTURAL, not textual:
   * - "example.com" matches "example.com" and "*.example.com" (subdomains)
   * - "example.com" does NOT match "example.com.evil.com" or "evil-example.com"
   * - Wildcard "*.example.com" matches any subdomain but not the apex
   */
  private evaluateNetwork(op: NetworkOperation): PolicyDecision {
    const url = op.type === 'http_request' ? op.url : `https://${op.hostname}`;
    const hostname = this.extractHostname(url);

    // 1. Deny check first (deny always wins)
    for (const denied of this.config.network.deniedDomains) {
      if (this.domainMatches(hostname, denied)) {
        return {
          allowed: false,
          domain: 'network',
          operation: op,
          reason: `Domínio bloqueado pela política: ${denied}`,
          violationType: 'network_denied',
        };
      }
    }

    // 2. Fail-closed: empty allowlist → DENY ALL
    if (this.config.network.allowedDomains.length === 0) {
      if (this.config.network.allowAllNetwork) {
        return { allowed: true, domain: 'network', operation: op };
      }
      return {
        allowed: false,
        domain: 'network',
        operation: op,
        reason: `Acesso à rede negado — allowlist vazia (fail-closed). Use allowAllNetwork=true para permitir deliberadamente.`,
        violationType: 'network_denied',
      };
    }

    // 3. Allowlist check (structural domain matching)
    for (const allowed of this.config.network.allowedDomains) {
      if (this.domainMatches(hostname, allowed)) {
        return { allowed: true, domain: 'network', operation: op };
      }
    }

    return {
      allowed: false,
      domain: 'network',
      operation: op,
      reason: `Domínio não está na allowlist de rede: ${hostname}`,
      violationType: 'network_denied',
    };
  }

  /**
   * Extract hostname from a URL string.
   */
  private extractHostname(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname;
    } catch {
      // Not a valid URL — might be just a hostname
      return url.replace(/^https?:\/\//, '').split(/[:/]/)[0];
    }
  }

  /**
   * Structural domain matching.
   *
   * "example.com" matches:
   *   - "example.com" (exact)
   *   - "sub.example.com" (subdomain)
   *
   * "example.com" does NOT match:
   *   - "example.com.evil.com" (suffix attack)
   *   - "evil-example.com" (prefix attack)
   *   - "example.com.evil" (partial suffix)
   *
   * "*.example.com" matches:
   *   - "sub.example.com" (any subdomain)
   *   - NOT "example.com" (apex not included with wildcard)
   */
  private domainMatches(hostname: string, pattern: string): boolean {
    const h = hostname.toLowerCase();
    const p = pattern.toLowerCase();

    // Wildcard pattern: *.example.com
    if (p.startsWith('*.')) {
      const base = p.slice(2);
      return h.endsWith('.' + base) && h !== base;
    }

    // Exact match or subdomain match
    return h === p || h.endsWith('.' + p);
  }
}
