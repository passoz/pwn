/**
 * Policy Engine — Preventive interception layer between agent and execution surface.
 *
 * Sits between the Contract and the agent runtime, producing concrete ALLOW/DENY
 * decisions for filesystem, shell, and network operations BEFORE they execute.
 *
 * This is the key architectural piece recommended by the technical audit:
 *   Contract → Policy Engine → ALLOW/DENY → filesystem / shell / network
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

export type ShellOperation =
  | { type: 'shell_exec'; command: string }
  | { type: 'shell_exec'; command: string; args: string[] };

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

export interface ShellPolicy {
  /** Allowed command prefixes (e.g. ['bun test', 'git status']) */
  allowedCommands: string[];
  /** Blocked command prefixes (deny overrides allow) */
  deniedCommands: string[];
}

export interface NetworkPolicy {
  /** Allowed URL prefixes / domains. Empty = all denied. */
  allowedDomains: string[];
  /** Blocked URL prefixes / domains (deny overrides allow). */
  deniedDomains: string[];
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
  deniedCommands: ['rm -rf /', 'mkfs', 'dd if=', ':(){:|:&};:'],
};

export const DEFAULT_NETWORK_POLICY: NetworkPolicy = {
  allowedDomains: [],
  deniedDomains: [],
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

  /**
   * Evaluate a proposed operation against the policy.
   * Returns ALLOW or DENY with a human-readable reason.
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

  private evaluateShell(op: ShellOperation): PolicyDecision {
    const fullCommand = 'args' in op ? `${op.command} ${(op.args ?? []).join(' ')}` : op.command;

    // Deny check first
    for (const denied of this.config.shell.deniedCommands) {
      if (fullCommand.startsWith(denied) || fullCommand.includes(denied)) {
        return {
          allowed: false,
          domain: 'shell',
          operation: op,
          reason: `Comando bloqueado pela política: ${denied}`,
          violationType: 'shell_denied',
        };
      }
    }

    // If allowlist is empty, allow everything not explicitly denied
    if (this.config.shell.allowedCommands.length === 0) {
      return { allowed: true, domain: 'shell', operation: op };
    }

    // Allowlist check
    for (const allowed of this.config.shell.allowedCommands) {
      if (fullCommand.startsWith(allowed)) {
        return { allowed: true, domain: 'shell', operation: op };
      }
    }

    return {
      allowed: false,
      domain: 'shell',
      operation: op,
      reason: `Comando não está na allowlist de shells: ${fullCommand}`,
      violationType: 'shell_denied',
    };
  }

  private evaluateNetwork(op: NetworkOperation): PolicyDecision {
    const url = op.type === 'http_request' ? op.url : `https://${op.hostname}`;

    // Deny check
    for (const denied of this.config.network.deniedDomains) {
      if (url.includes(denied)) {
        return {
          allowed: false,
          domain: 'network',
          operation: op,
          reason: `Domínio bloqueado pela política: ${denied}`,
          violationType: 'network_denied',
        };
      }
    }

    // If allowlist is empty, allow everything not explicitly denied
    if (this.config.network.allowedDomains.length === 0) {
      return { allowed: true, domain: 'network', operation: op };
    }

    // Allowlist check
    for (const allowed of this.config.network.allowedDomains) {
      if (url.includes(allowed)) {
        return { allowed: true, domain: 'network', operation: op };
      }
    }

    return {
      allowed: false,
      domain: 'network',
      operation: op,
      reason: `Domínio não está na allowlist de rede: ${url}`,
      violationType: 'network_denied',
    };
  }
}
