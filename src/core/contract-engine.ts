import fs from 'node:fs';
import path from 'node:path';

export type RiskLevel = 'L0' | 'L1' | 'L2' | 'L3' | 'L4';
export type ValidationStrategy = 'tdd-strict' | 'contract-first' | 'regression-guarded' | 'visual-contract';

export interface TaskContractV4 {
  contract_version: '4.0';
  task_id: string;
  work_id: string;
  title: string;
  risk: {
    level: RiskLevel;
    reasons: string[];
  };
  validation_strategy: ValidationStrategy;
  behavioral_contract: {
    scenarios: Array<{
      id: string;
      given: string;
      when: string;
      then: string;
    }>;
  };
  change_contract: {
    target_files: string[];
    affected_components: string[];
  };
  architecture_contract: {
    invariants: string[];
  };
  acceptance_contract: {
    commands: string[];
    required_evidence: string[];
  };
  scope_contract: {
    write_allow: string[];
    write_deny: string[];
    /** Opcional: contratos V4 congelados anteriores à padronização podem omitir. */
    out_of_scope?: string[];
  };
  budget_contract: {
    max_tokens?: number;
    max_cost_usd?: number;
    max_duration_minutes?: number;
    /** Max high-level agent retry attempts (e.g. tool failures, reasoning loops). */
    max_agent_attempts: number;
    /** Max LLM API calls (prompt completions). */
    max_llm_calls?: number;
    /** Max tool invocations (filesystem, shell, network via ToolAPI). */
    max_tool_calls?: number;
    /** Max shell process executions (spawned via ToolAPI.exec). */
    max_shell_executions?: number;
  };
  escalation_contract: {
    on_write_violation: 'block_and_escalate';
    on_budget_exceeded: 'escalate_to_strong_agent' | 'human_review';
    on_attempt_failed: 'retry_with_strong' | 'human_review';
  };
}

/**
 * Create a default contract with risk-appropriate defaults.
 *
 * The contract is now less generic than v0.1.0:
 * - Behavioral scenarios derive from the task title
 * - scope_contract.write_allow targets only the relevant directories
 * - architecture invariants are risk-level dependent
 * - budget limits scale with risk level
 */
export function createDefaultContractV4(
  taskId: string,
  workId: string,
  title: string,
  riskLevel: RiskLevel = 'L1',
  options?: {
    writeAllow?: string[];
    writeDeny?: string[];
    invariants?: string[];
    scenarios?: TaskContractV4['behavioral_contract']['scenarios'];
  },
): TaskContractV4 {
  const isHighRisk = riskLevel === 'L3' || riskLevel === 'L4';

  // Risk-scaled budget defaults
  const budgetByRisk: Record<RiskLevel, { max_tokens: number; max_cost_usd: number; max_duration_minutes: number; max_agent_attempts: number; max_llm_calls: number; max_tool_calls: number; max_shell_executions: number }> = {
    L0: { max_tokens: 10_000, max_cost_usd: 0.10, max_duration_minutes: 5, max_agent_attempts: 2, max_llm_calls: 10, max_tool_calls: 20, max_shell_executions: 5 },
    L1: { max_tokens: 30_000, max_cost_usd: 0.30, max_duration_minutes: 10, max_agent_attempts: 3, max_llm_calls: 20, max_tool_calls: 40, max_shell_executions: 10 },
    L2: { max_tokens: 50_000, max_cost_usd: 0.50, max_duration_minutes: 15, max_agent_attempts: 5, max_llm_calls: 30, max_tool_calls: 60, max_shell_executions: 15 },
    L3: { max_tokens: 100_000, max_cost_usd: 2.00, max_duration_minutes: 30, max_agent_attempts: 5, max_llm_calls: 50, max_tool_calls: 100, max_shell_executions: 30 },
    L4: { max_tokens: 200_000, max_cost_usd: 5.00, max_duration_minutes: 60, max_agent_attempts: 3, max_llm_calls: 30, max_tool_calls: 50, max_shell_executions: 10 },
  };

  const budget = budgetByRisk[riskLevel];

  // Risk-appropriate defaults
  const defaultScenarios: TaskContractV4['behavioral_contract']['scenarios'] = options?.scenarios ?? [
    {
      id: `SCENARIO-${taskId}-01`,
      given: `Dado que a tarefa "${title}" foi atribuída com risco ${riskLevel}`,
      when: `Quando o agente executa a tarefa ${taskId}`,
      then: `Então o resultado deve ser funcional, sem regressões e dentro do escopo declarado`,
    },
    {
      id: `SCENARIO-${taskId}-02`,
      given: `Dado que existem invariantes arquiteturais definidos`,
      when: `Quando o agente modifica código`,
      then: `Então as invariantes permanecem intactas`,
    },
  ];

  const defaultInvariants = options?.invariants ?? [
    'Não quebrar retrocompatibilidade nem expor dados sensíveis',
    'Manter cobertura de testes existente',
    ...(isHighRisk ? ['Exigir revisão humana para mudanças estruturais'] : []),
  ];

  return {
    contract_version: '4.0',
    task_id: taskId,
    work_id: workId,
    title,
    risk: {
      level: riskLevel,
      reasons: [`Task ${taskId} classificada como ${riskLevel}`],
    },
    validation_strategy: isHighRisk ? 'tdd-strict' : 'regression-guarded',
    behavioral_contract: {
      scenarios: defaultScenarios,
    },
    change_contract: {
      target_files: options?.writeAllow ?? ['src/**'],
      affected_components: ['core'],
    },
    architecture_contract: {
      invariants: defaultInvariants,
    },
    acceptance_contract: {
      commands: ['bun test'],
      required_evidence: ['evidence.json'],
    },
    scope_contract: {
      write_allow: options?.writeAllow ?? ['src/**', 'tests/**'],
      write_deny: options?.writeDeny ?? ['.git/**', 'package.json', '.env*'],
      out_of_scope: ['Mudanças de infraestrutura ou banco não especificadas'],
    },
    budget_contract: {
      max_tokens: budget.max_tokens,
      max_cost_usd: budget.max_cost_usd,
      max_duration_minutes: budget.max_duration_minutes,
      max_agent_attempts: budget.max_agent_attempts,
      max_llm_calls: budget.max_llm_calls,
      max_tool_calls: budget.max_tool_calls,
      max_shell_executions: budget.max_shell_executions,
    },
    escalation_contract: {
      on_write_violation: 'block_and_escalate',
      on_budget_exceeded: riskLevel === 'L4' ? 'human_review' : 'escalate_to_strong_agent',
      on_attempt_failed: riskLevel === 'L4' ? 'human_review' : 'retry_with_strong',
    },
  };
}

// ── BudgetController ───────────────────────────────────────────────

export type BudgetViolationReason =
  | 'max_tokens'
  | 'max_cost_usd'
  | 'max_duration_minutes'
  | 'max_agent_attempts'
  | 'max_llm_calls'
  | 'max_tool_calls'
  | 'max_shell_executions';

export interface BudgetViolation {
  reason: BudgetViolationReason;
  limit: number;
  actual: number;
  message: string;
}

export interface BudgetUsage {
  tokens: number;
  costUsd: number;
  durationMs: number;
  agentAttempts: number;
  llmCalls: number;
  toolCalls: number;
  shellExecutions: number;
}

/**
 * BudgetController — enforces budget limits at runtime.
 *
 * Tracks accumulated usage and blocks execution when any limit is exceeded.
 * This transforms the declarative budget_contract into an executable constraint.
 *
 * Distinct units are tracked:
 *   - agentAttempts: high-level retry attempts
 *   - llmCalls: prompt completions
 *   - toolCalls: ToolAPI invocations (filesystem, shell, network)
 *   - shellExecutions: spawned processes via ToolAPI.exec
 */
export class BudgetController {
  private contract: TaskContractV4;
  private usage: BudgetUsage;
  private startTime: number;

  constructor(contract: TaskContractV4) {
    this.contract = contract;
    this.startTime = Date.now();
    this.usage = { tokens: 0, costUsd: 0, durationMs: 0, agentAttempts: 0, llmCalls: 0, toolCalls: 0, shellExecutions: 0 };
  }

  /** Record tokens consumed by a single LLM call. */
  recordTokens(count: number): void {
    this.usage.tokens += count;
  }

  /** Record cost incurred by a single LLM call. */
  recordCost(usd: number): void {
    this.usage.costUsd += usd;
  }

  /** Record a high-level agent attempt (e.g. retry loop, reasoning failure). */
  recordAgentAttempt(): void {
    this.usage.agentAttempts += 1;
    this.usage.durationMs = Date.now() - this.startTime;
  }

  /** Record a single LLM API call (prompt completion). */
  recordLLMCall(): void {
    this.usage.llmCalls += 1;
  }

  /** Record a ToolAPI invocation (filesystem, shell, network). */
  recordToolCall(): void {
    this.usage.toolCalls += 1;
  }

  /** Record a spawned shell process execution (ToolAPI.exec). */
  recordShellExecution(): void {
    this.usage.shellExecutions += 1;
  }

  /** Get current usage snapshot. */
  getUsage(): Readonly<BudgetUsage> {
    return { ...this.usage, durationMs: Date.now() - this.startTime };
  }

  /**
   * Check if any budget limit has been exceeded.
   * Returns null if OK, or the first violation found.
   */
  checkBudget(): BudgetViolation | null {
    const b = this.contract.budget_contract;
    const u = this.getUsage();

    if (b.max_agent_attempts !== undefined && u.agentAttempts >= b.max_agent_attempts) {
      return {
        reason: 'max_agent_attempts',
        limit: b.max_agent_attempts,
        actual: u.agentAttempts,
        message: `Limite de tentativas do agente excedido: ${u.agentAttempts}/${b.max_agent_attempts}`,
      };
    }

    if (b.max_llm_calls !== undefined && u.llmCalls >= b.max_llm_calls) {
      return {
        reason: 'max_llm_calls',
        limit: b.max_llm_calls,
        actual: u.llmCalls,
        message: `Limite de chamadas LLM excedido: ${u.llmCalls}/${b.max_llm_calls}`,
      };
    }

    if (b.max_tool_calls !== undefined && u.toolCalls >= b.max_tool_calls) {
      return {
        reason: 'max_tool_calls',
        limit: b.max_tool_calls,
        actual: u.toolCalls,
        message: `Limite de chamadas de ferramenta excedido: ${u.toolCalls}/${b.max_tool_calls}`,
      };
    }

    if (b.max_shell_executions !== undefined && u.shellExecutions >= b.max_shell_executions) {
      return {
        reason: 'max_shell_executions',
        limit: b.max_shell_executions,
        actual: u.shellExecutions,
        message: `Limite de execuções shell excedido: ${u.shellExecutions}/${b.max_shell_executions}`,
      };
    }

    if (b.max_duration_minutes !== undefined) {
      const durationMinutes = u.durationMs / 60_000;
      if (durationMinutes >= b.max_duration_minutes) {
        return {
          reason: 'max_duration_minutes',
          limit: b.max_duration_minutes,
          actual: Math.round(durationMinutes * 10) / 10,
          message: `Limite de duração excedido: ${durationMinutes.toFixed(1)}min/${b.max_duration_minutes}min`,
        };
      }
    }

    if (b.max_tokens !== undefined && u.tokens >= b.max_tokens) {
      return {
        reason: 'max_tokens',
        limit: b.max_tokens,
        actual: u.tokens,
        message: `Limite de tokens excedido: ${u.tokens}/${b.max_tokens}`,
      };
    }

    if (b.max_cost_usd !== undefined && u.costUsd >= b.max_cost_usd) {
      return {
        reason: 'max_cost_usd',
        limit: b.max_cost_usd,
        actual: u.costUsd,
        message: `Limite de custo excedido: $${u.costUsd.toFixed(4)}/$${b.max_cost_usd}`,
      };
    }

    return null;
  }

  /**
   * Should the execution be interrupted?
   * Returns true if any budget limit is exceeded.
   */
  shouldInterrupt(): boolean {
    return this.checkBudget() !== null;
  }

  /** Load persisted usage from a JSON file. */
  static loadUsage(filePath: string): BudgetUsage | null {
    if (!fs.existsSync(filePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
      return null;
    }
  }

  /** Persist current usage to a JSON file. */
  saveUsage(filePath: string): void {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(this.getUsage(), null, 2), 'utf8');
  }
}
