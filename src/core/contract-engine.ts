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
    out_of_scope: string[];
  };
  budget_contract: {
    max_tokens?: number;
    max_cost_usd?: number;
    max_duration_minutes?: number;
    max_attempts: number;
  };
  escalation_contract: {
    on_write_violation: 'block_and_escalate';
    on_budget_exceeded: 'escalate_to_strong_agent' | 'human_review';
    on_attempt_failed: 'retry_with_strong' | 'human_review';
  };
}

export function createDefaultContractV4(taskId: string, workId: string, title: string, riskLevel: RiskLevel = 'L1'): TaskContractV4 {
  const isHighRisk = riskLevel === 'L3' || riskLevel === 'L4';

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
      scenarios: [
        {
          id: `SCENARIO-${taskId}-01`,
          given: `Dado o contexto da task ${taskId}`,
          when: 'Quando o código é executado',
          then: 'Então o comportamento esperado é satisfeito sem regressões',
        },
      ],
    },
    change_contract: {
      target_files: [`src/**`],
      affected_components: ['core'],
    },
    architecture_contract: {
      invariants: ['Não quebrar retrocompatibilidade nem expor dados sensíveis'],
    },
    acceptance_contract: {
      commands: ['bun test'],
      required_evidence: ['evidence.json'],
    },
    scope_contract: {
      write_allow: [`src/**`, `tests/**`],
      write_deny: [`.git/**`, `package.json`],
      out_of_scope: ['Mudanças de infraestrutura ou banco não especificadas'],
    },
    budget_contract: {
      max_tokens: 50000,
      max_cost_usd: 0.50,
      max_duration_minutes: 10,
      max_attempts: 3,
    },
    escalation_contract: {
      on_write_violation: 'block_and_escalate',
      on_budget_exceeded: 'escalate_to_strong_agent',
      on_attempt_failed: 'retry_with_strong',
    },
  };
}
