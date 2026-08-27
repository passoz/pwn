import { TaskContractV4, createDefaultContractV4 } from './contract-engine.js';

export interface ContextCapsuleOptions {
  task: TaskContractV4;
  relevantInterfaces?: string[];
}

export function generateContextCapsule(options: ContextCapsuleOptions): string {
  const { task, relevantInterfaces = [] } = options;

  return `
================================================================================
                      PWN TASK CONTEXT CAPSULE (v4.0)
================================================================================
TASK ID:    ${task.task_id} (Work: ${task.work_id})
TITLE:      ${task.title}
RISK LEVEL: ${task.risk.level} (${task.risk.reasons.join('; ')})
STRATEGY:   ${task.validation_strategy}

--------------------------------------------------------------------------------
1. BEHAVIORAL SCENARIOS
--------------------------------------------------------------------------------
${task.behavioral_contract.scenarios.map(s => `[${s.id}]
Given: ${s.given}
When:  ${s.when}
Then:  ${s.then}`).join('\n\n')}

--------------------------------------------------------------------------------
2. CHANGE & WRITE ALLOWLIST
--------------------------------------------------------------------------------
WRITE ALLOW:
${task.scope_contract.write_allow.map(w => `  + ${w}`).join('\n')}

WRITE DENY (PROHIBITED):
${task.scope_contract.write_deny.map(d => `  - ${d}`).join('\n')}

OUT OF SCOPE:
${task.scope_contract.out_of_scope.map(o => `  ! ${o}`).join('\n')}

--------------------------------------------------------------------------------
3. VALIDATION COMMANDS
--------------------------------------------------------------------------------
${task.acceptance_contract.commands.map(cmd => `  $ ${cmd}`).join('\n')}

--------------------------------------------------------------------------------
|4. BUDGET & ESCALATION RULES
|--------------------------------------------------------------------------------
|Max Agent Attempts:   ${task.budget_contract.max_agent_attempts}
|Max LLM Calls:        ${task.budget_contract.max_llm_calls ?? 'N/A'}
|Max Tool Calls:       ${task.budget_contract.max_tool_calls ?? 'N/A'}
|Max Shell Executions: ${task.budget_contract.max_shell_executions ?? 'N/A'}
|Max Duration:         ${task.budget_contract.max_duration_minutes ?? 'N/A'} mins
|Max USD:              $${task.budget_contract.max_cost_usd ?? 'N/A'}

On Write Violation: ${task.escalation_contract.on_write_violation}
On Budget Exceeded:  ${task.escalation_contract.on_budget_exceeded}
On Attempt Failed:   ${task.escalation_contract.on_attempt_failed}
================================================================================
`.trim();
}
