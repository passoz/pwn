import { TaskContractV4 } from './contract-engine.js';

export interface ContextCapsuleOptions {
  task: TaskContractV4;
  relevantInterfaces?: string[];
}

export function generateContextCapsule(options: ContextCapsuleOptions): string {
  const { task, relevantInterfaces = [] } = options;
  // Contratos V4 congelados mais antigos podem omitir out_of_scope; a cápsula
  // nunca deve quebrar por um campo opcional ausente.
  const writeAllow = task.scope_contract.write_allow ?? [];
  const writeDeny = task.scope_contract.write_deny ?? [];
  const outOfScope = task.scope_contract.out_of_scope ?? [];

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
${writeAllow.map(w => `  + ${w}`).join('\n')}

WRITE DENY (PROHIBITED):
${writeDeny.map(d => `  - ${d}`).join('\n')}

OUT OF SCOPE:
${outOfScope.length ? outOfScope.map(o => `  ! ${o}`).join('\n') : '  (não declarado)'}

--------------------------------------------------------------------------------
3. VALIDATION COMMANDS
--------------------------------------------------------------------------------
${task.acceptance_contract.commands.map(cmd => `  $ ${cmd}`).join('\n')}

--------------------------------------------------------------------------------
4. BUDGET & ESCALATION RULES
--------------------------------------------------------------------------------
Max Agent Attempts:   ${task.budget_contract.max_agent_attempts}
Max LLM Calls:        ${task.budget_contract.max_llm_calls ?? 'N/A'}
Max Tool Calls:       ${task.budget_contract.max_tool_calls ?? 'N/A'}
Max Shell Executions: ${task.budget_contract.max_shell_executions ?? 'N/A'}
Max Duration:         ${task.budget_contract.max_duration_minutes ?? 'N/A'} mins
Max USD:              $${task.budget_contract.max_cost_usd ?? 'N/A'}

On Write Violation: ${task.escalation_contract.on_write_violation}
On Budget Exceeded:  ${task.escalation_contract.on_budget_exceeded}
On Attempt Failed:   ${task.escalation_contract.on_attempt_failed}
================================================================================
`.trim();
}
