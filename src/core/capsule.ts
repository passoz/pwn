import { TaskContractV4 } from './contract-engine.js';

/** Check exigido pela task no plano v3: nome (`AC-1`, `REGRESSION`, ...) e comandos autorizados. */
export interface CapsuleCheckBinding {
  name: string;
  commands: string[];
  error?: string;
}

/**
 * Comandos do plano v3 que o audit exige (`parsePlanTask`/`allowedCheckCommands`).
 * Sem isto a cápsula mostraria só a allowlist do contrato — que não é o critério
 * de aceite — e o agente descobriria a regra pelo erro do audit.
 */
export interface CapsulePlanContext {
  redCommand: string | null;
  checks: CapsuleCheckBinding[];
  globalGates: string[];
}

export interface ContextCapsuleOptions {
  task: TaskContractV4;
  relevantInterfaces?: string[];
  plan?: CapsulePlanContext;
}

/** Bloco da seção de validação: só aparece quando o plano está disponível. */
function renderPlanCommands(plan: CapsulePlanContext): string {
  const lines = ['', 'PLANO (o audit exige EXATAMENTE estes comandos):'];
  lines.push(`  RED:        ${plan.redCommand ?? '(o plano não declara RED)'}`);
  if (!plan.checks.length) lines.push('  (o plano não declara checks de aceitação)');
  for (const check of plan.checks) {
    const commands = check.error ? `[${check.error}]` : check.commands.map((command) => `\`${command}\``).join(' | ');
    lines.push(`  ${check.name.padEnd(11)} ${commands}`);
  }
  lines.push(`  GATES GLOBAIS: ${plan.globalGates.length ? plan.globalGates.map((command) => `\`${command}\``).join(' | ') : '(N/A)'}`);
  return lines.join('\n');
}

export function generateContextCapsule(options: ContextCapsuleOptions): string {
  const { task, relevantInterfaces = [], plan } = options;
  // Contratos V4 congelados mais antigos podem omitir out_of_scope; a cápsula
  // nunca deve quebrar por um campo opcional ausente.
  const writeAllow = task.scope_contract.write_allow ?? [];
  const writeDeny = task.scope_contract.write_deny ?? [];
  const outOfScope = task.scope_contract.out_of_scope ?? [];
  const frozenTests = task.acceptance_contract.frozen_tests ?? [];

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
CONTRACT ALLOWLIST (o shell do sandbox só executa estes prefixos):
${task.acceptance_contract.commands.map(cmd => `  $ ${cmd}`).join('\n')}
${plan ? renderPlanCommands(plan) : ''}
FROZEN ACCEPTANCE TESTS (não editar — o audit recusa a atestação se mudarem):
${frozenTests.length ? frozenTests.map((entry) => `  = ${entry.path}`).join('\n') : '  (nenhum)'}

ACCEPTANCE: a task só conclui com 'pwn work audit candidate' (ACs do plano, idênticos, sobre o GREEN).

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
