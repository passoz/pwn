import type { TaskContractV4 } from "../../contract-engine.js";
import type { DeciderRequest, NoulAnswer } from "../contract.js";
import type { Judgment, Policy } from "../engine.js";

/**
 * Fila AFK (L4): a execução suspensa pode prosseguir? Só chega aqui com
 * `max_risk: L4` no decisor. Efeito destrutivo provável nunca é aprovado pelo modelo:
 * vai para o operador.
 */

export const QUEUE_THRESHOLDS = { destructive_max: 0.1, matches_min: 0.85, reject_matches_below: 0.2 };

/** Estado: as tasks L4 envolvidas (contratos originais, não o agregado) e o comando a executar. */
export function queueRequest(contracts: TaskContractV4[], command: string[]): DeciderRequest {
  return {
    state: {
      tasks: contracts.map((contract) => ({
        id: contract.task_id,
        title: contract.title,
        risk: contract.risk,
        scenarios: contract.behavioral_contract.scenarios,
        invariants: contract.architecture_contract.invariants,
        write_allow: contract.scope_contract.write_allow,
        write_deny: contract.scope_contract.write_deny,
        out_of_scope: contract.scope_contract.out_of_scope ?? [],
      })),
      command,
    },
    questions: {
      destructive: {
        type: "noul",
        instructions: "Executar `command` para estas tasks pode ter efeito destrutivo ou irreversível (apagar dados, migração sem volta, deploy, publicação, operação financeira, alteração de credenciais)?",
        criteria: { true: "Há efeito destrutivo ou irreversível plausível", false: "O efeito fica restrito ao repositório e é reversível" },
      },
      matches_task: {
        type: "noul",
        instructions: "`command` corresponde ao que as tasks descrevem (`scenarios`) e cabe no escopo declarado (`write_allow`, `out_of_scope`)?",
      },
    },
  };
}

export const queuePolicy: Policy = {
  point: "queue",
  thresholds: QUEUE_THRESHOLDS,
  judge(answers): Judgment {
    const destructive = (answers.destructive as NoulAnswer).noul;
    const matches = (answers.matches_task as NoulAnswer).noul;
    const facts = `destrutivo=${destructive.toFixed(2)}, corresponde=${matches.toFixed(2)}`;
    if (matches < QUEUE_THRESHOLDS.reject_matches_below) return { outcome: "reject", action: null, reasons: [`o comando não corresponde à task (${facts})`] };
    if (destructive < QUEUE_THRESHOLDS.destructive_max && matches > QUEUE_THRESHOLDS.matches_min) return { outcome: "approve", action: null, reasons: [facts] };
    return {
      outcome: "escalate",
      action: null,
      reasons: [destructive >= QUEUE_THRESHOLDS.destructive_max ? `efeito destrutivo possível (${facts})` : `incerto se o comando corresponde à task (${facts})`],
    };
  },
};
