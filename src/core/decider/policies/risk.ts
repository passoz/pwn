import type { RiskLevel } from "../../contract-engine.js";
import { RISK_LEVELS } from "../config.js";
import type { ChoiceAnswer, DeciderAnswer, DeciderRequest } from "../contract.js";
import type { Judgment, Policy } from "../engine.js";

/**
 * `--risk auto`: o decisor só SOBE o risco determinístico, nunca rebaixa, e nunca
 * atribui L4 (L4 suspende a execução: continua sendo escolha deliberada do operador).
 */

export const RISK_THRESHOLDS = { confidence_min: 0.7, ceiling: "L3" };

const OPTIONS: Record<string, string> = {
  L1: "Só documentação, comentários ou formatação; sem mudança de comportamento",
  L2: "Mudança de comportamento comum, sem superfície sensível",
  L3: "Superfície sensível: autenticação, autorização, sessão, credenciais, pagamentos, dados pessoais, criptografia, webhooks, migração de dados",
};

export interface RiskTask {
  id: string;
  title: string;
  description: string;
  files: string[];
  deterministic: RiskLevel;
}

const questionId = (taskId: string): string => `risk:${taskId}`;

export function riskRequest(tasks: RiskTask[]): DeciderRequest {
  return {
    state: { tasks: tasks.map(({ deterministic: _ignored, ...task }) => task) },
    questions: Object.fromEntries(
      tasks.map((task) => [
        questionId(task.id),
        { type: "choice" as const, instructions: `Qual o nível de risco da task de id \`${task.id}\` em \`tasks\`?`, criteria: OPTIONS },
      ]),
    ),
  };
}

export interface RiskRaise {
  task: string;
  from: RiskLevel;
  to: RiskLevel;
  confidence: number;
}

/** Elevações aplicáveis: escolha acima do determinístico, até L3, com confiança mínima. Pura. */
export function riskRaises(answers: Record<string, DeciderAnswer>, tasks: Array<Pick<RiskTask, "id" | "deterministic">>): RiskRaise[] {
  const raises: RiskRaise[] = [];
  for (const task of tasks) {
    const answer = answers[questionId(task.id)] as ChoiceAnswer | undefined;
    if (!answer || answer.confidence < RISK_THRESHOLDS.confidence_min) continue;
    const chosen = answer.choice as RiskLevel;
    if (RISK_LEVELS.indexOf(chosen) > RISK_LEVELS.indexOf(task.deterministic) && RISK_LEVELS.indexOf(chosen) <= RISK_LEVELS.indexOf("L3")) {
      raises.push({ task: task.id, from: task.deterministic, to: chosen, confidence: answer.confidence });
    }
  }
  return raises;
}

export function riskPolicy(tasks: RiskTask[]): Policy {
  return {
    point: "risk",
    thresholds: RISK_THRESHOLDS,
    judge(answers): Judgment {
      const raises = riskRaises(answers, tasks);
      return {
        outcome: "approve",
        action: raises.length ? raises.map((raise) => `${raise.task}:${raise.from}→${raise.to}`).join(", ") : null,
        reasons: raises.length
          ? raises.map((raise) => `task ${raise.task}: risco elevado de ${raise.from} para ${raise.to} (confiança ${raise.confidence.toFixed(2)})`)
          : ["nenhuma elevação: risco determinístico mantido"],
      };
    },
  };
}
