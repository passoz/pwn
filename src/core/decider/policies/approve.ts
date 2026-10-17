import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { parseGlobalGates } from "../../acceptance.js";
import { loadPlan, tasksMarkdownPath } from "../../plan-renderer.js";
import { loadTaskContract } from "../../task-contract.js";
import type { DeciderAnswer, DeciderRequest, NoulAnswer, ChoiceAnswer, ScoreAnswer } from "../contract.js";
import type { Judgment, Policy } from "../engine.js";

/**
 * `verify approve`: os testes congelados verificam o comportamento da task?
 * O modelo julga o texto; a política (limiares abaixo) decide. Os números são o
 * ponto de partida do desenho (§5) e só mudam no código, nunca por flag.
 */

export const APPROVE_THRESHOLDS = {
  covers_min: 0.8,
  passes_without_max: 0.15,
  specificity_min: 2,
  scope_confidence_min: 0.7,
  reject_covers_below: 0.2,
  reject_passes_without_above: 0.85,
};

const SPECIFICITY_LEVELS = [
  "Só checa existência, que não lança erro ou que algo foi chamado",
  "Checa forma ou tipo do resultado, sem o valor",
  "Checa o valor exato do caminho principal",
  "Checa o valor exato do caminho principal e casos de borda ou de erro",
];

/** Estado da aprovação de uma task: requisito, comportamento, ACs, testes congelados e escopo. */
export function taskApprovalRequest(rootDir: string, workId: string, taskId: string): DeciderRequest {
  const task = loadPlan(workId, rootDir)?.tasks.find((entry) => entry.id === taskId);
  if (!task) throw new Error(`task ${taskId} não encontrada no plan.json do Work ${workId}`);
  const contract = loadTaskContract(workId, taskId, rootDir);
  const frozen = contract.acceptance_contract.frozen_tests ?? [];
  if (!frozen.length) throw new Error(`a task ${taskId} não tem testes de aceitação congelados; congele-os antes de aprovar`);
  const frozenTests = frozen.map((entry) => {
    const absolute = path.resolve(rootDir, entry.path);
    if (!existsSync(absolute)) throw new Error(`teste de aceitação aprovado ausente no repositório: ${entry.path}`);
    return { path: entry.path, content: readFileSync(absolute, "utf8") };
  });
  return {
    state: {
      requirement_id: task.requirement_id,
      task: { id: task.id, title: task.title, behavior: task.behavior },
      acceptance_criteria: task.acceptance_criteria,
      frozen_tests: frozenTests,
      implementation_files: task.implementation_files,
      write_allow: contract.scope_contract.write_allow,
      write_deny: contract.scope_contract.write_deny,
    },
    questions: {
      covers_behavior: {
        type: "noul",
        instructions: "Os testes em `frozen_tests` verificam o resultado observável descrito em `task.behavior`?",
        criteria: { true: "Os testes falham se o comportamento descrito não acontecer", false: "Os testes não exercitam o comportamento descrito" },
      },
      passes_without_requirement: {
        type: "noul",
        instructions: "Os testes em `frozen_tests` passariam com uma implementação que ignora o requisito (stub, valor fixo, retorno vazio)?",
        criteria: { true: "Uma implementação vazia ou falsa passaria", false: "Só uma implementação real do comportamento passa" },
      },
      specificity: {
        type: "score",
        instructions: "Quão específicas são as asserções de `frozen_tests` em relação a `task.behavior`?",
        criteria: SPECIFICITY_LEVELS,
      },
      scope: {
        type: "choice",
        instructions: "O escopo de escrita `write_allow` é adequado para implementar `task.behavior` nos `implementation_files`?",
        criteria: {
          adequate: "Cobre os arquivos necessários e nada além do razoável",
          too_broad: "Permite escrever bem além do necessário (diretórios inteiros, manifestos, configuração)",
          too_narrow: "Não permite escrever arquivos necessários para a implementação",
        },
      },
    },
  };
}

const noul = (answers: Record<string, DeciderAnswer>, id: string): number => (answers[id] as NoulAnswer).noul;

export const taskApprovalPolicy: Policy = {
  point: "approve",
  thresholds: APPROVE_THRESHOLDS,
  judge(answers): Judgment {
    const t = APPROVE_THRESHOLDS;
    const covers = noul(answers, "covers_behavior");
    const passesWithout = noul(answers, "passes_without_requirement");
    const specificity = (answers.specificity as ScoreAnswer).score;
    const scope = answers.scope as ChoiceAnswer;
    const facts = `cobre=${covers.toFixed(2)}, passa_sem=${passesWithout.toFixed(2)}, especificidade=${specificity.toFixed(2)}, escopo=${scope.choice} (${scope.confidence.toFixed(2)})`;

    const rejections = [
      ...(covers < t.reject_covers_below ? [`os testes congelados não verificam o comportamento da task (cobre=${covers.toFixed(2)})`] : []),
      ...(passesWithout > t.reject_passes_without_above ? [`os testes congelados passariam com uma implementação que ignora o requisito (passa_sem=${passesWithout.toFixed(2)})`] : []),
    ];
    if (rejections.length) return { outcome: "reject", action: null, reasons: rejections };

    const gaps = [
      ...(covers > t.covers_min ? [] : [`cobertura do comportamento ${covers.toFixed(2)} ≤ ${t.covers_min}`]),
      ...(passesWithout < t.passes_without_max ? [] : [`chance de passar sem o requisito ${passesWithout.toFixed(2)} ≥ ${t.passes_without_max}`]),
      ...(specificity >= t.specificity_min ? [] : [`especificidade ${specificity.toFixed(2)} < ${t.specificity_min}`]),
      ...(scope.choice === "adequate" && scope.confidence >= t.scope_confidence_min ? [] : [`escopo ${scope.choice} com confiança ${scope.confidence.toFixed(2)}`]),
    ];
    if (gaps.length) return { outcome: "escalate", action: null, reasons: [...gaps, facts] };
    return { outcome: "approve", action: null, reasons: [facts] };
  },
};

export const GLOBAL_THRESHOLDS = { verifies_min: 0.85, reject_below: 0.2 };

/** Estado da aprovação de um gate global: o texto do gate e o comando que o verifica. */
export function globalApprovalRequest(rootDir: string, workId: string, gateName: string): DeciderRequest {
  const planPath = tasksMarkdownPath(workId, rootDir);
  if (!existsSync(planPath)) throw new Error(`plano não encontrado: ${planPath}`);
  const gates = parseGlobalGates(readFileSync(planPath, "utf8")) ?? [];
  const gate = gates[Number(gateName.replace(/^G-/, "")) - 1];
  if (!gate?.command) throw new Error(`${gateName} não existe ou não declara comando em ## Global gates`);
  return {
    state: { gate: { id: gateName, text: gate.text, command: gate.command } },
    questions: {
      verifies_gate: {
        type: "noul",
        instructions: "Executar `gate.command` verifica de fato o que `gate.text` declara?",
        criteria: { true: "O comando falha quando a condição declarada não vale", false: "O comando não verifica a condição declarada" },
      },
    },
  };
}

export const globalApprovalPolicy: Policy = {
  point: "approve",
  thresholds: GLOBAL_THRESHOLDS,
  judge(answers): Judgment {
    const verifies = noul(answers, "verifies_gate");
    const fact = `verifica_gate=${verifies.toFixed(2)}`;
    if (verifies < GLOBAL_THRESHOLDS.reject_below) return { outcome: "reject", action: null, reasons: [`o comando não verifica o gate declarado (${fact})`] };
    if (verifies > GLOBAL_THRESHOLDS.verifies_min) return { outcome: "approve", action: null, reasons: [fact] };
    return { outcome: "escalate", action: null, reasons: [`incerto se o comando verifica o gate (${fact} ≤ ${GLOBAL_THRESHOLDS.verifies_min})`] };
  },
};
