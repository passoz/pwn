/**
 * Primitivas neutras do decisor (docs/future/operador-decisor.md §4).
 *
 * As políticas falam só nestes tipos; cada adaptador traduz para o seu provedor.
 * O modelo escolhe entre opções fechadas: `noul` (sim/não com probabilidade),
 * `choice` (uma opção de um conjunto) e `score` (nível de uma rubrica ordenada).
 */

export type DeciderText = string | Record<string, unknown> | unknown[];

export type DeciderQuestion =
  | { type: "noul"; instructions: DeciderText; criteria?: { true: DeciderText; false: DeciderText } }
  | { type: "choice"; instructions: DeciderText; criteria: Record<string, DeciderText | null> }
  | { type: "score"; instructions: DeciderText; criteria: DeciderText[] };

export interface NoulAnswer {
  type: "noul";
  noul: number;
}

export interface ChoiceAnswer {
  type: "choice";
  choice: string;
  probabilities: Record<string, number>;
  confidence: number;
}

export interface ScoreAnswer {
  type: "score";
  score: number;
  probabilities: Record<string, number>;
  confidence: number;
}

export type DeciderAnswer = NoulAnswer | ChoiceAnswer | ScoreAnswer;

export interface DeciderRequest {
  /** Artefatos montados pelo código; o adaptador os envia rotulados como dados, não instrução. */
  state: Record<string, unknown>;
  questions: Record<string, DeciderQuestion>;
}

export interface DeciderResponse {
  /** Modelo exato que respondeu (ex.: `jev-1.13.0`), não o alias pedido. */
  model: string;
  answers: Record<string, DeciderAnswer>;
  usage: { input_tokens: number; output_tokens: number } | null;
}

/** Decisor pedido mas indisponível ou com resposta fora do contrato: a decisão volta para o humano. */
export class DeciderUnavailable extends Error {}

/** Conexão resolvida com o provedor: o adaptador recebe a chave, nunca o arquivo de configuração. */
export interface DeciderConnection {
  model: string;
  key: string;
  endpoint: string | null;
}

export type DeciderAdapter = (connection: DeciderConnection, request: DeciderRequest) => DeciderResponse;

const isProbability = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;

const isDistribution = (value: unknown): value is Record<string, number> =>
  typeof value === "object" && value !== null && Object.values(value).every(isProbability);

/**
 * Confere a resposta contra as perguntas feitas: uma resposta por pergunta, do mesmo
 * tipo, com números no intervalo. Qualquer desvio é indisponibilidade, nunca aprovação.
 */
export function validateResponse(request: DeciderRequest, raw: unknown): DeciderResponse {
  if (typeof raw !== "object" || raw === null) throw new DeciderUnavailable("resposta do decisor não é um objeto JSON");
  const body = raw as { model?: unknown; answers?: unknown; usage?: unknown };
  if (typeof body.model !== "string" || !body.model) throw new DeciderUnavailable("resposta do decisor sem 'model'");
  if (typeof body.answers !== "object" || body.answers === null) throw new DeciderUnavailable("resposta do decisor sem 'answers'");
  const received = body.answers as Record<string, unknown>;
  const answers: Record<string, DeciderAnswer> = {};
  for (const [id, question] of Object.entries(request.questions)) {
    const answer = received[id] as Record<string, unknown> | undefined;
    if (!answer || answer.type !== question.type) throw new DeciderUnavailable(`resposta sem '${id}' do tipo ${question.type}`);
    if (question.type === "noul") {
      if (!isProbability(answer.noul)) throw new DeciderUnavailable(`'${id}': noul fora de [0,1]`);
      answers[id] = { type: "noul", noul: answer.noul };
    } else if (question.type === "choice") {
      const options = Object.keys(question.criteria);
      if (typeof answer.choice !== "string" || !options.includes(answer.choice)) throw new DeciderUnavailable(`'${id}': opção fora do conjunto (${options.join(", ")})`);
      if (!isDistribution(answer.probabilities) || !isProbability(answer.confidence)) throw new DeciderUnavailable(`'${id}': probabilidades/confiança inválidas`);
      answers[id] = { type: "choice", choice: answer.choice, probabilities: answer.probabilities, confidence: answer.confidence };
    } else {
      const top = question.criteria.length - 1;
      if (typeof answer.score !== "number" || !Number.isFinite(answer.score) || answer.score < 0 || answer.score > top) throw new DeciderUnavailable(`'${id}': score fora de [0,${top}]`);
      if (!isDistribution(answer.probabilities) || !isProbability(answer.confidence)) throw new DeciderUnavailable(`'${id}': probabilidades/confiança inválidas`);
      answers[id] = { type: "score", score: answer.score, probabilities: answer.probabilities, confidence: answer.confidence };
    }
  }
  const usage = body.usage as { input_tokens?: unknown; output_tokens?: unknown } | undefined;
  return {
    model: body.model,
    answers,
    usage: typeof usage?.input_tokens === "number" && typeof usage?.output_tokens === "number" ? { input_tokens: usage.input_tokens, output_tokens: usage.output_tokens } : null,
  };
}
