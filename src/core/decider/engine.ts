import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

import { canonicalJson } from "../acceptance.js";
import type { RiskLevel } from "../contract-engine.js";
import { verifierRoot } from "../verifier-home.js";
import { jevAdapter } from "./adapters/jev.js";
import { projectIdentity, readDeciderConfig, RISK_LEVELS, type DecisionPoint, type EnabledDeciderConfig } from "./config.js";
import { DeciderUnavailable, type DeciderAdapter, type DeciderAnswer, type DeciderConnection, type DeciderRequest } from "./contract.js";
import { recordDecision, type DecisionOutcome, type DecisionRecord } from "./ledger.js";

/**
 * Quem decide cada ponto do operador (docs/future/operador-decisor.md §3).
 *
 * - Sem configuração do decisor no projeto (ou `enabled: false`): comportamento padrão,
 *   o humano decide e nenhum modelo é chamado.
 * - Configuração habilitada: o decisor decide por padrão, dentro do escopo e do teto de risco.
 * - `--operator human` (ou `PWN_OPERATOR=human`) devolve a decisão ao humano numa execução.
 * - Falha fechada: decisor indisponível ou incerto → a decisão volta para o humano.
 */

export const OPERATOR_ENV = "PWN_OPERATOR";
export type OperatorMode = "human" | "decider";
const OPERATOR_MODES: Record<string, OperatorMode> = { human: "human", decider: "decider" };

const ADAPTERS: Record<string, DeciderAdapter> = { jev: jevAdapter };

/** Modo pedido para esta execução; `null` = padrão do projeto. */
export function operatorMode(): OperatorMode | null {
  const raw = process.env[OPERATOR_ENV]?.trim();
  if (!raw) return null;
  const mode = OPERATOR_MODES[raw];
  if (!mode) throw new Error(`${OPERATOR_ENV} inválido: '${raw}' (use human ou decider)`);
  return mode;
}

/** Raiz Git do projeto: a configuração vale de qualquer subdiretório. */
export function projectRoot(rootDir: string): string {
  const top = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: rootDir, encoding: "utf8" });
  return top.status === 0 ? top.stdout.trim() : rootDir;
}

export type Governance = { config: EnabledDeciderConfig } | { config: null; reason: string | null };

/**
 * O decisor governa este ponto? `reason: null` = comportamento padrão silencioso
 * (sem decisor configurado ou humano pedido); texto = motivo a mostrar ao operador.
 */
export function governance(rootDir: string, point: DecisionPoint, risk: RiskLevel | null = null, root: string = verifierRoot()): Governance {
  const mode = operatorMode();
  if (mode === "human") return { config: null, reason: null };
  const config = readDeciderConfig(projectRoot(rootDir), root);
  if (!config?.enabled) {
    if (mode === "decider") throw new Error("--operator decider pedido, mas este projeto não tem decisor configurado (pwn decider set --decider <provedor:modelo>)");
    return { config: null, reason: null };
  }
  if (!config.scope.includes(point)) return { config: null, reason: `ponto '${point}' fora do escopo do decisor` };
  if (risk && RISK_LEVELS.indexOf(risk) > RISK_LEVELS.indexOf(config.max_risk)) {
    return { config: null, reason: `risco ${risk} acima do teto do decisor (${config.max_risk}): decisão do operador` };
  }
  return { config };
}

/** O que a política conclui das respostas; função pura, testável sem rede. */
export interface Judgment {
  outcome: DecisionOutcome;
  action: string | null;
  reasons: string[];
}

export interface Policy {
  point: DecisionPoint;
  thresholds: Record<string, number | string>;
  judge(answers: Record<string, DeciderAnswer>): Judgment;
}

export type DecisionResult =
  | { kind: "human"; reason: string | null }
  | { kind: "decided"; record: DecisionRecord };

export interface DecideOptions {
  rootDir: string;
  workId: string;
  taskId: string;
  risk?: RiskLevel | null;
  policy: Policy;
  /** Monta estado e perguntas só quando o decisor vai de fato ser chamado. */
  request: () => DeciderRequest;
  verifierRootDir?: string;
}

function connect(config: EnabledDeciderConfig): { adapter: DeciderAdapter; connection: DeciderConnection } | string {
  const separator = config.decider.indexOf(":");
  const adapter = ADAPTERS[config.decider.slice(0, separator)];
  if (!adapter) return `provedor sem adaptador: ${config.decider}`;
  const key = process.env[config.key_env]?.trim();
  if (!key) return `$${config.key_env} não está definida`;
  return { adapter, connection: { model: config.decider.slice(separator + 1), key, endpoint: config.endpoint ?? null } };
}

/**
 * Executa um ponto de decisão. Devolve `human` quando o decisor não governa o ponto,
 * ou o registro assinado. Indisponibilidade vira registro `escalate`: o chamador
 * segue o caminho humano e mostra os motivos.
 */
export function decide(options: DecideOptions): DecisionResult {
  const root = options.verifierRootDir ?? verifierRoot();
  const governed = governance(options.rootDir, options.policy.point, options.risk ?? null, root);
  if (!governed.config) return { kind: "human", reason: governed.reason };
  const { config } = governed;
  const base = {
    point: options.policy.point,
    project: projectIdentity(projectRoot(options.rootDir)),
    work_id: options.workId,
    task_id: options.taskId,
    decider: config.decider,
    thresholds: options.policy.thresholds,
  };
  const escalate = (reason: string, request: DeciderRequest | null): DecisionResult => ({
    kind: "decided",
    record: recordDecision(
      {
        ...base,
        model: null,
        state_sha256: request ? stateDigest(request) : null,
        questions: request?.questions ?? null,
        answers: null,
        usage: null,
        outcome: "escalate",
        action: null,
        reasons: [`decisor indisponível: ${reason}`],
      },
      options.rootDir,
      root,
    ),
  });

  const connected = connect(config);
  if (typeof connected === "string") return escalate(connected, null);
  const request = options.request();
  let response;
  try {
    response = connected.adapter(connected.connection, request);
  } catch (error) {
    if (error instanceof DeciderUnavailable) return escalate(error.message, request);
    throw error;
  }
  const judgment = options.policy.judge(response.answers);
  return {
    kind: "decided",
    record: recordDecision(
      {
        ...base,
        model: response.model,
        state_sha256: stateDigest(request),
        questions: request.questions,
        answers: response.answers,
        usage: response.usage,
        outcome: judgment.outcome,
        action: judgment.action,
        reasons: judgment.reasons,
      },
      options.rootDir,
      root,
    ),
  };
}

function stateDigest(request: DeciderRequest): string {
  return createHash("sha256").update(canonicalJson(request.state)).digest("hex");
}

/** Decisão por regra (sem modelo): registrada e assinada como as demais. */
export function recordRuleDecision(
  options: { rootDir: string; workId: string; taskId: string; point: DecisionPoint; action: string; reasons: string[] },
  root: string = verifierRoot(),
): DecisionRecord {
  return recordDecision(
    {
      point: options.point,
      project: projectIdentity(projectRoot(options.rootDir)),
      work_id: options.workId,
      task_id: options.taskId,
      decider: "rule",
      model: null,
      state_sha256: null,
      questions: null,
      answers: null,
      usage: null,
      thresholds: {},
      outcome: "approve",
      action: options.action,
      reasons: options.reasons,
    },
    options.rootDir,
    root,
  );
}

/** Referência citada nos artefatos que o decisor autoriza (ex.: `approved_by`). */
export function decisionReference(record: DecisionRecord): string {
  return `decider:${record.model ?? record.decider}#${record.decision_id}`;
}

/** Linhas para o operador: o que foi decidido, por quem e por quê. */
export function describeDecision(record: DecisionRecord): string[] {
  const label: Record<DecisionOutcome, string> = { approve: "APROVADO", reject: "REJEITADO", escalate: "PARA O OPERADOR" };
  return [
    `[DECISOR] ${label[record.outcome]}${record.action ? ` (${record.action})` : ""} — ${record.model ?? record.decider}, registro ${record.decision_id}`,
    ...record.reasons.map((reason) => `  · ${reason}`),
  ];
}
