import { sign, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { canonicalJson } from "../acceptance.js";
import {
  digestOfText,
  initializeVerifierHome,
  loadPrivateKey,
  loadPublicKey,
  publicKeyFingerprint,
  readConfig,
  verifierRoot,
  writeJsonAtomic,
} from "../verifier-home.js";
import type { DecisionPoint } from "./config.js";
import type { DeciderAnswer, DeciderQuestion } from "./contract.js";

/**
 * Registro de cada decisão tomada no lugar do operador.
 *
 * Fonte de autoridade: `<raiz do verificador>/decisions/<id>.json`, assinado com a
 * chave Ed25519 do verificador (a mesma dos recibos). Cópia para revisão humana em
 * `.pwn/decisions/<work>/<id>.json`. Guarda perguntas, respostas brutas, limiares e
 * modelo exato: a política pode ser recalculada sem chamar o modelo de novo.
 */

export type DecisionOutcome = "approve" | "reject" | "escalate";

export interface DecisionRecord {
  version: 1;
  decision_id: string;
  point: DecisionPoint;
  project: string;
  work_id: string;
  task_id: string;
  /** Decisor configurado (`jev:jev-latest`) ou `rule` quando a política é só código. */
  decider: string;
  /** Modelo exato que respondeu; `null` sem chamada (regra, indisponível). */
  model: string | null;
  state_sha256: string | null;
  questions: Record<string, DeciderQuestion> | null;
  answers: Record<string, DeciderAnswer> | null;
  usage: { input_tokens: number; output_tokens: number } | null;
  thresholds: Record<string, number | string>;
  outcome: DecisionOutcome;
  /** Ação escolhida quando o ponto tem mais de uma (ex.: nível de risco, `rebase`). */
  action: string | null;
  reasons: string[];
  created_at: string;
  verifier: { id: string; public_key_fingerprint: string };
  signature: string;
}

export type DecisionContent = Omit<DecisionRecord, "version" | "decision_id" | "created_at" | "verifier" | "signature">;

const decisionsDir = (root: string): string => path.join(root, "decisions");

export function decisionRepoCopy(rootDir: string, workId: string, decisionId: string): string {
  return path.resolve(rootDir, ".pwn", "decisions", workId, `${decisionId}.json`);
}

/** Assina e grava a decisão; devolve o registro com o id que a ação cita (ex.: `approved_by`). */
export function recordDecision(content: DecisionContent, rootDir: string, root: string = verifierRoot()): DecisionRecord {
  const { config } = initializeVerifierHome(root);
  const privateKey = loadPrivateKey(root);
  const fingerprint = publicKeyFingerprint(root);
  if (!privateKey || !fingerprint) throw new Error("verificador sem chave para assinar a decisão: rode 'pwn verify init'");
  const base = {
    version: 1 as const,
    ...content,
    created_at: new Date().toISOString(),
    verifier: { id: config.verifier_id, public_key_fingerprint: fingerprint },
  };
  const subject = { decision_id: digestOfText(canonicalJson(base)).slice(0, 24), ...base };
  const record: DecisionRecord = { ...subject, signature: sign(null, Buffer.from(canonicalJson(subject)), privateKey).toString("base64") };
  writeJsonAtomic(path.join(decisionsDir(root), `${record.decision_id}.json`), record);
  writeJsonAtomic(decisionRepoCopy(rootDir, record.work_id, record.decision_id), record);
  return record;
}

export function decisionSignatureIsValid(record: DecisionRecord, root: string = verifierRoot()): boolean {
  const publicKey = loadPublicKey(root);
  if (!publicKey) return false;
  const { signature, ...subject } = record;
  try {
    return verify(null, Buffer.from(canonicalJson(subject)), publicKey, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

export function readDecision(decisionId: string, root: string = verifierRoot()): DecisionRecord | null {
  const file = path.join(decisionsDir(root), `${decisionId}.json`);
  return existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as DecisionRecord) : null;
}

/** Decisões de um projeto, da mais antiga para a mais nova. */
export function listDecisions(project: string, root: string = verifierRoot()): DecisionRecord[] {
  const dir = decisionsDir(root);
  if (!existsSync(dir) || !readConfig(root)) return [];
  return readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(readFileSync(path.join(dir, file), "utf8")) as DecisionRecord)
    .filter((record) => record.project === project)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
}
