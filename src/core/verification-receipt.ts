import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { createHash, sign, verify } from "node:crypto";
import path from "node:path";

import { canonicalJson } from "./acceptance.js";
import type { CheckObservation, VerificationRunResult } from "./verification-runner.js";
import { currentApproval, type Approval } from "./acceptance-approval.js";
import { captureDependencyDigest, captureSnapshot } from "./candidate-snapshot.js";
import {
  digestOfText,
  loadPrivateKey,
  loadPublicKey,
  publicKeyFingerprint,
  receiptDir,
  readConfig,
  verifierRoot,
  writeJsonAtomic,
} from "./verifier-home.js";

/**
 * Recibo de aceitação independente.
 *
 * É o ÚNICO documento que autoriza conclusão. Ele é assinado com a chave privada do
 * verificador — que o código avaliado nunca alcança — e vincula três coisas:
 * a aprovação vigente, a entrega exata que foi executada e o resultado observado.
 *
 * A cópia no repositório serve para revisão; a assinatura é conferida contra a
 * chave pública da raiz protegida, então adulterá-la não produz aceitação.
 */

export interface ReceiptCheckSummary {
  id: string;
  outcome: CheckObservation["outcome"];
  exit_code: number;
  output_digest: string;
  baseline_exit_code: number | null;
  baseline_suspect_environmental: boolean;
}

export interface VerificationReceipt {
  version: 1;
  kind: "independent-acceptance";
  receipt_id: string;
  approval_id: string;
  work_id: string;
  task_id: string;
  candidate_snapshot_digest: string;
  dependency_digest: string;
  sandbox_digest: string;
  outcome: "pass" | "fail" | "blocked";
  checks: ReceiptCheckSummary[];
  verifier: { id: string; public_key_fingerprint: string };
  created_at: string;
  signature: string;
}

function summarize(observation: CheckObservation): ReceiptCheckSummary {
  return {
    id: observation.id,
    outcome: observation.outcome,
    exit_code: observation.exit_code,
    output_digest: observation.output_digest,
    baseline_exit_code: observation.baseline?.exit_code ?? null,
    baseline_suspect_environmental: observation.baseline?.suspect_environmental ?? false,
  };
}

export function receiptOutcome(result: VerificationRunResult): VerificationReceipt["outcome"] {
  if (result.checks.some((check) => check.outcome === "blocked")) return "blocked";
  if (result.checks.some((check) => check.outcome === "fail")) return "fail";
  if (!result.checks.length) return "blocked";
  return "pass";
}

export interface BuildReceiptOptions {
  approval: Approval;
  result: VerificationRunResult;
  verifierRootDir?: string;
}

export function buildReceipt(options: BuildReceiptOptions): VerificationReceipt {
  const root = options.verifierRootDir ?? verifierRoot();
  const fingerprint = publicKeyFingerprint(root);
  const config = readConfig(root);
  const privateKey = loadPrivateKey(root);
  if (!privateKey || !fingerprint || !config) {
    throw new Error("verificador não inicializado: não há chave privada para assinar o recibo");
  }
  const base = {
    version: 1 as const,
    kind: "independent-acceptance" as const,
    work_id: options.approval.work_id,
    task_id: options.approval.task_id,
    approval_id: options.approval.approval_id,
    candidate_snapshot_digest: options.result.snapshot_digest,
    dependency_digest: options.result.dependency_digest,
    sandbox_digest: options.result.sandbox_digest,
    outcome: receiptOutcome(options.result),
    checks: options.result.checks.map(summarize),
    verifier: { id: config.verifier_id, public_key_fingerprint: fingerprint },
    created_at: new Date().toISOString(),
  };
  const receiptId = digestOfText(canonicalJson(base));
  // O `receipt_id` precisa entrar no payload assinado: a conferência reconstrói o
  // sujeito removendo apenas `signature`, então assinar sem ele invalidaria todo recibo.
  const subject = { receipt_id: receiptId, ...base };
  const signature = sign(null, Buffer.from(canonicalJson(subject)), privateKey).toString("base64");
  return { ...subject, signature };
}

export function signatureIsValid(receipt: VerificationReceipt, root: string = verifierRoot()): boolean {
  const publicKey = loadPublicKey(root);
  if (!publicKey) return false;
  const { signature, ...subject } = receipt;
  try {
    return verify(null, Buffer.from(canonicalJson(subject)), publicKey, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

/** Rota no repositório: cópia para revisão humana, nunca fonte de autoridade. */
export function receiptRepoCopy(rootDir: string, workId: string, taskId: string): string {
  return path.resolve(rootDir, ".todo", "verification", `${workId}-${taskId}-receipt.json`);
}

export function latestReceipt(workId: string, taskId: string, root: string = verifierRoot()): VerificationReceipt | null {
  const file = path.join(receiptDir(root), `${workId}-${taskId}.json`);
  if (!existsSync(file)) return null;
  return parseReceipt(readFileSync(file, "utf8"));
}

function parseReceipt(text: string): VerificationReceipt | null {
  try {
    const parsed = JSON.parse(text) as VerificationReceipt;
    if (parsed?.version !== 1 || parsed.kind !== "independent-acceptance") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function storeReceipt(receipt: VerificationReceipt, rootDir: string, root: string = verifierRoot()): string[] {
  const history = path.join(receiptDir(root), "history", `${receipt.receipt_id}.json`);
  writeJsonAtomic(history, receipt);
  writeJsonAtomic(path.join(receiptDir(root), `${receipt.work_id}-${receipt.task_id}.json`), receipt);
  const repoCopy = receiptRepoCopy(rootDir, receipt.work_id, receipt.task_id);
  mkdirSync(path.dirname(repoCopy), { recursive: true });
  writeJsonAtomic(repoCopy, receipt);
  return [history, repoCopy];
}

export interface AcceptanceEvaluation {
  accepted: boolean;
  reason?: string;
  receipt?: VerificationReceipt;
  approval?: Approval | null;
}

/**
 * Decide se a task está aceita AGORA.
 *
 * Aceito exige: aprovação vigente, recibo assinado por chave confiável para essa
 * aprovação, resultado `pass` e a árvore atual idêntica à que foi avaliada. Qualquer
 * divergência (arquivo alterado, dependência alterada, aprovação nova) invalida a
 * autorização anterior — o recibo continua sendo histórico, não permissão.
 */
export function evaluateAcceptance(options: {
  rootDir: string;
  workId: string;
  taskId: string;
  verifierRootDir?: string;
}): AcceptanceEvaluation {
  const root = options.verifierRootDir ?? verifierRoot();
  const approval = currentApproval(options.workId, options.taskId, root);
  if (!approval) {
    return { accepted: false, approval: null, reason: "sem aprovação de aceitação independente" };
  }
  const receipt = latestReceipt(options.workId, options.taskId, root)
    ?? (() => {
      const copy = receiptRepoCopy(options.rootDir, options.workId, options.taskId);
      return existsSync(copy) ? parseReceipt(readFileSync(copy, "utf8")) : null;
    })();
  if (!receipt) {
    return { accepted: false, approval, reason: "sem recibo de verificação independente" };
  }
  if (receipt.approval_id !== approval.approval_id) {
    return { accepted: false, approval, receipt, reason: "recibo pertence a uma aprovação anterior" };
  }
  const fingerprint = publicKeyFingerprint(root);
  if (!fingerprint || receipt.verifier.public_key_fingerprint !== fingerprint) {
    return { accepted: false, approval, receipt, reason: "recibo assinado por verificador desconhecido" };
  }
  if (!signatureIsValid(receipt, root)) {
    return { accepted: false, approval, receipt, reason: "assinatura do recibo inválida" };
  }
  if (receipt.outcome !== "pass") {
    return { accepted: false, approval, receipt, reason: `última verificação independente: ${receipt.outcome}` };
  }
  const snapshot = captureSnapshot(options.rootDir);
  if (snapshot.digest !== receipt.candidate_snapshot_digest) {
    return { accepted: false, approval, receipt, reason: "a árvore mudou depois da verificação independente" };
  }
  const dependency = captureDependencyDigest(options.rootDir);
  if (dependency.digest !== receipt.dependency_digest) {
    return { accepted: false, approval, receipt, reason: "as dependências mudaram depois da verificação independente" };
  }
  return { accepted: true, approval, receipt };
}

/** Digest da árvore atual, para o operador comparar com o recibo. */
export function currentTreeDigest(rootDir: string): string {
  return createHash("sha256").update(captureSnapshot(rootDir).digest).digest("hex").slice(0, 16);
}
