
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { isDirectEntry } from "./entry-guard.js";
import {
  allowedCheckCommands,
  canonicalJson,
  commandMatches,
  displayCommand,
  genericExpectReason,
  normalizeCommand,
  parseGlobalGates,
  parsePlanTask,
  parsePlanTasks,
  placeholderPathReason,
  requiredAuditChecks,
  taskDefinitionDigest,
  type PlanTaskDefinition,
} from "./acceptance.js";
import { getVerifierKey, readVerifierKey } from "./gate-cache.js";
import { loadPlan, planMatchesMarkdown } from "./plan-renderer.js";
import harnessManifest from "../../package.json" with { type: "json" };

let STATE_DIR: string;
let LOG_DIR: string;
let ATTESTATION_DIR: string;
const REDACT = "[REDACTED]";
const SENSITIVE = ["authorization", "token", "password", "passwd", "cookie", "api_key", "apikey", "secret"];

/** Código de saída para execução concluída com sucesso. */
export const EXIT_OK = 0;
/** Código de saída para violação de contrato ou erro de uso. */
export const EXIT_VIOLATION = 1;
/** Código de saída para auditoria incompleta: falta evidência ou pré-requisito (não é violação). */
export const EXIT_INCOMPLETE = 2;
/** Código de saída reservado para suspensão (espelha run-orchestrator.ts); não emitido por este módulo. */
export const EXIT_SUSPENDED = 3;

/**
 * Versão do formato de atestação de aceitação gerado por este módulo.
 * v3: checks amarrados ao plano e ao snapshot do GREEN, definição da task
 * congelada e assinatura HMAC — v1/v2 não provam nada disso e não contam como aceitas.
 */
const ATTESTATION_VERSION = 3;
/** Versão do schema de gates referenciado pela atestação. */
const GATE_VERSION = "1";
/** Versão do estado por task; 2 = baseline amarrado ao plano. */
const STATE_VERSION = 2;
/** Pseudo-task que guarda a evidência dos gates globais do Work. */
const GLOBAL_TASK = "GLOBAL";

/** Hash of a single file at snapshot time. */
interface FileDigest {
  exists: boolean;
  sha256: string | null;
}

/** Map of file path to its digest. */
type Snapshot = Record<string, FileDigest>;

/** Teste de aceitação congelado no contrato (caminho + sha256 do conteúdo aprovado). */
interface FrozenTest {
  path: string;
  sha256: string;
}

/** Recorded result of a single audit check (AC-n, VISUAL, ...). */
interface AuditCheckRecord {
  command: string[];
  expect: string | null;
  exit_code: number;
  verdict: string;
  log: string;
  log_sha256: string | null;
  recorded_at: string;
  /** Snapshot GREEN (implementação + testes) sobre o qual o check rodou. */
  green_sha256?: string;
  /** AC-n: resultado do mesmo comando com a implementação removida (precisa falhar). */
  vacuity?: { exit_code: number; verdict: string };
}

/** Persistent per-task evidence state (`.todo/evidence/<work>/state/<task>.json`). */
interface EvidenceState {
  task: string;
  created_at: string;
  state_version?: number;
  baseline_commit?: string;
  plan_path?: string;
  task_definition_sha256?: string;
  contract?: { id: string; sha256: string } | null;
  frozen_tests?: FrozenTest[];
  implementation_files: string[];
  test_files: string[];
  baseline_implementation: Snapshot;
  baseline_tests: Snapshot;
  red_tests: Snapshot | null;
  red_command?: string[];
  red_expect?: string;
  green_implementation?: Snapshot;
  green_tests?: Snapshot;
  green_expect?: string | null;
  audit_checks?: Record<string, AuditCheckRecord>;
}

/** Evidência de um gate global (G-n) do Work. */
interface GlobalGateRecord {
  command: string[];
  gate_command: string;
  exit_code: number;
  verdict: string;
  log: string;
  log_sha256: string | null;
  recorded_at: string;
  /** Digest dos arquivos de implementação/teste de todas as tasks no momento da execução. */
  tree: Snapshot;
  signature: string;
}

interface GlobalGatesState {
  work: string;
  gates: Record<string, GlobalGateRecord>;
}

interface RunOptions {
  encoding?: null;
  input?: Buffer | string;
}

/** Result of {@link run} when the output is decoded as UTF-8 text. */
interface TextResult {
  exitCode: number;
  output: string;
}

/** Result of {@link run} when raw bytes were requested (`encoding: null`). */
interface BufferResult {
  exitCode: number;
  stdout: Buffer;
  stderr: Buffer;
}

type RunResult = TextResult | BufferResult;

const ACTIONS = ["baseline", "red", "green", "verify", "check", "candidate", "gate"] as const;
type Action = (typeof ACTIONS)[number];

function isAction(value: string | undefined): value is Action {
  return value !== undefined && (ACTIONS as readonly string[]).includes(value);
}

interface BaselineArgs {
  action: "baseline";
  work: string;
  task: string;
  /** Opcional: quando informado, precisa coincidir com os arquivos declarados no plano. */
  implementation: string[];
  tests: string[];
}

interface RedArgs {
  action: "red";
  work: string;
  task: string;
  expect: string;
  /** Exige que `--expect` apareça literalmente em algum arquivo de `state.test_files` (sempre ligado no contrato v3). */
  expectLiteral: boolean;
  command: string[];
}

interface GreenArgs {
  action: "green";
  work: string;
  task: string;
  expect: string | null;
  command: string[];
}

interface CheckArgs {
  action: "check";
  work: string;
  task: string;
  name: string;
  expect: string | null;
  /** Exige que `--expect` apareça literalmente na saída do comando de check. */
  expectLiteral: boolean;
  command: string[];
}

interface VerifyArgs {
  action: "verify" | "candidate";
  work: string;
  task: string;
  /**
   * Comando do operador (após `--`). Nunca é lido do arquivo de estado: o estado é
   * um artefato do repositório e, num repo hostil, executá-lo seria execução
   * arbitrária. O comando persistido serve apenas como conferência cruzada.
   */
  command: string[];
}

interface GateArgs {
  action: "gate";
  work: string;
  name: string;
  command: string[];
}

type ParsedArgs = BaselineArgs | RedArgs | GreenArgs | CheckArgs | VerifyArgs | GateArgs;

/** Erro de pré-requisito ausente: vira EXIT_INCOMPLETE em vez de violação. */
class IncompleteError extends Error {
  constructor(public readonly items: string[]) {
    super(items.join("; "));
  }
}

// Patterns that identify toolchain/environment errors that do not exercise a test assertion.
// A RED whose output consists exclusively of these patterns (without the expect text appearing
// in an assertion context) is an incidental failure and must be rejected per BR-001.
const TOOLCHAIN_PATTERNS = [
  /cannot find main module/i,
  /no required module provides/i,
  /package .+ is not in/i,
  /no such file or directory/i,
  /module not found/i,
  /cannot find module/i,
  /error: could not compile/i,
  /build failed/i,
  /compilation failed/i,
  /error\[E\d+\]/,           // Rust compiler errors
  /^make:\s+\*\*\*/im,       // Make errors
  /SyntaxError:/i,
  /ReferenceError:/i,
  /Parse error/i,
  /undefined:/i,
  /type mismatch:/i,
  /TS\d{4}:/,                // TypeScript errors
  /cannot find symbol/i,
];

/**
 * Returns true when the command output appears to be exclusively a toolchain or environment
 * error — i.e., the expect text appears in the output only because it matches an environment
 * error message, not because a test assertion fired with that message.
 *
 * Strategy: if the output matches at least one toolchain pattern AND the expect text only
 * appears within lines that themselves match a toolchain pattern, the RED is incidental.
 * If the expect text appears on a line that does NOT match any toolchain pattern, we treat
 * it as a legitimate assertion message and accept the RED.
 */
export function isToolchainError(output: string, expect: string): boolean {
  const lines = output.split(/\r?\n/);
  const hasToolchainLine = lines.some((line) => TOOLCHAIN_PATTERNS.some((p) => p.test(line)));
  if (!hasToolchainLine) return false;
  // Check whether expect appears on at least one line that is NOT a toolchain error line.
  const expectLower = expect.toLowerCase();
  const nonToolchainMatchLine = lines.some(
    (line) => line.toLowerCase().includes(expectLower) && !TOOLCHAIN_PATTERNS.some((p) => p.test(line)),
  );
  return !nonToolchainMatchLine;
}

function configureWork(workId: string): void {
  if (workId === "legacy") {
    LOG_DIR = path.join(".todo", "evidence");
    STATE_DIR = path.join(LOG_DIR, "state");
    ATTESTATION_DIR = path.join(".todo", "attestations", "legacy");
    return;
  }
  if (!/^\d{4}$/.test(workId)) throw new Error(`invalid Work ID: ${workId}; expected four digits or legacy`);
  LOG_DIR = path.join(".todo", "evidence", workId);
  STATE_DIR = path.join(LOG_DIR, "state");
  ATTESTATION_DIR = path.join(".todo", "attestations", workId);
}

function sha256Hex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function digest(filePath: string): FileDigest {
  if (!existsSync(filePath)) return { exists: false, sha256: null };
  if (!statSync(filePath).isFile()) throw new Error(`not a regular file: ${filePath}`);
  return { exists: true, sha256: sha256Hex(readFileSync(filePath)) };
}

function snapshot(paths: string[]): Snapshot {
  return Object.fromEntries(paths.map((filePath) => [filePath, digest(filePath)]));
}

function statePath(task: string): string {
  return path.join(STATE_DIR, `${task}.json`);
}

function loadState(task: string): EvidenceState {
  const filePath = statePath(task);
  if (!existsSync(filePath)) throw new Error(`baseline not found for task ${task}; run baseline first`);
  return JSON.parse(readFileSync(filePath, "utf8")) as EvidenceState;
}

/** Resultado de {@link tryLoadState}: estado carregado ou motivo de incompletude. */
type StateLoad = { state: EvidenceState } | { incomplete: string };

/**
 * Variante tolerante de {@link loadState}: em vez de lançar quando o estado ainda não existe,
 * devolve o motivo da ausência para que a ação relate uma auditoria INCOMPLETA (exit 2).
 */
function tryLoadState(task: string): StateLoad {
  const filePath = statePath(task);
  if (!existsSync(filePath)) return { incomplete: `baseline not found for task ${task}; run baseline first` };
  try {
    return { state: JSON.parse(readFileSync(filePath, "utf8")) as EvidenceState };
  } catch (error) {
    return { incomplete: `state unreadable for task ${task}: ${(error as Error).message}` };
  }
}

/**
 * Imprime a lista completa do que falta para concluir a auditoria e devolve `EXIT_INCOMPLETE`.
 * Incompletude não é violação: o pré-requisito simplesmente ainda não foi produzido.
 */
function reportIncomplete(items: string[]): number {
  console.error(`INCOMPLETO: faltam ${items.length} evidência(s):`);
  for (const item of items) console.error(`  - ${item}`);
  return EXIT_INCOMPLETE;
}

/** Imprime todas as violações encontradas (não para na primeira) e devolve `EXIT_VIOLATION`. */
function reportViolations(items: string[]): number {
  console.error(`FAIL: ${items.length} violação(ões):`);
  for (const item of items) console.error(`  - ${item}`);
  return EXIT_VIOLATION;
}

function saveState(task: string, state: EvidenceState): void {
  mkdirSync(STATE_DIR, { recursive: true });
  const record: Record<string, unknown> = { ...state };
  const ordered = Object.fromEntries(Object.keys(record).sort().map((key) => [key, record[key]]));
  writeFileSync(statePath(task), `${JSON.stringify(ordered, null, 2)}\n`, "utf8");
}

function changed(before: Snapshot, after: Snapshot): string[] {
  const paths = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...paths].filter((filePath) => JSON.stringify(before[filePath]) !== JSON.stringify(after[filePath])).sort();
}

function sanitize(output: string): string {
  return String(output ?? "").split(/\r?\n/).map((line) => {
    const lowered = line.toLowerCase();
    if (!SENSITIVE.some((key) => lowered.includes(key))) return line;
    const separator = line.indexOf(":");
    const prefix = separator === -1 ? "sensitive" : line.slice(0, separator);
    return `${prefix}: ${REDACT}`;
  }).join("\n");
}

function run(command: string[], options: { encoding: null; input?: Buffer | string }): BufferResult;
function run(command: string[], options?: { encoding?: null | undefined; input?: Buffer | string }): TextResult;
function run(command: string[], options: RunOptions = {}): RunResult {
  const env = { ...process.env };
  delete env.PWN_VERIFIER_KEY;
  const result = spawnSync(command[0], command.slice(1), {
    encoding: options.encoding === null ? null : "utf8",
    input: options.input,
    env,
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  const stdout = result.stdout ?? (options.encoding === null ? Buffer.alloc(0) : "");
  const stderr = result.stderr ?? (options.encoding === null ? Buffer.alloc(0) : "");
  if (options.encoding === null) return { exitCode: result.status ?? 1, stdout: stdout as Buffer, stderr: stderr as Buffer };
  return { exitCode: result.status ?? 1, output: sanitize(`${stdout}${stderr}`) };
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

interface ChainEntry {
  sequence: number;
  timestamp: string;
  task: string;
  check: string;
  command: string[];
  exit_code: number;
  output_sha256: string;
  prev_hash: string;
  entry_hash: string;
}

const GENESIS_HASH = "0".repeat(64);

function appendEvidenceChain(task: string, check: string, command: string[], exitCode: number, output: string): ChainEntry {
  mkdirSync(LOG_DIR, { recursive: true });
  const chainPath = path.join(LOG_DIR, `${task}-chain.jsonl`);
  const entries: ChainEntry[] = [];
  if (existsSync(chainPath)) {
    try {
      const lines = readFileSync(chainPath, "utf8").trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          entries.push(JSON.parse(line));
        } catch {
          // Linha corrompida: não reseta entradas anteriores já válidas
        }
      }
    } catch {
      // ignore
    }
  }

  const prevHash = entries.length > 0 ? entries[entries.length - 1].entry_hash : GENESIS_HASH;
  const sequence = entries.length + 1;
  const timestamp = new Date().toISOString();
  const outputSha256 = sha256Hex(output);

  const entryPayload = JSON.stringify([
    prevHash,
    sequence,
    timestamp,
    task,
    check,
    command,
    exitCode,
    outputSha256,
  ]);
  const entryHash = sha256Hex(entryPayload);

  const entry: ChainEntry = {
    sequence,
    timestamp,
    task,
    check,
    command,
    exit_code: exitCode,
    output_sha256: outputSha256,
    prev_hash: prevHash,
    entry_hash: entryHash,
  };

  appendFileSync(chainPath, JSON.stringify(entry) + "\n", "utf8");
  return entry;
}

export function verifyEvidenceChain(task: string): { valid: boolean; reason?: string; headHash?: string } {
  const chainPath = path.join(LOG_DIR, `${task}-chain.jsonl`);
  if (!existsSync(chainPath)) {
    return { valid: false, reason: `cadeia de evidências não encontrada: ${chainPath}` };
  }
  try {
    const lines = readFileSync(chainPath, "utf8").trim().split("\n").filter(Boolean);
    if (!lines.length) return { valid: false, reason: "cadeia de evidências vazia" };
    let prev = GENESIS_HASH;
    const latestForCheck: Record<string, string> = {};
    for (let i = 0; i < lines.length; i++) {
      const entry: ChainEntry = JSON.parse(lines[i]);
      if (entry.sequence !== i + 1) return { valid: false, reason: `lacuna de sequência no passo ${i + 1}` };
      if (entry.prev_hash !== prev) return { valid: false, reason: `elo quebrado na cadeia no passo ${i + 1}` };
      const expectedPayload = JSON.stringify([
        entry.prev_hash,
        entry.sequence,
        entry.timestamp,
        entry.task,
        entry.check,
        entry.command,
        entry.exit_code,
        entry.output_sha256,
      ]);
      const expectedHash = sha256Hex(expectedPayload);
      if (entry.entry_hash !== expectedHash) {
        return { valid: false, reason: `hash divergente na entrada ${i + 1}` };
      }
      prev = entry.entry_hash;
      latestForCheck[entry.check.toLowerCase()] = entry.entry_hash;
    }

    // Verificar que cada log persistido no disco corresponde ao último registro de sua classe na cadeia
    for (const [checkName, expectedHash] of Object.entries(latestForCheck)) {
      const logFile = path.join(LOG_DIR, `${task}-${checkName}.log`);
      if (existsSync(logFile)) {
        const logContent = readFileSync(logFile, "utf8");
        if (!logContent.includes(`CHAIN_HASH: ${expectedHash}`)) {
          return { valid: false, reason: `log ${checkName.toUpperCase()} adulterado (CHAIN_HASH não confere com o elo da cadeia)` };
        }
      }
    }

    return { valid: true, headHash: prev };
  } catch (err) {
    return { valid: false, reason: (err as Error).message };
  }
}

function writeLog(task: string, check: string, command: string[], exitCode: number, output: string, verdict: string, extra = ""): string {
  mkdirSync(LOG_DIR, { recursive: true });
  const chainEntry = appendEvidenceChain(task, check, command, exitCode, output);
  const filePath = path.join(LOG_DIR, `${task}-${check.toLowerCase()}.log`);
  const quoted = command.map(shellQuote).join(" ");
  writeFileSync(
    filePath,
    `TASK: ${task}\nCHECK: ${check}\nCOMMAND: ${quoted}\nEXIT: ${exitCode}\nOUTPUT:\n${output}\n${extra}VERDICT: ${verdict}\nCHAIN_HASH: ${chainEntry.entry_hash}\n`,
    "utf8",
  );
  return filePath;
}

function requireCleanBaseline(paths: string[]): void {
  if (!existsSync(".git")) throw new Error("git repository required to prove implementation removal");
  const result = run(["git", "status", "--porcelain=v1", "--", ...paths]);
  if (result.exitCode !== 0) throw new Error(`git status failed: ${result.output.trim()}`);
  if (result.output.trim()) throw new Error("baseline invalid: declared files already have changes; isolate or checkpoint them first");
}

function gitHead(): string {
  const result = run(["git", "rev-parse", "--verify", "HEAD"]);
  if (result.exitCode !== 0) throw new Error("baseline exige um commit em HEAD: a remoção da implementação restaura o conteúdo a partir dele");
  return result.output.trim();
}

/** Caminho relativo à raiz do repositório no formato que `git show <rev>:<path>` aceita. */
function gitPath(filePath: string): string {
  return path.relative(process.cwd(), path.resolve(filePath)).split(path.sep).join("/");
}

function ensureDisjoint(implementation: string[], tests: string[]): void {
  const testSet = new Set(tests);
  const overlap = [...new Set(implementation)].filter((filePath) => testSet.has(filePath)).sort();
  if (overlap.length) throw new Error(`implementation/test files overlap: ${overlap.join(", ")}`);
}

/**
 * Restaura temporariamente cada arquivo de implementação ao conteúdo do baseline
 * (lido de `baseline_commit`, conferido contra o digest do baseline), executa `fn`
 * e devolve os arquivos exatamente como estavam. Arquivos que não existiam no
 * baseline são removidos durante a execução.
 */
function withoutImplementation<T>(state: EvidenceState, fn: () => T): T {
  const commit = state.baseline_commit;
  if (!commit) throw new Error("mutation check exige baseline_commit; refaça o baseline");

  const baselineContent = new Map<string, Buffer | null>();
  for (const filePath of state.implementation_files) {
    const expected = state.baseline_implementation[filePath];
    if (!expected?.exists) {
      baselineContent.set(filePath, null);
      continue;
    }
    const shown = run(["git", "show", `${commit}:${gitPath(filePath)}`], { encoding: null });
    if (shown.exitCode !== 0) throw new Error(`mutation check: ${filePath} não está versionado em ${commit.slice(0, 12)}`);
    if (sha256Hex(shown.stdout) !== expected.sha256) {
      throw new Error(`mutation check: ${filePath} em ${commit.slice(0, 12)} não corresponde ao snapshot do baseline`);
    }
    baselineContent.set(filePath, shown.stdout);
  }

  const current = new Map<string, { content: Buffer; mode: number } | null>();
  for (const filePath of state.implementation_files) {
    current.set(filePath, existsSync(filePath) ? { content: readFileSync(filePath), mode: statSync(filePath).mode } : null);
  }

  try {
    for (const [filePath, content] of baselineContent) {
      if (content === null) {
        if (existsSync(filePath)) unlinkSync(filePath);
      } else {
        mkdirSync(path.dirname(filePath), { recursive: true });
        writeFileSync(filePath, content);
      }
    }
    return fn();
  } finally {
    const failures: string[] = [];
    for (const [filePath, original] of current) {
      try {
        if (original === null) {
          if (existsSync(filePath)) unlinkSync(filePath);
        } else {
          mkdirSync(path.dirname(filePath), { recursive: true });
          writeFileSync(filePath, original.content);
          chmodSync(filePath, original.mode);
        }
      } catch (error) {
        failures.push(`${filePath}: ${(error as Error).message}`);
      }
    }
    if (failures.length) throw new Error(`DATA SAFETY: failed to restore implementation after mutation check: ${failures.join("; ")}`);
  }
}

// ── Plano e contrato ───────────────────────────────────────────────

function planPathFor(workId: string): string {
  return workId === "legacy" ? path.join(".todo", "tasks.md") : path.join(".todo", `${workId}-tasks.md`);
}

function contractVersionOf(planText: string): number {
  const match = planText.match(/^\*\*Contract version:\*\* ([1-9]\d*)$/m);
  return match ? Number(match[1]) : 1;
}

interface LoadedPlan {
  path: string;
  text: string;
  task: PlanTaskDefinition;
}

/** Lê o plano e a definição da task; ausência é pré-requisito faltando (exit 2). */
function loadPlanTask(workId: string, taskId: string): LoadedPlan {
  const planPath = planPathFor(workId);
  if (!existsSync(planPath)) {
    throw new IncompleteError([`plano do Work (plan not found: ${planPath}) — o audit amarra comandos e arquivos ao plano`]);
  }
  const text = readFileSync(planPath, "utf8");
  const task = parsePlanTask(text, taskId);
  if (!task) throw new IncompleteError([`task ${taskId} no plano ${planPath}`]);
  return { path: planPath, text, task };
}

/** Markdown derivado divergente de `plan.json`: ACs/RED editados só num dos lados. */
function planDrift(workId: string, planText: string, rootDir = process.cwd()): string | null {
  if (workId === "legacy") return null;
  const canonicalPath = path.resolve(rootDir, ".pwn", "work", workId, "plan.json");
  if (!existsSync(canonicalPath)) return null;
  const plan = loadPlan(workId, rootDir);
  if (!plan) return `DRIFT: .pwn/work/${workId}/plan.json está ilegível ou inválido`;
  if (planMatchesMarkdown(plan, planText)) return null;
  return `DRIFT: ${planPathFor(workId)} diverge de .pwn/work/${workId}/plan.json; regenere com 'pwn work plan --work ${workId} --force'`;
}

interface ContractInfo {
  id: string;
  sha256: string;
  frozenTests: FrozenTest[];
}

/** Contrato V4 da task (Works nativos com plan.json); `null` em planos só-markdown. */
function loadContractInfo(workId: string, taskId: string, rootDir = process.cwd()): ContractInfo | null {
  if (workId === "legacy") return null;
  const plan = loadPlan(workId, rootDir);
  const entry = plan?.tasks.find((task) => task.id === taskId);
  if (!entry?.contract_id) return null;
  const contractPath = path.resolve(rootDir, ".pwn", "work", workId, `${entry.contract_id}.json`);
  if (!existsSync(contractPath)) throw new Error(`contrato ${entry.contract_id} da task ${taskId} não encontrado em ${contractPath}`);
  const raw = readFileSync(contractPath);
  let parsed: { acceptance_contract?: { frozen_tests?: unknown } };
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    throw new Error(`contrato ${entry.contract_id} ilegível: ${(error as Error).message}`);
  }
  const declared = parsed.acceptance_contract?.frozen_tests;
  const frozenTests: FrozenTest[] = [];
  if (declared !== undefined) {
    if (!Array.isArray(declared)) throw new Error(`contrato ${entry.contract_id}: acceptance_contract.frozen_tests deve ser uma lista`);
    for (const item of declared) {
      const candidate = item as Partial<FrozenTest>;
      if (typeof candidate?.path !== "string" || typeof candidate.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(candidate.sha256)) {
        throw new Error(`contrato ${entry.contract_id}: frozen_tests com entrada inválida (${JSON.stringify(item)})`);
      }
      frozenTests.push({ path: candidate.path, sha256: candidate.sha256 });
    }
  }
  return { id: entry.contract_id, sha256: sha256Hex(raw), frozenTests };
}

function frozenTestViolations(frozen: FrozenTest[]): string[] {
  return frozen
    .filter((entry) => digest(entry.path).sha256 !== entry.sha256)
    .map((entry) => `teste de aceitação congelado alterado ou ausente: ${entry.path}`);
}

/**
 * Confere que a definição da task (plano + contrato) é a mesma congelada no
 * baseline. Estados anteriores ao amarramento precisam refazer o baseline.
 */
function guardDefinition(state: EvidenceState, workId: string, taskId: string): LoadedPlan {
  if (state.state_version !== STATE_VERSION || !state.task_definition_sha256) {
    throw new IncompleteError([`baseline amarrado ao plano (estado da task ${taskId} é anterior ao amarramento; refaça o baseline)`]);
  }
  const plan = loadPlanTask(workId, taskId);
  const drift = planDrift(workId, plan.text);
  if (drift) throw new Error(drift);
  if (taskDefinitionDigest(plan.text, plan.task) !== state.task_definition_sha256) {
    throw new Error(`a definição da task ${taskId} no plano mudou depois do baseline (RED, ACs, arquivos ou gates); refaça o baseline`);
  }
  const contract = loadContractInfo(workId, taskId);
  const recorded = state.contract ?? null;
  if ((contract?.id ?? null) !== (recorded?.id ?? null)
    || (contract?.sha256 ?? null) !== (recorded?.sha256 ?? null)) {
    throw new Error(`o contrato da task ${taskId} mudou depois do baseline; refaça o baseline`);
  }
  return plan;
}

function sameSet(left: string[], right: string[]): boolean {
  const a = [...new Set(left)].sort();
  const b = [...new Set(right)].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function greenDigest(state: EvidenceState): string {
  return sha256Hex(canonicalJson({ implementation: state.green_implementation ?? null, tests: state.green_tests ?? null }));
}

function signPayload(payload: unknown, key: string): string {
  return createHmac("sha256", key).update(canonicalJson(payload)).digest("hex");
}

function signatureMatches(payload: unknown, signature: unknown, key: string): boolean {
  if (typeof signature !== "string" || !/^[0-9a-f]{64}$/.test(signature)) return false;
  return timingSafeEqual(Buffer.from(signPayload(payload, key), "hex"), Buffer.from(signature, "hex"));
}

// ── Ações ──────────────────────────────────────────────────────────

function baseline(args: BaselineArgs): number {
  const plan = loadPlanTask(args.work, args.task);
  const drift = planDrift(args.work, plan.text);
  if (drift) throw new Error(drift);

  const implementation = plan.task.implementationFiles;
  const tests = plan.task.testFiles;
  const problems: string[] = [];
  if (!implementation.length) problems.push(`a task ${args.task} não declara **Implementation files:** no plano`);
  if (!tests.length) problems.push(`a task ${args.task} não declara **Test files:** no plano`);
  for (const filePath of [...implementation, ...tests]) {
    const reason = placeholderPathReason(filePath);
    if (reason) problems.push(`${filePath} ${reason}: declare arquivos concretos no plano`);
  }
  if (args.implementation.length && !sameSet(args.implementation, implementation)) {
    problems.push(`--implementation diverge do plano (plano: ${implementation.join(", ") || "—"}; operador: ${args.implementation.join(", ")})`);
  }
  if (args.tests.length && !sameSet(args.tests, tests)) {
    problems.push(`--tests diverge do plano (plano: ${tests.join(", ") || "—"}; operador: ${args.tests.join(", ")})`);
  }
  if (problems.length) return reportViolations(problems);

  ensureDisjoint(implementation, tests);
  requireCleanBaseline([...implementation, ...tests]);
  const commit = gitHead();
  for (const filePath of implementation.filter((entry) => existsSync(entry))) {
    if (run(["git", "ls-files", "--error-unmatch", "--", filePath]).exitCode !== 0) {
      throw new Error(`arquivo de implementação existe mas não está versionado: ${filePath} (o mutation check restaura a partir do commit)`);
    }
  }

  const contract = loadContractInfo(args.work, args.task);
  const frozen = contract?.frozenTests ?? [];
  const frozenOverlap = frozen.filter((entry) => implementation.includes(entry.path)).map((entry) => entry.path);
  if (frozenOverlap.length) throw new Error(`teste congelado declarado como implementação: ${frozenOverlap.join(", ")}`);
  const frozenProblems = frozenTestViolations(frozen);
  if (frozenProblems.length) return reportViolations(frozenProblems);

  const state: EvidenceState = {
    task: args.task,
    created_at: new Date().toISOString(),
    state_version: STATE_VERSION,
    baseline_commit: commit,
    plan_path: plan.path,
    task_definition_sha256: taskDefinitionDigest(plan.text, plan.task),
    contract: contract ? { id: contract.id, sha256: contract.sha256 } : null,
    frozen_tests: frozen,
    implementation_files: implementation,
    test_files: tests,
    baseline_implementation: snapshot(implementation),
    baseline_tests: snapshot(tests),
    red_tests: null,
  };
  saveState(args.task, state);
  console.log(`PASS: baseline captured for ${args.task} (arquivos e comandos amarrados a ${plan.path})`);
  return 0;
}

function red(args: RedArgs): number {
  const loaded = tryLoadState(args.task);
  if ("incomplete" in loaded) return reportIncomplete([`baseline (${loaded.incomplete})`]);
  const state = loaded.state;
  const plan = guardDefinition(state, args.work, args.task);
  if (!plan.task.red) throw new Error(`a task ${args.task} não declara comando em **RED:** no plano`);
  if (!commandMatches(plan.task.red.command, args.command)) {
    throw new Error(`RED invalid: comando diverge do plano (plano: \`${plan.task.red.command}\`; operador: \`${displayCommand(args.command)}\`)`);
  }

  const implementationChanges = changed(state.baseline_implementation, snapshot(state.implementation_files));
  if (implementationChanges.length) throw new Error(`RED invalid: implementation changed before RED: ${implementationChanges.join(", ")}`);

  const testNow = snapshot(state.test_files);
  const testChanges = changed(state.baseline_tests, testNow);
  if (!testChanges.length) throw new Error("RED invalid: no test file changed since baseline");

  const contractVersion = contractVersionOf(plan.text);
  const strict = contractVersion >= 3;
  const genericExpect = genericExpectReason(args.expect);
  if (genericExpect) {
    if (strict) {
      console.error(`FAIL: --expect genérico: ${genericExpect}`);
      return EXIT_VIOLATION;
    }
    console.error(`WARNING: --expect genérico aceito pelo contrato legado v${contractVersion}: ${genericExpect}`);
  }

  // No contrato v3 o texto esperado precisa estar escrito no teste congelado: é a
  // única forma de saber que é a asserção da task, e não qualquer linha da saída.
  const literalRequired = strict || args.expectLiteral;
  const literalInTests = !literalRequired
    || state.test_files.some((filePath) => existsSync(filePath) && readFileSync(filePath, "utf8").includes(args.expect));
  if (!literalInTests) {
    console.error("FAIL: --expect não é literal nos arquivos de teste congelados");
    return EXIT_VIOLATION;
  }

  const result = run(args.command);
  const relevant = Boolean(args.expect && result.output.includes(args.expect));
  if (result.exitCode !== 0 && relevant && isToolchainError(result.output, args.expect)) {
    if (strict) {
      const log = writeLog(args.task, "RED", args.command, result.exitCode, result.output, "FAIL");
      console.error(`FAIL: RED rejected — output matches a toolchain/environment error pattern without evidence of an assertion firing; rewrite the task so the baseline contains a compilable but incorrect implementation and the test assertion fails; evidence: ${log}`);
      return 1;
    } else {
      console.error(`WARNING: RED accepted due to legacy contract v${contractVersion}, but output matches an incidental environment failure.`);
    }
  }
  const verdict = result.exitCode !== 0 && relevant ? "PASS" : "FAIL";
  const log = writeLog(args.task, "RED", args.command, result.exitCode, result.output, verdict);
  if (verdict === "FAIL") {
    console.error(`FAIL: RED needs non-zero exit and output containing ${JSON.stringify(args.expect)}; evidence: ${log}`);
    return 1;
  }

  state.red_tests = testNow;
  state.red_command = args.command;
  state.red_expect = args.expect;
  saveState(args.task, state);
  console.log(`PASS: RED captured and tests frozen; evidence: ${log}`);
  return 0;
}

function green(args: GreenArgs): number {
  const loaded = tryLoadState(args.task);
  if ("incomplete" in loaded) return reportIncomplete([`baseline (${loaded.incomplete})`]);
  const state = loaded.state;
  if (!state.red_tests) return reportIncomplete([`RED (RED evidence not found for task ${args.task})`]);
  guardDefinition(state, args.work, args.task);
  const redCommand = state.red_command!;
  const redExpect = state.red_expect!;

  const testNow = snapshot(state.test_files);
  const testChanges = changed(state.red_tests, testNow);
  if (testChanges.length) throw new Error(`GREEN invalid: test files changed after RED: ${testChanges.join(", ")}`);

  const implementationNow = snapshot(state.implementation_files);
  const implementationChanges = changed(state.baseline_implementation, implementationNow);
  if (!implementationChanges.length) throw new Error("GREEN invalid: no implementation file changed since baseline");

  const command = args.command;
  if (JSON.stringify(command) !== JSON.stringify(redCommand)) throw new Error("GREEN invalid: command differs from RED command");
  const result = run(command);
  const relevant = !args.expect || result.output.includes(args.expect);
  if (result.exitCode !== 0 || !relevant) {
    const log = writeLog(args.task, "GREEN", command, result.exitCode, result.output, "FAIL");
    console.error(`FAIL: GREEN command did not pass expected output; evidence: ${log}`);
    return 1;
  }

  const mutation = withoutImplementation(state, () => run(command));
  if (mutation.exitCode === 0 || !mutation.output.includes(redExpect)) {
    throw new Error("mutation check failed: test still passes or no longer reports the RED assertion without implementation diff");
  }
  const extra = `MUTATION_EXIT: ${mutation.exitCode}\nMUTATION_OUTPUT:\n${mutation.output}\nMUTATION_VERDICT: PASS\n`;
  const log = writeLog(args.task, "GREEN", command, result.exitCode, result.output, "PASS", extra);

  state.green_implementation = implementationNow;
  state.green_tests = testNow;
  state.green_expect = args.expect ?? null;
  saveState(args.task, state);
  console.log(`PASS: GREEN captured with frozen tests and production diff; evidence: ${log}`);
  return 0;
}

function verify(args: VerifyArgs): number {
  const loaded = tryLoadState(args.task);
  if ("incomplete" in loaded) return reportIncomplete([`baseline (${loaded.incomplete})`]);
  const state = loaded.state;
  guardDefinition(state, args.work, args.task);
  const greenImplementation = state.green_implementation;
  const greenTests = state.green_tests;
  if (!greenImplementation || !greenTests) {
    return reportIncomplete([`GREEN (GREEN evidence not found for task ${args.task})`]);
  }
  const redCommand = state.red_command;
  if (!redCommand || !redCommand.length) {
    return reportIncomplete([`RED (comando RED não registrado no estado da task ${args.task})`]);
  }
  // O comando executado vem do operador (CLI). O comando gravado no estado é
  // apenas conferência: se divergir, a evidência não corresponde ao que se está
  // reexecutando — e um estado forjado não consegue executar nada.
  if (JSON.stringify(args.command) !== JSON.stringify(redCommand)) {
    throw new Error(`verification invalidated: command differs from RED command (estado: ${shellQuote(redCommand.join(" "))}; operador: ${shellQuote(args.command.join(" "))})`);
  }
  const testChanges = changed(greenTests, snapshot(state.test_files));
  const implementationChanges = changed(greenImplementation, snapshot(state.implementation_files));
  if (testChanges.length || implementationChanges.length) {
    const details = [];
    if (testChanges.length) details.push(`tests changed: ${testChanges.join(", ")}`);
    if (implementationChanges.length) details.push(`implementation changed: ${implementationChanges.join(", ")}`);
    throw new Error(`verification invalidated: ${details.join("; ")}`);
  }

  const result = run(args.command);
  const relevant = !state.green_expect || result.output.includes(state.green_expect);
  const verdict = result.exitCode === 0 && relevant ? "PASS" : "FAIL";
  const log = writeLog(args.task, "VERIFY", args.command, result.exitCode, result.output, verdict);
  if (verdict === "FAIL") {
    console.error(`FAIL: current focused test no longer passes; evidence: ${log}`);
    return 1;
  }
  console.log(`PASS: evidence matches working tree and focused test passes for ${args.task}; evidence: ${log}`);
  return 0;
}

function auditCheck(args: CheckArgs): number {
  if (!/^(?:AC-[1-9]\d*|VISUAL|DOCUMENTATION|LOCAL-GATES|REGRESSION)$/.test(args.name)) {
    throw new Error(`invalid audit check name: ${args.name}`);
  }
  if (!args.command.length) throw new Error("audit check command is required after --");
  if (args.expectLiteral && !args.expect) throw new Error("--expect-literal requires --expect");
  const loaded = tryLoadState(args.task);
  if ("incomplete" in loaded) return reportIncomplete([`baseline (${loaded.incomplete})`]);
  const state = loaded.state;
  if (!state.green_implementation || !state.green_tests) {
    return reportIncomplete([`GREEN (o check ${args.name} roda sobre o snapshot do GREEN da task ${args.task})`]);
  }
  const plan = guardDefinition(state, args.work, args.task);

  const drifted = [
    ...changed(state.green_implementation, snapshot(state.implementation_files)),
    ...changed(state.green_tests, snapshot(state.test_files)),
  ];
  if (drifted.length) throw new Error(`check invalidated: arquivos mudaram depois do GREEN (${drifted.join(", ")}); refaça o GREEN`);

  const allowed = allowedCheckCommands(plan.text, plan.task, args.name);
  if (allowed.error) throw new Error(allowed.error);
  if (!allowed.commands.some((command) => commandMatches(command, args.command))) {
    const expected = allowed.commands.map((command) => `\`${command}\``).join(" | ");
    throw new Error(`${args.name}: comando diverge do plano (plano: ${expected}; operador: \`${displayCommand(args.command)}\`)`);
  }

  const result = run(args.command);
  // Com `--expect-literal` a exigência é a mesma comparação verbatim na saída do comando;
  // a flag existe para simetria com `red` e para tornar a intenção explícita.
  const relevant = !args.expect || result.output.includes(args.expect);
  let verdict = result.exitCode === 0 && relevant ? "PASS" : "FAIL";
  let extra = "";
  let vacuity: AuditCheckRecord["vacuity"];
  if (verdict === "PASS" && args.name.startsWith("AC-")) {
    // Um critério de aceite que continua passando sem a implementação não aceita nada.
    const without = withoutImplementation(state, () => run(args.command));
    const passesWithout = without.exitCode === 0 && (!args.expect || without.output.includes(args.expect));
    vacuity = { exit_code: without.exitCode, verdict: passesWithout ? "FAIL" : "PASS" };
    extra = `MUTATION_EXIT: ${without.exitCode}\nMUTATION_OUTPUT:\n${without.output}\nMUTATION_VERDICT: ${vacuity.verdict}\n`;
    if (passesWithout) verdict = "FAIL";
  }
  const log = writeLog(args.task, args.name, args.command, result.exitCode, result.output, verdict, extra);
  state.audit_checks ??= {};
  state.audit_checks[args.name] = {
    command: args.command,
    expect: args.expect ?? null,
    exit_code: result.exitCode,
    verdict,
    log,
    log_sha256: digest(log).sha256,
    recorded_at: new Date().toISOString(),
    green_sha256: greenDigest(state),
    ...(vacuity ? { vacuity } : {}),
  };
  saveState(args.task, state);
  if (verdict === "FAIL") {
    if (vacuity?.verdict === "FAIL") {
      console.error(`FAIL: ${args.name} é vácuo — passa também com a implementação removida, então não prova o comportamento da task; evidence: ${log}`);
    } else {
      console.error(`FAIL: ${args.name} did not produce the expected successful result; evidence: ${log}`);
    }
    return 1;
  }
  console.log(`PASS: ${args.name} captured for ${args.work}/${args.task}; evidence: ${log}`);
  return 0;
}

function candidate(args: VerifyArgs): number {
  const verifyExit = verify(args);
  if (verifyExit !== 0) return verifyExit;
  const state = loadState(args.task);
  const plan = guardDefinition(state, args.work, args.task);

  const violations: string[] = [];
  if (!plan.task.red || !state.red_command || !commandMatches(plan.task.red.command, state.red_command)) {
    violations.push(`RED registrado não corresponde ao comando do plano (${plan.task.red?.command ?? "ausente"})`);
  }
  if (!sameSet(state.implementation_files, plan.task.implementationFiles) || !sameSet(state.test_files, plan.task.testFiles)) {
    violations.push("arquivos do baseline não correspondem aos declarados no plano");
  }
  violations.push(...frozenTestViolations(state.frozen_tests ?? []));

  const requiredNames = requiredAuditChecks(plan.task);
  const missing: string[] = [];
  const alteredLogs: string[] = [];
  const currentGreen = greenDigest(state);
  for (const name of requiredNames) {
    const check = state.audit_checks?.[name];
    if (!check || check.verdict !== "PASS") {
      missing.push(`${name} (não observado)`);
      continue;
    }
    const allowed = allowedCheckCommands(plan.text, plan.task, name);
    if (allowed.error || !allowed.commands.some((command) => commandMatches(command, check.command))) {
      violations.push(`${name}: comando registrado (\`${displayCommand(check.command)}\`) não é o declarado no plano`);
      continue;
    }
    if (check.green_sha256 !== currentGreen) {
      missing.push(`${name} (registrado sobre outro snapshot; reexecute sobre o GREEN atual)`);
      continue;
    }
    if (name.startsWith("AC-") && check.vacuity?.verdict !== "PASS") {
      missing.push(`${name} (sem prova de que falha sem a implementação)`);
      continue;
    }
    if (!existsSync(check.log)) alteredLogs.push(`log ausente após ${name}: ${check.log}`);
    else if (digest(check.log).sha256 !== check.log_sha256) alteredLogs.push(`log alterado após ${name}: ${check.log}`);
  }
  const evidenceFiles = ["red", "green", "verify"].map((check) => path.join(LOG_DIR, `${args.task}-${check}.log`));
  for (const filePath of evidenceFiles) if (!existsSync(filePath)) missing.push(`evidência ausente: ${filePath}`);

  const chainCheck = verifyEvidenceChain(args.task);
  const chainProblems = chainCheck.valid ? [] : [`cadeia de evidências (${chainCheck.reason})`];
  if (violations.length) return reportViolations(violations);
  const problems = [...missing, ...alteredLogs, ...chainProblems];
  if (problems.length) return reportIncomplete(problems);

  const evidenceDigest = createHash("sha256");
  for (const filePath of evidenceFiles) evidenceDigest.update(readFileSync(filePath));
  const subject = {
    version: ATTESTATION_VERSION,
    kind: "task-acceptance-candidate",
    harness_version: harnessManifest.version,
    gate_version: GATE_VERSION,
    work_id: args.work,
    task_id: args.task,
    result: "pass",
    plan: {
      path: plan.path,
      sha256: digest(plan.path).sha256,
      task_definition_sha256: state.task_definition_sha256,
    },
    contract: state.contract ?? null,
    baseline_commit: state.baseline_commit,
    red: { command: state.red_command, expect: state.red_expect },
    implementation: state.green_implementation,
    tests: state.green_tests,
    frozen_tests: state.frozen_tests ?? [],
    evidence_sha256: evidenceDigest.digest("hex"),
    evidence_chain_head: chainCheck.headHash ?? null,
    audit_checks: Object.fromEntries(requiredNames.map((name) => [name, state.audit_checks![name]])),
    generated_at: new Date().toISOString(),
  };
  const attestation = { ...subject, signature: signPayload(subject, getVerifierKey(process.cwd())) };
  mkdirSync(ATTESTATION_DIR, { recursive: true });
  const target = path.join(ATTESTATION_DIR, `${args.task}-candidate.json`);
  writeFileSync(target, `${JSON.stringify(attestation, null, 2)}\n`, "utf8");
  console.log(`PASS: acceptance candidate generated for ${args.work}/${args.task}: ${target}`);
  return 0;
}

/** Arquivos concretos (implementação + teste) de todas as tasks do plano. */
function planTreeFiles(planText: string): string[] {
  const files = parsePlanTasks(planText).flatMap((task) => [...task.implementationFiles, ...task.testFiles]);
  return [...new Set(files)].filter((filePath) => !placeholderPathReason(filePath)).sort();
}

function globalStatePath(): string {
  return statePath(GLOBAL_TASK);
}

function globalGatePayload(work: string, name: string, record: Omit<GlobalGateRecord, "signature">): unknown {
  return { work, name, ...record };
}

function auditGate(args: GateArgs): number {
  const match = args.name.match(/^G-([1-9]\d*)$/);
  if (!match) throw new Error(`invalid global gate name: ${args.name} (esperado G-1, G-2, ...)`);
  if (!args.command.length) throw new Error("global gate command is required after --");
  const planPath = planPathFor(args.work);
  if (!existsSync(planPath)) return reportIncomplete([`plano do Work (plan not found: ${planPath})`]);
  const planText = readFileSync(planPath, "utf8");
  const drift = planDrift(args.work, planText);
  if (drift) throw new Error(drift);
  const gates = parseGlobalGates(planText) ?? [];
  const gate = gates[Number(match[1]) - 1];
  if (!gate) throw new Error(`${args.name} não existe no plano: ## Global gates declara ${gates.length} item(ns)`);
  if (!gate.command) throw new Error(`${args.name} não declara comando executável (use crase: \`comando\`) em ## Global gates`);
  if (!commandMatches(gate.command, args.command)) {
    throw new Error(`${args.name}: comando diverge do plano (plano: \`${gate.command}\`; operador: \`${displayCommand(args.command)}\`)`);
  }

  const result = run(args.command);
  const verdict = result.exitCode === 0 ? "PASS" : "FAIL";
  const log = writeLog(GLOBAL_TASK, args.name, args.command, result.exitCode, result.output, verdict);
  const record: Omit<GlobalGateRecord, "signature"> = {
    command: args.command,
    gate_command: gate.command,
    exit_code: result.exitCode,
    verdict,
    log,
    log_sha256: digest(log).sha256,
    recorded_at: new Date().toISOString(),
    tree: snapshot(planTreeFiles(planText)),
  };
  const statePathname = globalStatePath();
  let current: GlobalGatesState = { work: args.work, gates: {} };
  if (existsSync(statePathname)) {
    try {
      current = JSON.parse(readFileSync(statePathname, "utf8")) as GlobalGatesState;
    } catch {
      current = { work: args.work, gates: {} };
    }
  }
  current.gates[args.name] = { ...record, signature: signPayload(globalGatePayload(args.work, args.name, record), getVerifierKey(process.cwd())) };
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(statePathname, `${JSON.stringify(current, null, 2)}\n`, "utf8");
  if (verdict === "FAIL") {
    console.error(`FAIL: ${args.name} (\`${gate.command}\`) falhou; evidence: ${log}`);
    return 1;
  }
  console.log(`PASS: ${args.name} captured for ${args.work}; evidence: ${log}`);
  return 0;
}

// ── Verificação para o status (somente leitura) ────────────────────

/** Resultado da conferência de uma atestação de aceitação. */
export interface AttestationStatus {
  present: boolean;
  valid: boolean;
  stale: boolean;
  reason?: string;
}

function readDigest(filePath: string, rootDir: string): FileDigest {
  const absolute = path.resolve(rootDir, filePath);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) return { exists: false, sha256: null };
  return { exists: true, sha256: sha256Hex(readFileSync(absolute)) };
}

function snapshotDiffers(recorded: unknown, rootDir: string): boolean {
  if (!recorded || typeof recorded !== "object") return true;
  return Object.entries(recorded as Snapshot).some(([filePath, expected]) => JSON.stringify(readDigest(filePath, rootDir)) !== JSON.stringify(expected));
}

/**
 * Confere a atestação de aceitação de uma task sem escrever nada: assinatura
 * HMAC com a chave do verificador, versão amarrada ao plano, definição da task
 * inalterada e arquivos iguais aos atestados (`stale` quando mudaram).
 */
export function verifyTaskAttestation(options: {
  rootDir: string;
  todoDirectory: string;
  workId: string | null;
  taskId: string;
  planText: string;
}): AttestationStatus {
  const work = options.workId ?? "legacy";
  const file = path.join(options.todoDirectory, "attestations", work, `${options.taskId}-candidate.json`);
  if (!existsSync(file)) return { present: false, valid: false, stale: false, reason: "atestação de aceitação ausente" };
  let record: Record<string, any>;
  try {
    record = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return { present: true, valid: false, stale: false, reason: "atestação ilegível" };
  }
  if (record?.version !== ATTESTATION_VERSION) {
    return { present: true, valid: false, stale: false, reason: `atestação v${record?.version ?? "?"} não amarra os ACs ao plano; regenere com 'pwn work audit candidate'` };
  }
  const key = readVerifierKey(options.rootDir);
  if (!key) return { present: true, valid: false, stale: false, reason: "chave do verificador ausente (PWN_VERIFIER_KEY ou .pwn/.verifier_key)" };
  const { signature, ...subject } = record;
  if (!signatureMatches(subject, signature, key)) return { present: true, valid: false, stale: false, reason: "assinatura da atestação inválida" };
  if (record.result !== "pass" || record.work_id !== work || record.task_id !== options.taskId) {
    return { present: true, valid: false, stale: false, reason: "atestação não corresponde a esta task" };
  }
  const drift = planDrift(work, options.planText, options.rootDir);
  if (drift) return { present: true, valid: false, stale: false, reason: drift };
  try {
    const contract = loadContractInfo(work, options.taskId, options.rootDir);
    if ((contract?.id ?? null) !== (record.contract?.id ?? null)
      || (contract?.sha256 ?? null) !== (record.contract?.sha256 ?? null)) {
      return { present: true, valid: false, stale: false, reason: "o contrato da task mudou depois da atestação" };
    }
  } catch (error) {
    return { present: true, valid: false, stale: false, reason: (error as Error).message };
  }
  const task = parsePlanTask(options.planText, options.taskId);
  if (!task || taskDefinitionDigest(options.planText, task) !== record.plan?.task_definition_sha256) {
    return { present: true, valid: false, stale: false, reason: "a definição da task mudou depois da atestação" };
  }
  const frozen = Array.isArray(record.frozen_tests) ? (record.frozen_tests as FrozenTest[]) : [];
  const stale = snapshotDiffers(record.implementation, options.rootDir)
    || snapshotDiffers(record.tests, options.rootDir)
    || frozen.some((entry) => readDigest(entry.path, options.rootDir).sha256 !== entry.sha256);
  return { present: true, valid: true, stale };
}

/** Situação da evidência de cada gate global do plano (G-1, G-2, ...). */
export interface GlobalGateEvidence {
  name: string;
  command: string | null;
  ok: boolean;
  reason?: string;
}

/**
 * Confere, sem escrever nada, a evidência assinada de cada item de
 * `## Global gates`: mesmo comando do plano, PASS, log intacto e árvore de
 * arquivos das tasks igual à do momento da execução.
 */
export function verifyGlobalGates(options: {
  rootDir: string;
  todoDirectory: string;
  workId: string | null;
  planText: string;
}): GlobalGateEvidence[] {
  const gates = parseGlobalGates(options.planText) ?? [];
  const work = options.workId ?? "legacy";
  const evidenceRoot = options.workId ? path.join(options.todoDirectory, "evidence", options.workId) : path.join(options.todoDirectory, "evidence");
  const stateFile = path.join(evidenceRoot, "state", `${GLOBAL_TASK}.json`);
  let state: GlobalGatesState | null = null;
  try {
    state = existsSync(stateFile) ? (JSON.parse(readFileSync(stateFile, "utf8")) as GlobalGatesState) : null;
  } catch {
    state = null;
  }
  const key = readVerifierKey(options.rootDir);
  const treeFiles = planTreeFiles(options.planText);
  const drift = planDrift(work, options.planText, options.rootDir);

  return gates.map((gate, index) => {
    const name = `G-${index + 1}`;
    const fail = (reason: string): GlobalGateEvidence => ({ name, command: gate.command, ok: false, reason });
    if (drift) return fail(drift);
    if (!gate.command) return fail("item sem comando executável");
    const record = state?.gates?.[name];
    if (!record) return fail("sem evidência");
    if (!key) return fail("chave do verificador ausente");
    const { signature, ...unsigned } = record;
    if (!signatureMatches(globalGatePayload(work, name, unsigned), signature, key)) return fail("assinatura inválida");
    if (record.verdict !== "PASS") return fail("última execução falhou");
    if (normalizeCommand(record.gate_command) !== normalizeCommand(gate.command)) return fail("comando do plano mudou");
    if (readDigest(record.log, options.rootDir).sha256 !== record.log_sha256) return fail("log alterado");
    const recordedFiles = Object.keys(record.tree ?? {}).sort();
    if (recordedFiles.length !== treeFiles.length || recordedFiles.some((filePath, position) => filePath !== treeFiles[position])) {
      return fail("arquivos das tasks mudaram desde a execução");
    }
    if (snapshotDiffers(record.tree, options.rootDir)) return fail("arquivos das tasks mudaram desde a execução");
    return { name, command: gate.command, ok: true };
  });
}

/**
 * Lê uma atestação de aceitação e informa se foi gerada por uma versão compatível do harness.
 * Compatível: `version` 1 (legado), 2 ou 3 (que exigem `harness_version` presente).
 * Compatibilidade de formato não é aceitação: só a v3 assinada conta como aceita
 * (ver {@link verifyTaskAttestation}).
 * Devolve `null` quando o arquivo não existe, não é JSON válido ou não declara `version` numérica.
 */
export function readAttestation(
  filePath: string,
): { version: number; harness_version: string | null; compatible: boolean } | null {
  if (!existsSync(filePath)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const record = parsed as { version?: unknown; harness_version?: unknown };
  const version = typeof record.version === "number" ? record.version : Number(record.version);
  if (!Number.isInteger(version)) return null;
  const harness_version = typeof record.harness_version === "string" && record.harness_version ? record.harness_version : null;
  return { version, harness_version, compatible: version === 1 || ((version === 2 || version === 3) && harness_version !== null) };
}

function takeOption(tokens: string[], name: string, options: { multiple: true; required?: boolean }): string[];
function takeOption(tokens: string[], name: string, options: { multiple?: false; required: true }): string;
function takeOption(tokens: string[], name: string, options?: { multiple?: false; required?: boolean }): string | null;
function takeOption(
  tokens: string[],
  name: string,
  { multiple = false, required = false }: { multiple?: boolean; required?: boolean } = {},
): string | string[] | null {
  const index = tokens.indexOf(name);
  if (index === -1) {
    if (required) throw new Error(`missing required option: ${name}`);
    return multiple ? [] : null;
  }
  if (!multiple) {
    const value = tokens[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${name}`);
    tokens.splice(index, 2);
    return value;
  }
  const values = [];
  let cursor = index + 1;
  while (cursor < tokens.length && !tokens[cursor].startsWith("--")) {
    values.push(tokens[cursor]);
    cursor += 1;
  }
  if (required && !values.length) throw new Error(`missing values for ${name}`);
  tokens.splice(index, cursor - index);
  return values;
}

/** Remove uma flag booleana (sem valor) da lista de tokens; retorna true quando estava presente. */
function takeFlag(tokens: string[], name: string): boolean {
  const index = tokens.indexOf(name);
  if (index === -1) return false;
  tokens.splice(index, 1);
  return true;
}

function usage(): void {
  console.error("usage: task_evidence.js baseline --work NNNN|legacy --task ID [--implementation PATH...] [--tests PATH...]");
  console.error("       task_evidence.js red --work NNNN|legacy --task ID --expect TEXT [--expect-literal] -- COMMAND...");
  console.error("       task_evidence.js green --work NNNN|legacy --task ID [--expect TEXT] -- COMMAND...");
  console.error("       task_evidence.js verify --work NNNN|legacy --task ID -- COMMAND...");
  console.error("       task_evidence.js check --work NNNN|legacy --task ID --name NAME [--expect TEXT] [--expect-literal] -- COMMAND...");
  console.error("       task_evidence.js candidate --work NNNN|legacy --task ID -- COMMAND...");
  console.error("       task_evidence.js gate --work NNNN|legacy --name G-N -- COMMAND...");
  console.error("O comando após `--` é sempre obrigatório e precisa ser o declarado no plano: o harness nunca executa comandos lidos do repositório.");
}

function parseArgs(argv: string[]): ParsedArgs {
  const [action, ...rest] = argv;
  if (!isAction(action)) throw new Error("unknown or missing action");
  const separator = rest.indexOf("--");
  const options = separator === -1 ? [...rest] : rest.slice(0, separator);
  const command = separator === -1 ? [] : rest.slice(separator + 1);
  const work = takeOption(options, "--work", { required: true });

  if (action === "gate") {
    configureWork(work);
    const name = takeOption(options, "--name", { required: true });
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    if (!command.length) throw new Error("GATE command is required after --");
    return { action, work, name, command };
  }

  const task = takeOption(options, "--task", { required: true });
  configureWork(work);

  if (action === "baseline") {
    const implementation = takeOption(options, "--implementation", { multiple: true });
    const tests = takeOption(options, "--tests", { multiple: true });
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    return { action, work, task, implementation, tests };
  }
  if (action === "red") {
    const expectLiteral = takeFlag(options, "--expect-literal");
    const expect = takeOption(options, "--expect", { required: true });
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    if (!command.length) throw new Error("RED command is required after --");
    return { action, work, task, expect, expectLiteral, command };
  }
  if (action === "green") {
    const expect = takeOption(options, "--expect");
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    if (!command.length) throw new Error("GREEN command is required after --");
    return { action, work, task, expect, command };
  }
  if (action === "check") {
    const expectLiteral = takeFlag(options, "--expect-literal");
    const name = takeOption(options, "--name", { required: true });
    const expect = takeOption(options, "--expect");
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    return { action, work, task, name, expect, expectLiteral, command };
  }
  if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
  // verify/candidate também exigem o comando do operador: o estado persistido é
  // conferência cruzada, nunca a fonte do que vai ser executado.
  if (!command.length) {
    throw new Error(`${action.toUpperCase()} command is required after -- (o comando RED gravado no estado não é executado)`);
  }
  return { action, work, task, command };
}

export function main(argv: string[] = process.argv.slice(2)): number {
  try {
    const args = parseArgs(argv);
    if (args.action === "baseline") return baseline(args);
    if (args.action === "red") return red(args);
    if (args.action === "green") return green(args);
    if (args.action === "check") return auditCheck(args);
    if (args.action === "candidate") return candidate(args);
    if (args.action === "gate") return auditGate(args);
    return verify(args);
  } catch (error) {
    if (error instanceof IncompleteError) return reportIncomplete(error.items);
    console.error(`FAIL: ${(error as Error).message}`);
    return EXIT_VIOLATION;
  }
}

if (isDirectEntry(import.meta.url)) {
  if (process.argv.length < 3) usage();
  process.exitCode = main();
}
