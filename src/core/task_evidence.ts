
import { createHash } from "node:crypto";
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
  parsePlanTask,
  placeholderPathReason,
  taskDefinitionDigest,
  type PlanTaskDefinition,
} from "./acceptance.js";
import { loadPlan, planMatchesMarkdown } from "./plan-renderer.js";

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

/** Hash of a single file at snapshot time. */
interface FileDigest {
  exists: boolean;
  sha256: string | null;
}

/** Versão do estado por task; 2 = baseline amarrado ao plano. */
const STATE_VERSION = 2;

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

const ACTIONS = ["baseline", "red", "green", "verify", "check"] as const;
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

type ParsedArgs = BaselineArgs | RedArgs | GreenArgs | CheckArgs | VerifyArgs;

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

/**
 * Cadeia de hash local: ordena os logs do diagnóstico TDD. NÃO é mecanismo de
 * aceitação — a autoridade de conclusão é o recibo do verificador independente.
 */
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
  console.error("O comando após `--` é sempre obrigatório e precisa ser o declarado no plano: o harness nunca executa comandos lidos do repositório.");
}

function parseArgs(argv: string[]): ParsedArgs {
  const [action, ...rest] = argv;
  if (!isAction(action)) throw new Error("unknown or missing action");
  const separator = rest.indexOf("--");
  const options = separator === -1 ? [...rest] : rest.slice(0, separator);
  const command = separator === -1 ? [] : rest.slice(separator + 1);
  const work = takeOption(options, "--work", { required: true });

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
