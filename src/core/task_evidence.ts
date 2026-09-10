
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

let STATE_DIR;
let LOG_DIR;
let ATTESTATION_DIR;
const REDACT = "[REDACTED]";
const SENSITIVE = ["authorization", "token", "password", "passwd", "cookie", "api_key", "apikey", "secret"];

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
export function isToolchainError(output, expect) {
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

function configureWork(workId) {
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

function digest(filePath) {
  if (!existsSync(filePath)) return { exists: false, sha256: null };
  if (!statSync(filePath).isFile()) throw new Error(`not a regular file: ${filePath}`);
  return { exists: true, sha256: createHash("sha256").update(readFileSync(filePath)).digest("hex") };
}

function snapshot(paths) {
  return Object.fromEntries(paths.map((filePath) => [filePath, digest(filePath)]));
}

function statePath(task) {
  return path.join(STATE_DIR, `${task}.json`);
}

function loadState(task) {
  const filePath = statePath(task);
  if (!existsSync(filePath)) throw new Error(`baseline not found for task ${task}; run baseline first`);
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function saveState(task, state) {
  mkdirSync(STATE_DIR, { recursive: true });
  const ordered = Object.fromEntries(Object.keys(state).sort().map((key) => [key, state[key]]));
  writeFileSync(statePath(task), `${JSON.stringify(ordered, null, 2)}\n`, "utf8");
}

function changed(before, after) {
  const paths = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...paths].filter((filePath) => JSON.stringify(before[filePath]) !== JSON.stringify(after[filePath])).sort();
}

function sanitize(output) {
  return String(output ?? "").split(/\r?\n/).map((line) => {
    const lowered = line.toLowerCase();
    if (!SENSITIVE.some((key) => lowered.includes(key))) return line;
    const separator = line.indexOf(":");
    const prefix = separator === -1 ? "sensitive" : line.slice(0, separator);
    return `${prefix}: ${REDACT}`;
  }).join("\n");
}

function run(command, options = {}) {
  const result = spawnSync(command[0], command.slice(1), {
    encoding: options.encoding === null ? null : "utf8",
    input: options.input,
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  const stdout = result.stdout ?? (options.encoding === null ? Buffer.alloc(0) : "");
  const stderr = result.stderr ?? (options.encoding === null ? Buffer.alloc(0) : "");
  if (options.encoding === null) return { exitCode: result.status ?? 1, stdout, stderr };
  return { exitCode: result.status ?? 1, output: sanitize(`${stdout}${stderr}`) };
}

function shellQuote(value) {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function writeLog(task, check, command, exitCode, output, verdict, extra = "") {
  mkdirSync(LOG_DIR, { recursive: true });
  const filePath = path.join(LOG_DIR, `${task}-${check.toLowerCase()}.log`);
  const quoted = command.map(shellQuote).join(" ");
  writeFileSync(
    filePath,
    `TASK: ${task}\nCHECK: ${check}\nCOMMAND: ${quoted}\nEXIT: ${exitCode}\nOUTPUT:\n${output}\n${extra}VERDICT: ${verdict}\n`,
    "utf8",
  );
  return filePath;
}

function requireCleanBaseline(paths) {
  if (!existsSync(".git")) throw new Error("git repository required to prove implementation removal");
  const result = run(["git", "status", "--porcelain=v1", "--", ...paths]);
  if (result.exitCode !== 0) throw new Error(`git status failed: ${result.output.trim()}`);
  if (result.output.trim()) throw new Error("baseline invalid: declared files already have changes; isolate or checkpoint them first");
}

function mutationCheck(paths, baseline, command, expect) {
  const trackedPaths = paths.filter((filePath) => baseline[filePath].exists);
  const newPaths = paths.filter((filePath) => !baseline[filePath].exists);
  const newContents = new Map(newPaths.map((filePath) => [filePath, [readFileSync(filePath), statSync(filePath).mode]]));
  let patch = Buffer.alloc(0);

  if (trackedPaths.length) {
    const tracked = run(["git", "ls-files", "--error-unmatch", "--", ...trackedPaths]);
    if (tracked.exitCode !== 0) throw new Error("mutation check requires baseline implementation files tracked by Git");
    const diff = run(["git", "diff", "--binary", "HEAD", "--", ...trackedPaths], { encoding: null });
    if (diff.exitCode !== 0) throw new Error("mutation check could not capture implementation diff");
    patch = diff.stdout;
  }

  if (patch.length === 0 && newPaths.length === 0) throw new Error("mutation check could not capture implementation diff");

  if (patch.length) {
    const removed = run(
      ["git", "apply", "--reverse", "--binary", "--whitespace=nowarn", "-"],
      { encoding: null, input: patch },
    );
    if (removed.exitCode !== 0) {
      throw new Error(`mutation check could not remove implementation diff: ${sanitize(removed.stderr.toString("utf8"))}`);
    }
  }
  for (const filePath of newPaths) unlinkSync(filePath);

  let mutationResult = { exitCode: 127, output: "mutation command did not execute" };
  let restoreError = "";
  try {
    mutationResult = run(command);
  } finally {
    if (patch.length) {
      const reapplied = run(
        ["git", "apply", "--binary", "--whitespace=nowarn", "-"],
        { encoding: null, input: patch },
      );
      if (reapplied.exitCode !== 0) restoreError = sanitize(reapplied.stderr.toString("utf8"));
    }
    for (const [filePath, [content, mode]] of newContents) {
      mkdirSync(path.dirname(filePath), { recursive: true });
      writeFileSync(filePath, content);
      chmodSync(filePath, mode);
    }
    if (restoreError) throw new Error(`DATA SAFETY: failed to restore implementation diff after mutation check: ${restoreError}`);
  }

  if (mutationResult.exitCode === 0 || !mutationResult.output.includes(expect)) {
    throw new Error("mutation check failed: test still passes or no longer reports the RED assertion without implementation diff");
  }
  return mutationResult;
}

function ensureDisjoint(implementation, tests) {
  const testSet = new Set(tests);
  const overlap = [...new Set(implementation)].filter((filePath) => testSet.has(filePath)).sort();
  if (overlap.length) throw new Error(`implementation/test files overlap: ${overlap.join(", ")}`);
}

function baseline(args) {
  ensureDisjoint(args.implementation, args.tests);
  requireCleanBaseline([...args.implementation, ...args.tests]);
  const state = {
    task: args.task,
    created_at: new Date().toISOString(),
    implementation_files: args.implementation,
    test_files: args.tests,
    baseline_implementation: snapshot(args.implementation),
    baseline_tests: snapshot(args.tests),
    red_tests: null,
  };
  saveState(args.task, state);
  console.log(`PASS: baseline captured for ${args.task}`);
  return 0;
}

function getContractVersion(workId) {
  const planPath = workId === "legacy" ? path.join(".todo", "tasks.md") : path.join(".todo", `${workId}-tasks.md`);
  if (!existsSync(planPath)) return 3;
  const text = readFileSync(planPath, "utf8");
  const match = text.match(/^\*\*Contract version:\*\* ([1-9]\d*)$/m);
  return match ? Number(match[1]) : 1;
}

function red(args) {
  const state = loadState(args.task);
  const implementationChanges = changed(state.baseline_implementation, snapshot(state.implementation_files));
  if (implementationChanges.length) throw new Error(`RED invalid: implementation changed before RED: ${implementationChanges.join(", ")}`);

  const testNow = snapshot(state.test_files);
  const testChanges = changed(state.baseline_tests, testNow);
  if (!testChanges.length) throw new Error("RED invalid: no test file changed since baseline");

  const result = run(args.command);
  const relevant = Boolean(args.expect && result.output.includes(args.expect));
  if (result.exitCode !== 0 && relevant && isToolchainError(result.output, args.expect)) {
    const contractVersion = getContractVersion(args.work);
    if (contractVersion >= 3) {
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

function green(args) {
  const state = loadState(args.task);
  if (!state.red_tests) throw new Error(`RED evidence not found for task ${args.task}`);

  const testNow = snapshot(state.test_files);
  const testChanges = changed(state.red_tests, testNow);
  if (testChanges.length) throw new Error(`GREEN invalid: test files changed after RED: ${testChanges.join(", ")}`);

  const implementationNow = snapshot(state.implementation_files);
  const implementationChanges = changed(state.baseline_implementation, implementationNow);
  if (!implementationChanges.length) throw new Error("GREEN invalid: no implementation file changed since baseline");

  const command = args.command?.length ? args.command : state.red_command;
  if (JSON.stringify(command) !== JSON.stringify(state.red_command)) throw new Error("GREEN invalid: command differs from RED command");
  const result = run(command);
  const relevant = !args.expect || result.output.includes(args.expect);
  const assertionRan = !result.output.includes(state.red_expect);
  if (result.exitCode !== 0 || !relevant || !assertionRan) {
    const log = writeLog(args.task, "GREEN", command, result.exitCode, result.output, "FAIL");
    console.error(`FAIL: GREEN command did not pass expected output; evidence: ${log}`);
    return 1;
  }

  const mutation = mutationCheck(state.implementation_files, state.baseline_implementation, command, state.red_expect);
  const extra = `MUTATION_EXIT: ${mutation.exitCode}\nMUTATION_OUTPUT:\n${mutation.output}\nMUTATION_VERDICT: PASS\n`;
  const log = writeLog(args.task, "GREEN", command, result.exitCode, result.output, "PASS", extra);

  state.green_implementation = implementationNow;
  state.green_tests = testNow;
  state.green_expect = args.expect ?? null;
  saveState(args.task, state);
  console.log(`PASS: GREEN captured with frozen tests and production diff; evidence: ${log}`);
  return 0;
}

function verify(args) {
  const state = loadState(args.task);
  if (!state.green_implementation) throw new Error(`GREEN evidence not found for task ${args.task}`);
  const testChanges = changed(state.green_tests, snapshot(state.test_files));
  const implementationChanges = changed(state.green_implementation, snapshot(state.implementation_files));
  if (testChanges.length || implementationChanges.length) {
    const details = [];
    if (testChanges.length) details.push(`tests changed: ${testChanges.join(", ")}`);
    if (implementationChanges.length) details.push(`implementation changed: ${implementationChanges.join(", ")}`);
    throw new Error(`verification invalidated: ${details.join("; ")}`);
  }

  const result = run(state.red_command);
  const relevant = !state.green_expect || result.output.includes(state.green_expect);
  const assertionRan = !result.output.includes(state.red_expect);
  const verdict = result.exitCode === 0 && relevant && assertionRan ? "PASS" : "FAIL";
  const log = writeLog(args.task, "VERIFY", state.red_command, result.exitCode, result.output, verdict);
  if (verdict === "FAIL") {
    console.error(`FAIL: current focused test no longer passes; evidence: ${log}`);
    return 1;
  }
  console.log(`PASS: evidence matches working tree and focused test passes for ${args.task}; evidence: ${log}`);
  return 0;
}

function auditCheck(args) {
  if (!/^(?:AC-[1-9]\d*|VISUAL|DOCUMENTATION|LOCAL-GATES|REGRESSION)$/.test(args.name)) {
    throw new Error(`invalid audit check name: ${args.name}`);
  }
  if (!args.command.length) throw new Error("audit check command is required after --");
  const state = loadState(args.task);
  const result = run(args.command);
  const relevant = !args.expect || result.output.includes(args.expect);
  const verdict = result.exitCode === 0 && relevant ? "PASS" : "FAIL";
  const log = writeLog(args.task, args.name, args.command, result.exitCode, result.output, verdict);
  state.audit_checks ??= {};
  state.audit_checks[args.name] = {
    command: args.command,
    expect: args.expect ?? null,
    exit_code: result.exitCode,
    verdict,
    log,
    log_sha256: digest(log).sha256,
    recorded_at: new Date().toISOString(),
  };
  saveState(args.task, state);
  if (verdict === "FAIL") {
    console.error(`FAIL: ${args.name} did not produce the expected successful result; evidence: ${log}`);
    return 1;
  }
  console.log(`PASS: ${args.name} captured for ${args.work}/${args.task}; evidence: ${log}`);
  return 0;
}

function taskAuditRequirements(planText, taskId) {
  const heading = new RegExp(`^### \\[([ x!])\\] \\[${taskId.replace(".", "\\.")}\\] `, "m");
  const match = heading.exec(planText);
  if (!match) throw new Error(`task not found in plan: ${taskId}`);
  const blockStart = match.index;
  const remainder = planText.slice(blockStart);
  const next = remainder.slice(1).search(/^### /m);
  const block = next === -1 ? remainder : remainder.slice(0, next + 1);
  const acSection = block.match(/\*\*ACs:\*\*\n([\s\S]*?)(?=\n\*\*[^*]+:\*\*|$)/)?.[1] ?? "";
  const acCount = [...acSection.matchAll(/^- \[[ x!]\] `[^`]+`/gm)].length;
  return {
    required: [
      ...Array.from({ length: acCount }, (_, index) => `AC-${index + 1}`),
      ...(block.includes("**Visual:** REQUIRED") ? ["VISUAL"] : []),
      ...(block.includes("**Documentation:** REQUIRED") ? ["DOCUMENTATION"] : []),
      "REGRESSION",
    ],
  };
}

function candidate(args) {
  const verifyExit = verify(args);
  if (verifyExit !== 0) return verifyExit;
  const state = loadState(args.task);
  const planPath = args.work === "legacy" ? path.join(".todo", "tasks.md") : path.join(".todo", `${args.work}-tasks.md`);
  if (!existsSync(planPath)) throw new Error(`plan not found: ${planPath}`);
  const auditRequirements = taskAuditRequirements(readFileSync(planPath, "utf8"), args.task);
  for (const name of auditRequirements.required) {
    const check = state.audit_checks?.[name];
    if (!check || check.verdict !== "PASS") throw new Error(`acceptance candidate requires observed PASS for ${name}`);
    if (!existsSync(check.log) || digest(check.log).sha256 !== check.log_sha256) throw new Error(`acceptance evidence changed after ${name}: ${check.log}`);
  }
  const evidenceFiles = ["red", "green", "verify"].map((check) => path.join(LOG_DIR, `${args.task}-${check}.log`));
  for (const filePath of evidenceFiles) if (!existsSync(filePath)) throw new Error(`evidence missing: ${filePath}`);
  const evidenceDigest = createHash("sha256");
  for (const filePath of evidenceFiles) evidenceDigest.update(readFileSync(filePath));
  const subject = {
    version: 1,
    kind: "task-acceptance-candidate",
    work_id: args.work,
    task_id: args.task,
    result: "pass",
    plan: { path: planPath, sha256: digest(planPath).sha256 },
    implementation: state.green_implementation,
    tests: state.green_tests,
    evidence_sha256: evidenceDigest.digest("hex"),
    audit_checks: Object.fromEntries(auditRequirements.required.map((name) => [name, state.audit_checks[name]])),
    generated_at: new Date().toISOString(),
  };
  mkdirSync(ATTESTATION_DIR, { recursive: true });
  const target = path.join(ATTESTATION_DIR, `${args.task}-candidate.json`);
  writeFileSync(target, `${JSON.stringify(subject, null, 2)}\n`, "utf8");
  console.log(`PASS: acceptance candidate generated for ${args.work}/${args.task}: ${target}`);
  return 0;
}

function takeOption(tokens, name, { multiple = false, required = false } = {}) {
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

function usage() {
  console.error("usage: task_evidence.js baseline --work NNNN|legacy --task ID --implementation PATH... --tests PATH...");
  console.error("       task_evidence.js red --work NNNN|legacy --task ID --expect TEXT -- COMMAND...");
  console.error("       task_evidence.js green --work NNNN|legacy --task ID [--expect TEXT] [-- COMMAND...]");
  console.error("       task_evidence.js verify --work NNNN|legacy --task ID");
  console.error("       task_evidence.js check --work NNNN|legacy --task ID --name NAME [--expect TEXT] -- COMMAND...");
  console.error("       task_evidence.js candidate --work NNNN|legacy --task ID");
}

function parseArgs(argv) {
  const [action, ...rest] = argv;
  if (!action || !["baseline", "red", "green", "verify", "check", "candidate"].includes(action)) throw new Error("unknown or missing action");
  const separator = rest.indexOf("--");
  const options = separator === -1 ? [...rest] : rest.slice(0, separator);
  const command = separator === -1 ? [] : rest.slice(separator + 1);
  const work = takeOption(options, "--work", { required: true });
  const task = takeOption(options, "--task", { required: true });
  configureWork(work);

  if (action === "baseline") {
    const implementation = takeOption(options, "--implementation", { multiple: true, required: true });
    const tests = takeOption(options, "--tests", { multiple: true, required: true });
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    return { action, work, task, implementation, tests };
  }
  if (action === "red") {
    const expect = takeOption(options, "--expect", { required: true });
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    if (!command.length) throw new Error("RED command is required after --");
    return { action, work, task, expect, command };
  }
  if (action === "green") {
    const expect = takeOption(options, "--expect");
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    return { action, work, task, expect, command };
  }
  if (action === "check") {
    const name = takeOption(options, "--name", { required: true });
    const expect = takeOption(options, "--expect");
    if (options.length) throw new Error(`unexpected arguments: ${options.join(" ")}`);
    return { action, work, task, name, expect, command };
  }
  if (options.length || command.length) throw new Error(`unexpected arguments: ${[...options, ...command].join(" ")}`);
  return { action, work, task };
}

export function main(argv = process.argv.slice(2)) {
  try {
    const args = parseArgs(argv);
    if (args.action === "baseline") return baseline(args);
    if (args.action === "red") return red(args);
    if (args.action === "green") return green(args);
    if (args.action === "check") return auditCheck(args);
    if (args.action === "candidate") return candidate(args);
    return verify(args);
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    return 1;
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile)) {
  if (process.argv.length < 3) usage();
  process.exitCode = main();
}
