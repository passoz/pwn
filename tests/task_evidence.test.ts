import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = path.resolve(import.meta.dirname, "../src/core/task_evidence.ts");

function run(cwd: string, ...args: string[]) {
  return spawnSync(process.execPath, [script, ...args], { cwd, encoding: "utf8" });
}

function git(cwd: string, ...args: string[]) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

function commit(cwd: string, message: string): void {
  git(cwd, "add", ".");
  git(cwd, "commit", "-qm", message);
}

test("enforces immutable RED/GREEN evidence", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-"));
  git(cwd, "init", "-q");
  git(cwd, "config", "user.email", "test@example.invalid");
  git(cwd, "config", "user.name", "Test");

  const implementation = path.join(cwd, "app.js");
  const tests = path.join(cwd, "test-app.mjs");
  writeFileSync(implementation, "export const value = 'old';\n");
  writeFileSync(tests, "");
  commit(cwd, "baseline");

  writeFileSync(implementation, "export const value = 'dirty';\n");
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "dirty", "--implementation", "app.js", "--tests", "test-app.mjs").status, 1);
  writeFileSync(implementation, "export const value = 'old';\n");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.js", "--tests", "test-app.mjs").status, 0);
  writeFileSync(implementation, "export const value = 'premature';\n");
  writeFileSync(tests, "throw new Error('expected-new-behavior');\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "expected-new-behavior", "--", process.execPath, "test-app.mjs").status, 1);

  writeFileSync(implementation, "export const value = 'old';\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "expected-new-behavior", "--", process.execPath, "test-app.mjs").status, 0);
  writeFileSync(tests, "// weakened after RED\n");
  writeFileSync(implementation, "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.1", "--", process.execPath, "test-app.mjs").status, 1);

  writeFileSync(implementation, "export const value = 'old';\n");
  writeFileSync(tests, `import { value } from './app.js';\nif (value !== 'new') throw new Error('expected-new-behavior-v2');\n`);
  commit(cwd, "second baseline");
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.2", "--implementation", "app.js", "--tests", "test-app.mjs").status, 0);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.2", "--expect", "expected-new-behavior-v2", "--", process.execPath, "test-app.mjs").status, 1);

  writeFileSync(tests, `import { value } from './app.js';\nif (value !== 'new') throw new Error('expected-new-behavior-v3');\n`);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.2", "--expect", "expected-new-behavior-v3", "--", process.execPath, "test-app.mjs").status, 0);
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.2", "--", process.execPath, "test-app.mjs").status, 1);

  writeFileSync(implementation, "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.2", "--", process.execPath, "test-app.mjs").status, 0);
  const greenLog = readFileSync(path.join(cwd, ".todo/evidence/0001/1.2-green.log"), "utf8");
  assert.match(greenLog, /MUTATION_EXIT:/);
  assert.match(greenLog, /MUTATION_VERDICT: PASS/);
  assert.equal(readFileSync(implementation, "utf8"), "export const value = 'new';\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2").status, 0);
  const planDirectory = path.join(cwd, ".todo");
  writeFileSync(path.join(planDirectory, "0001-tasks.md"), `# Tasks: evidence fixture

### [x] [1.2] Implement value

**ACs:**
- [ ] \`node test-app.mjs\` — exit 0.

**Visual:** N/A

**Documentation:** N/A
`, "utf8");
  assert.equal(run(cwd, "candidate", "--work", "0001", "--task", "1.2").status, 1);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "AC-1", "--", process.execPath, "test-app.mjs").status, 0);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "REGRESSION", "--", process.execPath, "test-app.mjs").status, 0);
  assert.equal(run(cwd, "candidate", "--work", "0001", "--task", "1.2").status, 0);
  const candidate = JSON.parse(readFileSync(path.join(cwd, ".todo/attestations/0001/1.2-candidate.json"), "utf8"));
  assert.equal(candidate.work_id, "0001");
  assert.equal(candidate.task_id, "1.2");
  assert.equal(candidate.result, "pass");

  writeFileSync(implementation, "export const value = 'broken-after-green';\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2").status, 1);
  writeFileSync(implementation, "export const value = 'new';\n");
  writeFileSync(tests, "// changed after green\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2").status, 1);
});

test("supports a new implementation file during mutation checking", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-new-"));
  git(cwd, "init", "-q");
  git(cwd, "config", "user.email", "test@example.invalid");
  git(cwd, "config", "user.name", "Test");
  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  writeFileSync(path.join(cwd, "test-feature.mjs"), "");
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.3", "--implementation", "feature.js", "--tests", "test-feature.mjs").status, 0);
  writeFileSync(path.join(cwd, "test-feature.mjs"), `let value;\ntry { ({ value } = await import('./feature.js')); } catch { throw new Error('new-file-behavior'); }\nif (value !== 'created') throw new Error('new-file-behavior');\n`);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.3", "--expect", "new-file-behavior", "--", process.execPath, "test-feature.mjs").status, 0);
  writeFileSync(path.join(cwd, "feature.js"), "export const value = 'created';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.3", "--", process.execPath, "test-feature.mjs").status, 0);
  assert.equal(readFileSync(path.join(cwd, "feature.js"), "utf8"), "export const value = 'created';\n");
});

test("rejects RED whose output is exclusively a toolchain/environment error", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-toolchain-"));
  git(cwd, "init", "-q");
  git(cwd, "config", "user.email", "test@example.invalid");
  git(cwd, "config", "user.name", "Test");
  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  const impl = path.join(cwd, "app.js");
  const tests = path.join(cwd, "test-app.mjs");
  writeFileSync(impl, "export const value = 'old';\n");
  writeFileSync(tests, "");
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.js", "--tests", "test-app.mjs").status, 0);
  // create a test that references a symbol — exists but test is changed
  writeFileSync(tests, "throw new Error('cannot find main module');\n");

  // RED whose output is exclusively a toolchain pattern must be rejected
  const toolchainResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", process.execPath, "test-app.mjs");
  assert.equal(toolchainResult.status, 1, "RED must be rejected when output is exclusively a toolchain error");
  assert.match(toolchainResult.stderr, /toolchain|environment|incidental/i);

  // RED whose output contains the expect as an assertion message (not just toolchain) must be accepted
  writeFileSync(tests, "throw new Error('assertion-new-behavior: value should be X not Y');\n");
  const assertionResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "assertion-new-behavior", "--", process.execPath, "test-app.mjs");
  assert.equal(assertionResult.status, 0, "RED must be accepted when output contains assertion-driven failure message");
});

test("allows incidental RED in legacy v1/v2 plans but warns", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-legacy-red-"));
  git(cwd, "init", "-q");
  git(cwd, "config", "user.email", "test@example.invalid");
  git(cwd, "config", "user.name", "Test");
  
  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  const planPath = path.join(cwd, ".todo");
  mkdirSync(planPath);
  writeFileSync(path.join(planPath, "0001-tasks.md"), `**Contract version:** 2\n**Work ID:** 0001\n`);
  
  const impl = path.join(cwd, "app.js");
  const tests = path.join(cwd, "test-app.mjs");
  writeFileSync(impl, "export const value = 'old';\n");
  writeFileSync(tests, "");
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.js", "--tests", "test-app.mjs").status, 0);
  writeFileSync(tests, "throw new Error('cannot find main module');\n");

  const legacyResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", process.execPath, "test-app.mjs");
  assert.equal(legacyResult.status, 0, "RED must be accepted for v2 plan even if output is incidental");
  assert.match(legacyResult.stderr, /WARNING: RED accepted due to legacy contract/i);
});
