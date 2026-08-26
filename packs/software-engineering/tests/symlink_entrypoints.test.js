import assert from "node:assert/strict";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const REPO = path.resolve(import.meta.dirname, "..");

function runThroughLink(script, args = []) {
  const root = mkdtempSync(path.join(tmpdir(), "skill-entrypoint-"));
  const link = path.join(root, script);
  symlinkSync(path.join(REPO, "scripts", script), link);
  return { root, result: spawnSync(process.execPath, [link, ...args], { cwd: root, encoding: "utf8" }) };
}

test("validate_tasks executes through a skill symlink", () => {
  const { result } = runThroughLink("validate_tasks.js");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: validate_tasks\.js \[--strict\] PATH \| --migrate --work NNNN \[--write\] PATH/);
});

test("work_artifacts executes through a skill symlink", () => {
  const { result } = runThroughLink("work_artifacts.js");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: work_artifacts\.js/);
});

test("validate_work_graph executes through a skill symlink", () => {
  const { result } = runThroughLink("validate_work_graph.js", ["missing-root"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /WORK GRAPH VALIDATION: FAIL/);
});

test("validate_prompt executes through a skill symlink", () => {
  const { result } = runThroughLink("validate_prompt.js");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage: validate_prompt\.js/);
});

test("validate_system_spec executes through a skill symlink", () => {
  const { result } = runThroughLink("validate_system_spec.js");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage: validate_system_spec\.js/);
});

test("task_evidence executes through a skill symlink", () => {
  const { result } = runThroughLink("task_evidence.js");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /usage: task_evidence\.js/);
  assert.match(result.stderr, /unknown or missing action/);
});

test("unattended_exec executes through a skill symlink", () => {
  const { result } = runThroughLink("unattended_exec.js");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: unattended_exec\.js/);
});

test("validate_prompt returns its exit code through a symlink", () => {
  const { root, result: usage } = runThroughLink("validate_prompt.js");
  assert.equal(usage.status, 2);
  const prompt = path.join(root, "prompt.md");
  const system = path.join(root, "system.md");
  writeFileSync(prompt, "invalid\n", "utf8");
  writeFileSync(system, "invalid\n", "utf8");
  const link = path.join(root, "validate_prompt.js");
  const result = spawnSync(process.execPath, [link, prompt, system], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PROMPT VALIDATION: FAIL/);
});
