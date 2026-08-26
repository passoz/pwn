import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { collectProjectStatus, renderMarkdown } from "../scripts/project_status.js";

const PROJECT_STATUS_SCRIPT = fileURLToPath(new URL("../scripts/project_status.js", import.meta.url));

function task(id, marker, requirement, dependsOn, title) {
  return `### [${marker}] [${id}] ${title}

**Requirement:** ${requirement}
**Depends on:** ${dependsOn}
**Behavior:** ${title} produces one observable result.
**Components:** backend
**Files:** src/${id}.js, tests/${id}.test.js
**Implementation files:** src/${id}.js
**Test files:** tests/${id}.test.js

**RED:**
- \`node --test tests/${id}.test.js\` — exit non-zero and failure names the new assertion.

**Implementation:**
1. Implement only the declared observable result.

**ACs:**
- [ ] \`node --test tests/${id}.test.js\` — exit 0 and verifies the observable result.

**Visual:** N/A

**Documentation:** N/A
`;
}

function plan(tasks, global = "N/A") {
  return `# Tasks: project
**Contract version:** 3
**Work ID:** 0001

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| backend | \`.\` | \`node --test\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` |

## Global gates
${global}

${tasks.join("\n")}`;
}

function fixture(content) {
  const root = mkdtempSync(path.join(tmpdir(), "project-status-"));
  const tasksPath = path.join(root, ".todo", "0001-tasks.md");
  mkdirSync(path.dirname(tasksPath), { recursive: true });
  writeFileSync(tasksPath, content, "utf8");
  return { root, tasksPath };
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

test("executes through the shared-skill symlink path", () => {
  const root = mkdtempSync(path.join(tmpdir(), "project-status-symlink-"));
  const link = path.join(root, "project_status.js");
  symlinkSync(PROJECT_STATUS_SCRIPT, link);
  const result = spawnSync(process.execPath, [link], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /# Work index/);
  assert.match(result.stdout, /\| Work \| State \| Plan \| Progress \| Panorama \|/);
});

test("reports all tasks and the next pending task", () => {
  const { root, tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", " ", "FR-002", "1.1", "Reject duplicate account"),
  ]));
  const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
  const evidenceDirectory = path.join(root, ".todo", "evidence", "0001");
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(path.join(stateDirectory, "1.1.json"), JSON.stringify({
    task: "1.1",
    baseline_implementation: {},
    baseline_tests: {},
    red_tests: {},
    green_implementation: {},
    green_tests: {},
  }), "utf8");
  writeFileSync(path.join(evidenceDirectory, "1.1-verify.log"), "VERDICT: PASS\n", "utf8");

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "IN PROGRESS");
  assert.match(report.panorama.stoppedAt, /Next task: 1\.2/);
  assert.deepEqual(report.panorama.counts, {
    total: 2,
    completed: 1,
    pending: 1,
    blocked: 0,
    stale: 0,
    unverifiedChecked: 0,
    verifiedOpen: 0,
  });
  assert.equal(report.contractVersion, 3);
  assert.deepEqual(report.validationWarnings, []);
  assert.deepEqual(report.validationExceptions, []);
  const output = renderMarkdown(report);
  assert.match(output, /\| `1\.1` \| \[x\] checked/);
  assert.match(output, /\| `1\.2` \| \[ \] pending/);
});

test("reports checked tasks without VERIFIED evidence as inconsistent", () => {
  const { tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", " ", "FR-002", "1.1", "Reject duplicate account"),
  ]));
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "INCONSISTENT STATE");
  assert.match(report.panorama.stoppedAt, /1\.1 is checked but evidence stage is not started/);
  assert.equal(report.panorama.counts.unverifiedChecked, 1);
});

test("reports a blocked task as the stop point", () => {
  const { tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    "### [!] [1.2] Reject duplicate account — bloqueada: contrato externo ausente\n",
    task("1.3", " ", "FR-003", "1.2", "Notify account owner"),
  ]));
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "BLOCKED");
  assert.match(report.panorama.stoppedAt, /Blocked at 1\.2/);
  assert.equal(report.panorama.counts.blocked, 1);
});

test("reports a partial evidence stage", () => {
  const { root, tasksPath } = fixture(plan([task("1.1", " ", "FR-001", "none", "Create account")]));
  const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(path.join(stateDirectory, "1.1.json"), JSON.stringify({
    task: "1.1",
    baseline_implementation: {},
    baseline_tests: {},
    red_tests: {},
  }), "utf8");
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "IN PROGRESS");
  assert.match(report.panorama.stoppedAt, /during 1\.1 at RED/);
  assert.equal(report.tasks[0].evidence.stage, "RED");
});

test("marks evidence stale when captured files changed", () => {
  const { root, tasksPath } = fixture(plan([task("1.1", "x", "FR-001", "none", "Create account")]));
  const implementation = path.join(root, "implementation.js");
  const tests = path.join(root, "implementation.test.js");
  writeFileSync(implementation, "changed\n", "utf8");
  writeFileSync(tests, "test\n", "utf8");
  const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(path.join(stateDirectory, "1.1.json"), JSON.stringify({
    task: "1.1",
    baseline_implementation: {},
    baseline_tests: {},
    red_tests: { [tests]: { exists: true, sha256: digest("test\n") } },
    green_implementation: { [implementation]: { exists: true, sha256: digest("original\n") } },
    green_tests: { [tests]: { exists: true, sha256: digest("test\n") } },
  }), "utf8");
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "STALE EVIDENCE");
  assert.equal(report.panorama.counts.stale, 1);
  assert.match(renderMarkdown(report), /GREEN \(STALE\)/);
});

test("reports invalid current plans without hiding tasks", () => {
  const invalid = plan([task("1.1", " ", "FR-001", "none", "Create account")]).replace("**Requirement:** FR-001\n", "");
  const { tasksPath } = fixture(invalid);
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "INVALID PLAN");
  assert.equal(report.tasks.length, 1);
  assert.ok(report.validationErrors.some((error) => error.includes("missing field **Requirement:**")));
  assert.match(renderMarkdown(report), /## Structural issues/);
});


test("keeps a legacy plan executable and reports compatibility warnings", () => {
  const legacy = plan([task("1.1", " ", "FR-001", "none", "Create account")])
    .replace("**Contract version:** 3\n**Work ID:** 0001\n", "")
    .replace("**Requirement:** FR-001\n", "")
    .replace("**Depends on:** none\n", "");
  const { tasksPath } = fixture(legacy);
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "NOT STARTED");
  assert.equal(report.artifacts.tasks.state, "compatible");
  assert.equal(report.contractVersion, 1);
  assert.deepEqual(report.validationErrors, []);
  assert.ok(report.validationWarnings.some((warning) => warning.includes("contract version is missing")));
  assert.match(renderMarkdown(report), /## Compatibility warnings/);
});

test("reports exact exceptions preserved by a migrated legacy plan", () => {
  const migrated = plan([task("1.1", " ", "FR-001", "none", "Create account")])
    .replace("**Contract version:** 3\n**Work ID:** 0001", "**Contract version:** 3\n**Migrated from task contract:** 1\n**Work ID:** 0001")
    .replace("**Depends on:** none", "**Depends on:** none\n**Legacy allowances:** implementation-files=4")
    .replace(
      "**Files:** src/1.1.js, tests/1.1.test.js",
      "**Files:** src/1.1.js, src/a.js, src/b.js, src/c.js, tests/1.1.test.js",
    )
    .replace("**Implementation files:** src/1.1.js", "**Implementation files:** src/1.1.js, src/a.js, src/b.js, src/c.js");
  const { tasksPath } = fixture(migrated);
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "NOT STARTED");
  assert.equal(report.artifacts.tasks.state, "compatible");
  assert.equal(report.migratedFromContractVersion, 1);
  assert.ok(report.validationExceptions.some((entry) => entry.includes("implementation-files=4")));
  assert.match(renderMarkdown(report), /## Preserved legacy exceptions/);
});


test("reports completion only when all tasks are checked with current VERIFIED evidence", () => {
  const { root, tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", "x", "FR-002", "1.1", "Reject duplicate account"),
  ]));
  const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
  const evidenceDirectory = path.join(root, ".todo", "evidence", "0001");
  mkdirSync(stateDirectory, { recursive: true });
  for (const id of ["1.1", "1.2"]) {
    writeFileSync(path.join(stateDirectory, `${id}.json`), JSON.stringify({
      task: id,
      baseline_implementation: {},
      baseline_tests: {},
      red_tests: {},
      green_implementation: {},
      green_tests: {},
    }), "utf8");
    writeFileSync(path.join(evidenceDirectory, `${id}-verify.log`), "VERDICT: PASS\n", "utf8");
  }
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "COMPLETE");
  assert.equal(report.panorama.progress, 100);
  assert.equal(report.panorama.stoppedAt, "All tasks are checked and global gates are complete");
  assert.deepEqual(report.globalGates, { state: "N/A", detail: "N/A" });
});
