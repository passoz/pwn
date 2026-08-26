import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { reserveWork, updateManifest } from "../scripts/work_artifacts.js";
import { validateWorkGraph } from "../scripts/validate_work_graph.js";

function root() {
  return mkdtempSync(path.join(tmpdir(), "work-graph-"));
}

function task(id, requirement, dependsOn) {
  return `### [ ] [${id}] Task ${id}

**Requirement:** ${requirement}
**Depends on:** ${dependsOn}
**Behavior:** Produce one observable result.
**Components:** node
**Files:** src/${id}.js, test/${id}.test.js
**Implementation files:** src/${id}.js
**Test files:** test/${id}.test.js

**RED:**
- \`node --test test/${id}.test.js\` — exit non-zero and names the assertion.

**Implementation:**
1. Implement the behavior.

**ACs:**
- [ ] \`node --test test/${id}.test.js\` — exit 0.

**Visual:** N/A

**Documentation:** N/A
`;
}

function createPlan(repository, workId, tasks) {
  const manifest = reserveWork(repository, { workId });
  mkdirSync(path.join(repository, ".todo"), { recursive: true });
  writeFileSync(path.join(repository, manifest.artifacts.plan), `# Tasks: ${workId}
**Contract version:** 3
**Work ID:** ${workId}

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| node | \`.\` | \`node --test\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` | \`N/A\` |

## Global gates
N/A

${tasks.join("\n")}`);
  updateManifest(repository, workId, { state: "planned" });
}

test("accepts qualified dependencies across plans in the same repository", () => {
  const repository = root();
  createPlan(repository, "0001", [task("1.1", "FR-001", "none")]);
  createPlan(repository, "0002", [task("1.1", "FR-002", "0001/1.1")]);
  assert.deepEqual(validateWorkGraph(repository).errors, []);
});

test("rejects missing qualified dependencies", () => {
  const repository = root();
  createPlan(repository, "0001", [task("1.1", "FR-001", "0009/1.1")]);
  assert.ok(validateWorkGraph(repository).errors.some((error) => error.includes("dependency not found: 0009/1.1")));
});

test("rejects dependency cycles across plans", () => {
  const repository = root();
  createPlan(repository, "0001", [task("1.1", "FR-001", "0002/1.1")]);
  createPlan(repository, "0002", [task("1.1", "FR-002", "0001/1.1")]);
  assert.ok(validateWorkGraph(repository).errors.some((error) => error.includes("dependency cycle")));
});
