import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  applyLegacyMigration,
  listWorks,
  previewLegacyMigration,
  reserveWork,
  resolvePlanTarget,
  updateManifest,
} from "../src/core/work-manifest.js";

function fixture() {
  return mkdtempSync(path.join(tmpdir(), "work-artifacts-"));
}

test("reserves monotonically increasing Work IDs across all artifact namespaces", () => {
  const root = fixture();
  mkdirSync(path.join(root, ".prompts"), { recursive: true });
  writeFileSync(path.join(root, ".prompts", "0004-change.md"), "prompt\n");

  const first = reserveWork(root, { originType: "local" });
  assert.equal(first.work_id, "0005");
  assert.equal(first.artifacts.plan, ".todo/0005-tasks.md");
  assert.equal(first.artifacts.evidence, ".todo/evidence/0005");

  const second = reserveWork(root, { originType: "issue", originReference: "github:owner/repo#3" });
  assert.equal(second.work_id, "0006");
  assert.equal(second.origin.reference, "github:owner/repo#3");
});

test("snapshots a source and keeps the manifest as the portable reservation", () => {
  const root = fixture();
  mkdirSync(path.join(root, "docs"), { recursive: true });
  writeFileSync(path.join(root, "docs", "request.md"), "source body\n");

  const manifest = reserveWork(root, { originType: "request", sourcePath: "docs/request.md" });
  assert.equal(manifest.state, "prompt_pending");
  assert.equal(readFileSync(path.join(root, manifest.artifacts.source), "utf8"), "source body\n");
  assert.equal(existsSync(path.join(root, ".work", "0001.json")), true);
  assert.throws(() => reserveWork(root, { workId: "0001" }), /already reserved/);
});

test("resolves only explicit canonical plan targets and validates their manifests", () => {
  const root = fixture();
  const manifest = reserveWork(root);
  mkdirSync(path.join(root, ".todo"), { recursive: true });
  writeFileSync(path.join(root, manifest.artifacts.plan), "# Tasks: sample\n");
  updateManifest(root, manifest.work_id, { state: "planned" });

  assert.equal(resolvePlanTarget(root, "0001").relative, ".todo/0001-tasks.md");
  assert.equal(resolvePlanTarget(root, ".todo/0001-tasks.md").workId, "0001");
  assert.throws(() => resolvePlanTarget(root, "1"), /preserve four digits/);
  assert.throws(() => resolvePlanTarget(root, "../outside.md"), /escapes repository root/);
  assert.throws(() => resolvePlanTarget(root), /explicit plan target required/);
});

test("previews and explicitly applies a legacy layout migration", () => {
  const root = fixture();
  mkdirSync(path.join(root, ".todo", "evidence"), { recursive: true });
  writeFileSync(path.join(root, ".todo", "tasks.md"), "# Tasks: legacy\n");
  writeFileSync(path.join(root, ".todo", "evidence", "1.1-red.log"), "evidence\n");

  const preview = previewLegacyMigration(root);
  assert.equal(preview.work_id, "0001");
  assert.equal(existsSync(path.join(root, ".todo", "tasks.md")), true);
  assert.ok(preview.moves.some((move) => move.to === ".todo/0001-tasks.md"));

  const applied = applyLegacyMigration(root);
  assert.equal(applied.work_id, "0001");
  assert.equal(existsSync(path.join(root, ".todo", "tasks.md")), false);
  assert.equal(existsSync(path.join(root, ".todo", "0001-tasks.md")), true);
  assert.equal(existsSync(path.join(root, ".todo", "evidence", "0001", "1.1-red.log")), true);
  assert.equal(listWorks(root)[0].state, "planned");
});

test("lists a legacy plan explicitly without assigning a number silently", () => {
  const root = fixture();
  mkdirSync(path.join(root, ".todo"), { recursive: true });
  writeFileSync(path.join(root, ".todo", "tasks.md"), "legacy\n");
  assert.deepEqual(listWorks(root), [{ work_id: "legacy", state: "legacy", plan: ".todo/tasks.md", plan_exists: true }]);
  assert.equal(resolvePlanTarget(root, "legacy").legacy, true);
});
