import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { test as bunTest } from "bun:test";

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalJson, parsePlanTask, taskDefinitionDigest } from "../src/core/acceptance.js";
import { collectProjectStatus, renderMarkdown } from "../src/core/project_status.js";
import { createDefaultContractV4 } from "../src/core/contract-engine.js";
import { renderTasksMarkdown, type Plan } from "../src/core/plan-renderer.js";
import { createApproval, GLOBAL_TASK_ID, type Approval } from "../src/core/acceptance-approval.js";
import { captureDependencyDigest, captureSnapshot } from "../src/core/candidate-snapshot.js";
import { buildReceipt, storeReceipt } from "../src/core/verification-receipt.js";
import { runVerification, sandboxPolicy, type VerificationRunResult } from "../src/core/verification-runner.js";
import {
  assertProtectedOutsideRepository,
  initializeVerifierHome,
  VerificationUnavailable,
} from "../src/core/verifier-home.js";
import { isBwrapSupported } from "../src/core/sandbox.js";

const PROJECT_STATUS_SCRIPT = fileURLToPath(new URL("../src/core/project_status.ts", import.meta.url));

function task(id: string, marker: string, requirement: string, dependsOn: string, title: string): string {
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

function plan(tasks: string[], global: string = "N/A"): string {
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

function fixture(content: string) {
  const root = mkdtempSync(path.join(tmpdir(), "project-status-"));
  const tasksPath = path.join(root, ".todo", "0001-tasks.md");
  mkdirSync(path.dirname(tasksPath), { recursive: true });
  writeFileSync(tasksPath, content, "utf8");
  return { root, tasksPath };
}

function canonicalFixture() {
  const runtime = process.execPath;
  const canonical: Plan = {
    work_id: "0001",
    title: "Project canônico",
    components: [{ name: "backend", root: ".", regression: `${runtime} test`, lint: "N/A", build: "N/A", security: "N/A", dev: "N/A", health: "N/A", purpose: "fixture do status" }],
    global_gates: [`\`${runtime} --version\` — o runtime responde.`],
    tasks: [{
      id: "1.1",
      title: "Create account",
      requirement_id: "FR-001",
      depends_on: [],
      behavior: "Create account produces one observable result.",
      components: ["backend"],
      files: ["src/1.1.js", "tests/1.1.test.js"],
      implementation_files: ["src/1.1.js"],
      test_files: ["tests/1.1.test.js"],
      red: { command: `${runtime} test tests/1.1.test.js`, description: "a asserção ACCOUNT-RED-001 falha antes da implementação" },
      implementation_steps: ["Implement only the declared observable result."],
      acceptance_criteria: [{ command: `${runtime} test tests/1.1.test.js`, description: "a asserção ACCOUNT-RED-001 passa" }],
      visual: "N/A",
      documentation: "N/A",
      spec_reference: "CAP-001",
      contract_id: "CTR-001",
      complexity: "standard",
      status: "pending",
    }],
  };
  const content = renderTasksMarkdown(canonical);
  const { root, tasksPath } = fixture(content);
  const workDir = path.join(root, ".pwn", "work", "0001");
  mkdirSync(workDir, { recursive: true });
  const canonicalPath = path.join(workDir, "plan.json");
  const contractPath = path.join(workDir, "CTR-001.json");
  const contractText = `${JSON.stringify(createDefaultContractV4("1.1", "0001", "Create account", "L3"), null, 2)}\n`;
  writeFileSync(canonicalPath, `${JSON.stringify(canonical, null, 2)}\n`, "utf8");
  writeFileSync(contractPath, contractText, "utf8");
  return { root, tasksPath, content, canonical, canonicalPath, contractPath, contractText };
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Escreve a evidência TDD local mínima: estado RED/GREEN com snapshots vazios e
 * log de verify PASS. É o que `pwn work audit` produz — diagnóstico do agente, não
 * autorização de conclusão.
 */
function writeGreenEvidence(root: string, taskId: string): void {
  const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
  const evidenceDirectory = path.join(root, ".todo", "evidence", "0001");
  mkdirSync(stateDirectory, { recursive: true });
  writeFileSync(path.join(stateDirectory, `${taskId}.json`), JSON.stringify({
    task: taskId,
    baseline_implementation: {},
    baseline_tests: {},
    red_tests: {},
    green_implementation: {},
    green_tests: {},
  }), "utf8");
  writeFileSync(path.join(evidenceDirectory, `${taskId}-verify.log`), "VERDICT: PASS\n", "utf8");
}

/**
 * Atestação v3 "forjada": o agente escreve o candidato e assina com uma chave que
 * ele mesmo controla (`.pwn/.verifier_key`). Sob a autoridade antiga isso bastava;
 * a aceitação independente não lê este arquivo — é exatamente o que se prova aqui.
 */
function writeForgedV3Attestation(root: string, planText: string, taskId: string): void {
  const key = "agent-controlled-key";
  mkdirSync(path.join(root, ".pwn"), { recursive: true });
  writeFileSync(path.join(root, ".pwn", ".verifier_key"), key, "utf8");

  const parsed = parsePlanTask(planText, taskId);
  assert.ok(parsed, `task ${taskId} precisa existir no plano do fixture`);
  const subject = {
    version: 3,
    kind: "task-acceptance-candidate",
    harness_version: "0.1.0",
    gate_version: "1",
    work_id: "0001",
    task_id: taskId,
    result: "pass",
    plan: { task_definition_sha256: taskDefinitionDigest(planText, parsed) },
    contract: null,
    implementation: {},
    tests: {},
    frozen_tests: [],
    generated_at: new Date().toISOString(),
  };
  const signature = createHmac("sha256", key).update(canonicalJson(subject)).digest("hex");
  const directory = path.join(root, ".todo", "attestations", "0001");
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, `${taskId}-candidate.json`), `${JSON.stringify({ ...subject, signature }, null, 2)}\n`, "utf8");
}

/** Raiz do verificador para casos que NÃO têm aceitação: sempre vazia e externa. */
function withNeutralVerifier<T>(fn: () => T): T {
  const dir = mkdtempSync(path.join(tmpdir(), "project-status-neutral-verifier-"));
  try {
    return withVerifierRoot(dir, fn);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withVerifierRoot<T>(dir: string, fn: () => T): T {
  const previous = process.env.PWN_VERIFIER_HOME;
  process.env.PWN_VERIFIER_HOME = dir;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.PWN_VERIFIER_HOME;
    else process.env.PWN_VERIFIER_HOME = previous;
  }
}

// ── Fixture canônica com repositório Git, contrato congelado e raiz do verificador ──

interface FixtureTaskSpec {
  id: string;
  title: string;
  requirement: string;
  contractId: string;
  testPath: string;
  implPath: string;
  testContent: string;
  /** Conteúdo commitado (baseline aprovado). */
  baselineImpl: string;
  /** Conteúdo da entrega candidata (working tree). */
  currentImpl: string;
}

function defaultTaskSpec(): FixtureTaskSpec {
  return {
    id: "1.1",
    title: "Create account",
    requirement: "FR-001",
    contractId: "CTR-001",
    testPath: "tests/1.1.test.js",
    implPath: "src/1.1.js",
    testContent: `import { expect, test } from "bun:test";\nimport { answer } from "../src/1.1.js";\ntest("answer is implemented", () => { expect(answer).toBe(2); });\n`,
    baselineImpl: `export const answer = 1;\n`,
    currentImpl: `export const answer = 2;\n`,
  };
}

function secondTaskSpec(): FixtureTaskSpec {
  return {
    id: "1.2",
    title: "Reject duplicate account",
    requirement: "FR-002",
    contractId: "CTR-002",
    testPath: "tests/1.2.test.js",
    implPath: "src/1.2.js",
    testContent: `import { expect, test } from "bun:test";\nimport { duplicate } from "../src/1.2.js";\ntest("duplicate is rejected", () => { expect(duplicate).toBe(true); });\n`,
    baselineImpl: `export const duplicate = false;\n`,
    currentImpl: `export const duplicate = true;\n`,
  };
}

interface VerifierFixture {
  root: string;
  verifierRoot: string;
  tasksPath: string;
  plan: Plan;
  markdown: string;
  specs: FixtureTaskSpec[];
}

/**
 * Repositório canônico completo: plano markdown + plan.json, contratos V4 com
 * `frozen_tests`, arquivos de implementação/teste, baseline commitado e uma raiz
 * de verificador (chaves Ed25519) FORA do repositório.
 */
function verifierFixture(specs: FixtureTaskSpec[] = [defaultTaskSpec()]): VerifierFixture {
  const root = mkdtempSync(path.join(tmpdir(), "project-status-repo-"));
  const verifierRoot = mkdtempSync(path.join(tmpdir(), "project-status-verifier-"));
  const runtime = process.execPath;
  const canonical: Plan = {
    work_id: "0001",
    title: "Project canônico",
    components: [{ name: "backend", root: ".", regression: `${runtime} test`, lint: "N/A", build: "N/A", security: "N/A", dev: "N/A", health: "N/A", purpose: "fixture do status" }],
    global_gates: [`\`${runtime} --version\` — o runtime responde.`],
    tasks: specs.map((spec) => ({
      id: spec.id,
      title: spec.title,
      requirement_id: spec.requirement,
      depends_on: [],
      behavior: `${spec.title} produces one observable result.`,
      components: ["backend"],
      files: [spec.implPath, spec.testPath],
      implementation_files: [spec.implPath],
      test_files: [spec.testPath],
      red: { command: `${runtime} test ${spec.testPath}`, description: `a asserção ${spec.id}-RED falha antes da implementação` },
      implementation_steps: ["Implement only the declared observable result."],
      acceptance_criteria: [{ command: `${runtime} test ${spec.testPath}`, description: `a asserção ${spec.id}-AC passa` }],
      visual: "N/A" as const,
      documentation: "N/A" as const,
      spec_reference: "CAP-001",
      contract_id: spec.contractId,
      complexity: "standard",
      status: "pending" as const,
    })),
  };
  const markdown = renderTasksMarkdown(canonical);
  const tasksPath = path.join(root, ".todo", "0001-tasks.md");
  mkdirSync(path.dirname(tasksPath), { recursive: true });
  writeFileSync(tasksPath, markdown, "utf8");

  const workDir = path.join(root, ".pwn", "work", "0001");
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, "plan.json"), `${JSON.stringify(canonical, null, 2)}\n`, "utf8");

  for (const spec of specs) {
    mkdirSync(path.dirname(path.join(root, spec.implPath)), { recursive: true });
    mkdirSync(path.dirname(path.join(root, spec.testPath)), { recursive: true });
    writeFileSync(path.join(root, spec.implPath), spec.baselineImpl, "utf8");
    writeFileSync(path.join(root, spec.testPath), spec.testContent, "utf8");
    const contract = createDefaultContractV4(spec.id, "0001", spec.title, "L3");
    contract.acceptance_contract.frozen_tests = [{ path: spec.testPath, sha256: digest(spec.testContent) }];
    writeFileSync(path.join(workDir, `${spec.contractId}.json`), `${JSON.stringify(contract, null, 2)}\n`, "utf8");
  }

  const git = (...args: string[]): string => {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, `git ${args.join(" ")} falhou: ${result.stderr}`);
    return result.stdout ?? "";
  };
  git("init", "-q");
  git("config", "user.email", "fixture@example.com");
  git("config", "user.name", "Fixture");
  git("add", "-A");
  git("commit", "-qm", "baseline");

  // Entrega candidata: a implementação atual difere do baseline aprovado, então os
  // checks AC provam causalidade (passam agora, falham com o baseline revertido).
  for (const spec of specs) writeFileSync(path.join(root, spec.implPath), spec.currentImpl, "utf8");

  initializeVerifierHome(verifierRoot);
  return { root, verifierRoot, tasksPath, plan: canonical, markdown, specs };
}

function cleanupFixture(fx: VerifierFixture): void {
  rmSync(fx.root, { recursive: true, force: true });
  rmSync(fx.verifierRoot, { recursive: true, force: true });
}

/** Resultado de verificação sintético com o digest da árvore atual (assinado por buildReceipt). */
function fabricatedRun(rootDir: string, approval: Approval, outcome: "pass" | "fail" = "pass"): VerificationRunResult {
  const snapshot = captureSnapshot(rootDir);
  const dependency = captureDependencyDigest(rootDir);
  const policy = sandboxPolicy(process.execPath, approval.checks.map((check) => check.command));
  const checks = approval.checks.map((check) => ({
    id: check.id,
    command: check.command,
    outcome: outcome === "pass" ? ("pass" as const) : ("fail" as const),
    exit_code: outcome === "pass" ? 0 : 1,
    output_digest: digest(`output:${check.id}:${outcome}`),
    output_tail: outcome === "pass" ? "ok" : "falha simulada",
    ...(check.require_baseline_failure
      ? { baseline: { exit_code: 1, output_digest: digest(`baseline:${check.id}`), output_tail: "assertion failed", suspect_environmental: false } }
      : {}),
  })) as VerificationRunResult["checks"];
  return {
    checks,
    snapshot_digest: snapshot.digest,
    dependency_digest: dependency.digest,
    sandbox_digest: digest(canonicalJson(policy)),
    sandbox_policy: policy,
  };
}

/** Aprova a task e grava um recibo assinado pela chave do verificador do fixture. */
function acceptTask(fx: VerifierFixture, taskId: string): Approval {
  const approval = createApproval({ rootDir: fx.root, workId: "0001", taskId, approvedBy: "verifier-test", verifierRootDir: fx.verifierRoot });
  const receipt = buildReceipt({ approval, result: fabricatedRun(fx.root, approval), verifierRootDir: fx.verifierRoot });
  storeReceipt(receipt, fx.root, fx.verifierRoot);
  return approval;
}

/** Aprova um gate global e grava o recibo assinado. */
function acceptGate(fx: VerifierFixture, gateName: string): Approval {
  const approval = createApproval({ rootDir: fx.root, workId: "0001", taskId: GLOBAL_TASK_ID, global: gateName, approvedBy: "verifier-test", verifierRootDir: fx.verifierRoot });
  const receipt = buildReceipt({ approval, result: fabricatedRun(fx.root, approval), verifierRootDir: fx.verifierRoot });
  storeReceipt(receipt, fx.root, fx.verifierRoot);
  return approval;
}

function statusWithVerifier(fx: VerifierFixture) {
  return withVerifierRoot(fx.verifierRoot, () => collectProjectStatus(fx.tasksPath));
}

// ── Parse/renderização e diagnóstico local (não dependem da autoridade antiga) ──

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
  const fx = verifierFixture([defaultTaskSpec(), secondTaskSpec()]);
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");

    const report = statusWithVerifier(fx);
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
    assert.match(output, /\| `1\.1` \| \[x\] checked \|[^|]*\|[^|]*\| ACCEPTED \|/);
    assert.match(output, /\| `1\.2` \| \[ \] pending/);
  } finally {
    cleanupFixture(fx);
  }
});

test("evidência local fabricada com atestação v3 forjada não vira ACCEPTED nem COMPLETE", () => {
  const content = plan([task("1.1", "x", "FR-001", "none", "Create account")]);
  const { root, tasksPath } = fixture(content);
  try {
    writeGreenEvidence(root, "1.1");
    writeForgedV3Attestation(root, content, "1.1");
    const forged = path.join(root, ".todo", "attestations", "0001", "1.1-candidate.json");
    assert.equal(existsSync(forged), true, "o fixture precisa ter gravado a atestação v3 forjada");

    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.notEqual(report.tasks[0].evidence.stage, "ACCEPTED");
    assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
    assert.notEqual(report.panorama.state, "COMPLETE");
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
    assert.equal(report.panorama.counts.unverifiedChecked, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a checked task with VERIFIED evidence but no independent receipt is inconsistent", () => {
  const content = plan([task("1.1", "x", "FR-001", "none", "Create account")]);
  const { root, tasksPath } = fixture(content);
  try {
    writeGreenEvidence(root, "1.1");

    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
    assert.match(report.panorama.stoppedAt, /1\.1 is checked but evidence stage is VERIFIED \(sem aprovação de aceitação independente\)/);
    assert.equal(report.panorama.counts.unverifiedChecked, 1);
    assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports checked tasks without VERIFIED evidence as inconsistent", () => {
  const { root, tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", " ", "FR-002", "1.1", "Reject duplicate account"),
  ]));
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
    assert.match(report.panorama.stoppedAt, /1\.1 is checked but evidence stage is not started/);
    assert.equal(report.panorama.counts.unverifiedChecked, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports a blocked task as the stop point", () => {
  const { root, tasksPath } = fixture(plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    "### [!] [1.2] Reject duplicate account — bloqueada: contrato externo ausente\n",
    task("1.3", " ", "FR-003", "1.2", "Notify account owner"),
  ]));
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "BLOCKED");
    assert.match(report.panorama.stoppedAt, /Blocked at 1\.2/);
    assert.equal(report.panorama.counts.blocked, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports a partial evidence stage", () => {
  const { root, tasksPath } = fixture(plan([task("1.1", " ", "FR-001", "none", "Create account")]));
  try {
    const stateDirectory = path.join(root, ".todo", "evidence", "0001", "state");
    mkdirSync(stateDirectory, { recursive: true });
    writeFileSync(path.join(stateDirectory, "1.1.json"), JSON.stringify({
      task: "1.1",
      baseline_implementation: {},
      baseline_tests: {},
      red_tests: {},
    }), "utf8");
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "IN PROGRESS");
    assert.match(report.panorama.stoppedAt, /during 1\.1 at RED/);
    assert.equal(report.tasks[0].evidence.stage, "RED");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("marks evidence stale when captured files changed", () => {
  const { root, tasksPath } = fixture(plan([task("1.1", "x", "FR-001", "none", "Create account")]));
  try {
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
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "STALE EVIDENCE");
    assert.equal(report.panorama.counts.stale, 1);
    assert.match(renderMarkdown(report), /GREEN \(STALE\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports invalid current plans without hiding tasks", () => {
  const invalid = plan([task("1.1", " ", "FR-001", "none", "Create account")]).replace("**Requirement:** FR-001\n", "");
  const { root, tasksPath } = fixture(invalid);
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "INVALID PLAN");
    assert.equal(report.tasks.length, 1);
    assert.ok(report.validationErrors.some((error) => error.includes("missing field **Requirement:**")));
    assert.match(renderMarkdown(report), /## Structural issues/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("keeps a legacy plan executable and reports compatibility warnings", () => {
  const legacy = plan([task("1.1", " ", "FR-001", "none", "Create account")])
    .replace("**Contract version:** 3\n**Work ID:** 0001\n", "")
    .replace("**Requirement:** FR-001\n", "")
    .replace("**Depends on:** none\n", "");
  const { root, tasksPath } = fixture(legacy);
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "NOT STARTED");
    assert.equal(report.artifacts.tasks.state, "compatible");
    assert.equal(report.contractVersion, 1);
    assert.deepEqual(report.validationErrors, []);
    assert.ok(report.validationWarnings.some((warning) => warning.includes("contract version is missing")));
    assert.match(renderMarkdown(report), /## Compatibility warnings/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
  const { root, tasksPath } = fixture(migrated);
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.panorama.state, "NOT STARTED");
    assert.equal(report.artifacts.tasks.state, "compatible");
    assert.equal(report.migratedFromContractVersion, 1);
    assert.ok(report.validationExceptions.some((entry) => entry.includes("implementation-files=4")));
    assert.match(renderMarkdown(report), /## Preserved legacy exceptions/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("drift é INVALID PLAN sem recibo, estado de evidência ou gates globais", () => {
  const { root, tasksPath, canonical, canonicalPath } = canonicalFixture();
  try {
    canonical.global_gates = [];
    const content = renderTasksMarkdown(canonical);
    writeFileSync(tasksPath, content, "utf8");
    writeFileSync(canonicalPath, `${JSON.stringify(canonical, null, 2)}\n`, "utf8");
    const clean = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(clean.panorama.state, "NOT STARTED");
    assert.deepEqual(clean.validationErrors, []);
    writeFileSync(tasksPath, content.replace("a asserção ACCOUNT-RED-001 passa", "critério markdown mudou"), "utf8");
    const drifted = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(drifted.panorama.state, "INVALID PLAN");
    assert.ok(drifted.validationErrors.some((error) => error.includes("DRIFT")));
    assert.equal(drifted.tasks[0].evidence.stage, "not started");
    writeFileSync(tasksPath, content, "utf8");
    writeFileSync(canonicalPath, "{ invalid JSON\n", "utf8");
    const unreadable = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(unreadable.panorama.state, "INVALID PLAN");
    assert.ok(unreadable.validationErrors.some((error) => error.includes("DRIFT")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── Autoridade de conclusão: recibo independente assinado ──

bunTest("todas as tasks e o gate global com recibo próprio deixam o panorama COMPLETE", () => {
  const fx = verifierFixture([defaultTaskSpec(), secondTaskSpec()]);
  try {
    const checked = fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]").replace("### [ ] [1.2]", "### [x] [1.2]");
    writeFileSync(fx.tasksPath, checked, "utf8");
    for (const id of ["1.1", "1.2"]) {
      writeGreenEvidence(fx.root, id);
      acceptTask(fx, id);
    }
    acceptGate(fx, "G-1");

    const report = statusWithVerifier(fx);
    assert.equal(report.panorama.state, "COMPLETE");
    assert.equal(report.panorama.progress, 100);
    assert.equal(report.panorama.stoppedAt, "All tasks are checked and global gates are complete");
    assert.equal(report.globalGates.state, "PASS");
    assert.deepEqual(report.panorama.counts, {
      total: 2,
      completed: 2,
      pending: 0,
      blocked: 0,
      stale: 0,
      unverifiedChecked: 0,
      verifiedOpen: 0,
    });
  } finally {
    cleanupFixture(fx);
  }
});

test("com todas as tasks aceitas mas gate global pendente o work é TASKS COMPLETE", () => {
  const fx = verifierFixture();
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");

    const report = statusWithVerifier(fx);
    assert.equal(report.panorama.state, "TASKS COMPLETE");
    assert.equal(report.globalGates.state, "PENDING");
    assert.match(report.globalGates.detail, /0\/1 with independent receipt/);
    assert.match(report.globalGates.detail, /G-1: /);
  } finally {
    cleanupFixture(fx);
  }
});

test("recibo válido em task aberta é estado inconsistente", () => {
  const fx = verifierFixture();
  try {
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");

    const report = statusWithVerifier(fx);
    assert.equal(report.tasks[0].evidence.stage, "ACCEPTED");
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
    assert.match(report.panorama.stoppedAt, /1\.1 has ACCEPTED evidence but marker is not checked/);
    assert.equal(report.panorama.counts.verifiedOpen, 1);
  } finally {
    cleanupFixture(fx);
  }
});

test("mudar um arquivo depois do recibo devolve a task a VERIFIED e o panorama não é COMPLETE", () => {
  const fx = verifierFixture();
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");
    acceptGate(fx, "G-1");
    assert.equal(statusWithVerifier(fx).panorama.state, "COMPLETE");

    writeFileSync(path.join(fx.root, "src", "1.1.js"), "export const answer = 3;\n", "utf8");
    const after = statusWithVerifier(fx);
    assert.equal(after.tasks[0].evidence.stage, "VERIFIED");
    assert.match(after.tasks[0].evidence.attestation!, /a árvore mudou depois da verificação independente/);
    assert.notEqual(after.panorama.state, "COMPLETE");
    assert.equal(after.panorama.state, "INCONSISTENT STATE");
    assert.equal(after.globalGates.state, "PENDING");
    assert.match(after.globalGates.detail, /a árvore mudou depois da verificação independente/);
  } finally {
    cleanupFixture(fx);
  }
});

test("recibo com assinatura inválida é recusado", () => {
  const fx = verifierFixture();
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");

    const receiptFile = path.join(fx.verifierRoot, "receipts", "0001-1.1.json");
    const receipt = JSON.parse(readFileSync(receiptFile, "utf8"));
    receipt.signature = Buffer.from("forged-signature").toString("base64");
    storeReceipt(receipt, fx.root, fx.verifierRoot);

    const report = statusWithVerifier(fx);
    assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
    assert.match(report.tasks[0].evidence.attestation!, /assinatura do recibo inválida/);
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
  } finally {
    cleanupFixture(fx);
  }
});

test("recibo assinado por outro verificador é recusado", () => {
  const fx = verifierFixture();
  const other = mkdtempSync(path.join(tmpdir(), "project-status-other-verifier-"));
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");

    // Outra raiz de verificador: aprovação e recibo copiados, mas a chave é outra.
    initializeVerifierHome(other);
    cpSync(path.join(fx.verifierRoot, "approvals"), path.join(other, "approvals"), { recursive: true });
    cpSync(path.join(fx.verifierRoot, "receipts"), path.join(other, "receipts"), { recursive: true });

    const report = withVerifierRoot(other, () => collectProjectStatus(fx.tasksPath));
    assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
    assert.match(report.tasks[0].evidence.attestation!, /recibo assinado por verificador desconhecido/);
    assert.equal(report.panorama.state, "INCONSISTENT STATE");
  } finally {
    cleanupFixture(fx);
    rmSync(other, { recursive: true, force: true });
  }
});

test("raiz do verificador dentro do repositório é recusada", () => {
  const fx = verifierFixture();
  try {
    const inside = path.join(fx.root, ".pwn-verifier");
    assert.throws(
      () => assertProtectedOutsideRepository(inside, fx.root),
      (error: unknown) => error instanceof VerificationUnavailable,
    );
    assert.throws(
      () => createApproval({ rootDir: fx.root, workId: "0001", taskId: "1.1", approvedBy: "operador", verifierRootDir: inside }),
      (error: unknown) => error instanceof VerificationUnavailable,
    );
  } finally {
    cleanupFixture(fx);
  }
});

bunTest("drift canônico e plan.json ilegível impedem COMPLETE mesmo com recibo válido", () => {
  const fx = verifierFixture();
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    acceptTask(fx, "1.1");
    acceptGate(fx, "G-1");
    assert.equal(statusWithVerifier(fx).panorama.state, "COMPLETE");

    const planPath = path.join(fx.root, ".pwn", "work", "0001", "plan.json");
    const original = readFileSync(planPath, "utf8");
    writeFileSync(planPath, "{ invalid JSON\n", "utf8");
    const report = statusWithVerifier(fx);
    assert.equal(report.panorama.state, "INVALID PLAN");
    assert.ok(report.validationErrors.some((error) => error.includes("DRIFT")));
    assert.notEqual(report.panorama.state, "COMPLETE");

    writeFileSync(planPath, original, "utf8");
    assert.equal(statusWithVerifier(fx).panorama.state, "COMPLETE");
  } finally {
    cleanupFixture(fx);
  }
});

test("reporta gate global marcado como bloqueado", () => {
  const content = plan(
    [task("1.1", " ", "FR-001", "none", "Create account")],
    "- [!] `node --version` — adiado até o runtime externo ficar disponível.",
  );
  const { root, tasksPath } = fixture(content);
  try {
    const report = withNeutralVerifier(() => collectProjectStatus(tasksPath));
    assert.equal(report.globalGates.state, "BLOCKED");
    assert.match(report.globalGates.detail, /1 blocked/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("executa a aceitação independente de verdade no sandbox e conclui a task", {
  skip: isBwrapSupported() ? false : "bwrap ausente: sem isolamento não há aceitação independente",
}, () => {
  const fx = verifierFixture();
  try {
    writeFileSync(fx.tasksPath, fx.markdown.replace("### [ ] [1.1]", "### [x] [1.1]"), "utf8");
    writeGreenEvidence(fx.root, "1.1");
    const approval = createApproval({ rootDir: fx.root, workId: "0001", taskId: "1.1", approvedBy: "verifier-test", verifierRootDir: fx.verifierRoot });
    const result = runVerification({ rootDir: fx.root, approval, timeoutSeconds: 60, verifierRootDir: fx.verifierRoot });
    assert.equal(
      result.checks.every((check) => check.outcome === "pass"),
      true,
      JSON.stringify(result.checks.map((check) => [check.id, check.outcome, check.reason])),
    );
    const receipt = buildReceipt({ approval, result, verifierRootDir: fx.verifierRoot });
    storeReceipt(receipt, fx.root, fx.verifierRoot);

    const report = statusWithVerifier(fx);
    assert.equal(report.tasks[0].evidence.stage, "ACCEPTED");
    assert.equal(report.panorama.state, "TASKS COMPLETE");
  } finally {
    cleanupFixture(fx);
  }
});
