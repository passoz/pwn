import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
import { verifyTaskAttestation } from "../src/core/task_evidence.js";

const PROJECT_STATUS_SCRIPT = fileURLToPath(new URL("../src/core/project_status.ts", import.meta.url));
const AUDIT = path.resolve(import.meta.dirname, "../src/core/task_evidence.ts");

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
 * Escreve a evidência TDD mínima que o status reconhece acima de BASELINE quando
 * combinada com a atestação: GREEN amarrado a snapshots vazios + log de verify PASS.
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
 * Atestação de aceitação v3 assinada com a chave do verificador do fixture, como
 * `pwn work audit candidate` a emitiria: só ela faz uma task contar como concluída.
 */
function writeAttestation(root: string, planText: string, taskId: string): void {
  writeAttestationWithSnapshots(root, planText, taskId, {});
}

/**
 * Atestação v3 assinada com snapshots explícitos de implementação/testes. O helper
 * padrão grava snapshots vazios, que nenhuma mudança de arquivo consegue invalidar;
 * este permite montar um snapshot real para exercitar o `stale` do status.
 */
function writeAttestationWithSnapshots(
  root: string,
  planText: string,
  taskId: string,
  snapshots: { implementation?: Record<string, unknown>; tests?: Record<string, unknown>; contract?: { id: string; sha256: string } },
): void {
  const key = "project-status-test-key";
  mkdirSync(path.join(root, ".pwn"), { recursive: true });
  writeFileSync(path.join(root, ".pwn", ".verifier_key"), key, "utf8");

  const task = parsePlanTask(planText, taskId);
  assert.ok(task, `task ${taskId} precisa existir no plano do fixture`);
  const subject = {
    version: 3,
    kind: "task-acceptance-candidate",
    harness_version: "0.1.0",
    gate_version: "1",
    work_id: "0001",
    task_id: taskId,
    result: "pass",
    plan: { task_definition_sha256: taskDefinitionDigest(planText, task) },
    contract: snapshots.contract ?? null,
    implementation: snapshots.implementation ?? {},
    tests: snapshots.tests ?? {},
    frozen_tests: [],
    generated_at: new Date().toISOString(),
  };
  const signature = createHmac("sha256", key).update(canonicalJson(subject)).digest("hex");
  const directory = path.join(root, ".todo", "attestations", "0001");
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, `${taskId}-candidate.json`), `${JSON.stringify({ ...subject, signature }, null, 2)}\n`, "utf8");
}

function acceptedCanonicalFixture() {
  const current = canonicalFixture();
  const checked = current.content.replace("### [ ] [1.1]", "### [x] [1.1]");
  writeFileSync(current.tasksPath, checked, "utf8");
  writeGreenEvidence(current.root, "1.1");
  writeAttestationWithSnapshots(current.root, checked, "1.1", {
    contract: { id: "CTR-001", sha256: digest(current.contractText) },
  });
  const gate = spawnSync(process.execPath, [AUDIT, "gate", "--work", "0001", "--name", "G-1", "--", process.execPath, "--version"], {
    cwd: current.root,
    encoding: "utf8",
  });
  assert.equal(gate.status, 0, gate.stderr);
  return { ...current, checked };
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
  const content = plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", " ", "FR-002", "1.1", "Reject duplicate account"),
  ]);
  const { root, tasksPath } = fixture(content);
  writeGreenEvidence(root, "1.1");
  writeAttestation(root, content, "1.1");

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
  assert.match(output, /\| `1\.1` \| \[x\] checked \|[^|]*\|[^|]*\| ACCEPTED \|/);
  assert.match(output, /\| `1\.2` \| \[ \] pending/);
});

test("a checked task with VERIFIED evidence but no signed attestation is inconsistent", () => {
  const content = plan([task("1.1", "x", "FR-001", "none", "Create account")]);
  const { root, tasksPath } = fixture(content);
  writeGreenEvidence(root, "1.1");

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "INCONSISTENT STATE");
  assert.match(report.panorama.stoppedAt, /1\.1 is checked but evidence stage is VERIFIED \(atestação de aceitação ausente\)/);
  assert.equal(report.panorama.counts.unverifiedChecked, 1);
  assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
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


test("reports completion only when all tasks carry current signed acceptance evidence", () => {
  const content = plan([
    task("1.1", "x", "FR-001", "none", "Create account"),
    task("1.2", "x", "FR-002", "1.1", "Reject duplicate account"),
  ]);
  const { root, tasksPath } = fixture(content);
  for (const id of ["1.1", "1.2"]) {
    writeGreenEvidence(root, id);
    writeAttestation(root, content, id);
  }
  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "COMPLETE");
  assert.equal(report.panorama.progress, 100);
  assert.equal(report.panorama.stoppedAt, "All tasks are checked and global gates are complete");
  assert.deepEqual(report.globalGates, { state: "N/A", detail: "N/A" });
  assert.deepEqual(report.panorama.counts, {
    total: 2,
    completed: 2,
    pending: 0,
    blocked: 0,
    stale: 0,
    unverifiedChecked: 0,
    verifiedOpen: 0,
  });
});

test("with all tasks accepted but global gates pending, the work is TASKS COMPLETE", () => {
  const content = plan(
    [task("1.1", "x", "FR-001", "none", "Create account")],
    "- [ ] `node --test` — a suíte completa passa.",
  );
  const { root, tasksPath } = fixture(content);
  writeGreenEvidence(root, "1.1");
  writeAttestation(root, content, "1.1");

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "TASKS COMPLETE");
  assert.equal(report.globalGates.state, "PENDING");
  assert.match(report.globalGates.detail, /0\/1 with evidence/);
  assert.match(report.globalGates.detail, /G-1: /);
});

test("aceita a atestação em task aberta como estado inconsistente", (t) => {
  const content = plan([task("1.1", " ", "FR-001", "none", "Create account")]);
  const { root, tasksPath } = fixture(content);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeGreenEvidence(root, "1.1");
  writeAttestation(root, content, "1.1");

  const report = collectProjectStatus(tasksPath);
  // A evidência aceita existe, mas o marcador continua aberto: o status não pode
  // tratar isso como progresso silencioso.
  assert.equal(report.panorama.state, "INCONSISTENT STATE");
  assert.match(report.panorama.stoppedAt, /1\.1 has ACCEPTED evidence but marker is not checked/);
  assert.equal(report.panorama.counts.verifiedOpen, 1);
  assert.equal(report.tasks[0].evidence.stage, "ACCEPTED");
});

test("mantém a atestação válida porém stale quando o arquivo atestado muda", (t) => {
  const content = plan([task("1.1", "x", "FR-001", "none", "Create account")]);
  const { root, tasksPath } = fixture(content);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, "src"), { recursive: true });
  const implementation = path.join(root, "src", "1.1.js");
  writeFileSync(implementation, "original\n", "utf8");
  writeGreenEvidence(root, "1.1");
  // Atestação com snapshot real: mudar o arquivo depois tem de invalidar a
  // aceitação (stale), não a assinatura.
  writeAttestationWithSnapshots(root, content, "1.1", {
    implementation: { "src/1.1.js": { exists: true, sha256: digest("original\n") } },
  });
  writeFileSync(implementation, "changed\n", "utf8");

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.tasks[0].evidence.stage, "ACCEPTED");
  assert.equal(report.panorama.state, "STALE EVIDENCE");
  assert.equal(report.panorama.counts.stale, 1);
  assert.match(renderMarkdown(report), /ACCEPTED \(STALE\)/);
});

test("prova o gate global por evidência assinada e volta a PENDING quando a árvore muda", (t) => {
  const runtime = process.execPath;
  const content = plan(
    [task("1.1", "x", "FR-001", "none", "Create account")],
    `- [ ] \`${runtime} --version\` — o build passa.`,
  );
  const { root, tasksPath } = fixture(content);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, "src"), { recursive: true });
  mkdirSync(path.join(root, "tests"), { recursive: true });
  const implementation = path.join(root, "src", "1.1.js");
  writeFileSync(implementation, "console.log('1.1');\n", "utf8");
  writeFileSync(path.join(root, "tests", "1.1.test.js"), "// teste\n", "utf8");
  writeGreenEvidence(root, "1.1");
  writeAttestation(root, content, "1.1");

  const gate = spawnSync(
    process.execPath,
    [AUDIT, "gate", "--work", "0001", "--name", "G-1", "--", runtime, "--version"],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(gate.status, 0, gate.stderr);

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.panorama.state, "COMPLETE");
  assert.equal(report.globalGates.state, "PASS");

  // O snapshot da árvore cobre os arquivos declarados no plano: alterar um deles
  // rebaixa o gate assinado mesmo com o checkbox intacto.
  writeFileSync(implementation, "console.log('alterado');\n", "utf8");
  const after = collectProjectStatus(tasksPath);
  assert.equal(after.globalGates.state, "PENDING");
  assert.match(after.globalGates.detail, /arquivos das tasks mudaram desde a execução/);
});

test("reporta gate global marcado como bloqueado", (t) => {
  const content = plan(
    [task("1.1", " ", "FR-001", "none", "Create account")],
    "- [!] `node --version` — adiado até o runtime externo ficar disponível.",
  );
  const { root, tasksPath } = fixture(content);
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const report = collectProjectStatus(tasksPath);
  assert.equal(report.globalGates.state, "BLOCKED");
  assert.match(report.globalGates.detail, /1 blocked/);
});

bunTest("plano canônico legítimo fica COMPLETE e alterações somente de checkbox preservam a aceitação", () => {
  const { root, tasksPath, checked } = acceptedCanonicalFixture();
  try {
    const verify = (planText: string) => verifyTaskAttestation({ rootDir: root, todoDirectory: path.join(root, ".todo"), workId: "0001", taskId: "1.1", planText });
    const complete = collectProjectStatus(tasksPath);
    assert.equal(complete.panorama.state, "COMPLETE");
    assert.equal(complete.globalGates.state, "PASS");
    assert.equal(complete.tasks[0].evidence.stage, "ACCEPTED");
    assert.deepEqual(complete.validationErrors, []);
    assert.equal(verify(checked).valid, true);

    const open = checked.replace("### [x] [1.1]", "### [ ] [1.1]");
    writeFileSync(tasksPath, open, "utf8");
    assert.equal(verify(open).valid, true, "checkbox não altera a definição atestada");
    const openReport = collectProjectStatus(tasksPath);
    assert.deepEqual(openReport.validationErrors, []);
    assert.equal(openReport.panorama.state, "INCONSISTENT STATE");
    assert.equal(openReport.tasks[0].evidence.stage, "ACCEPTED");

    const checkedAll = checked.replace(/^- \[ \]/gm, "- [x]");
    writeFileSync(tasksPath, checkedAll, "utf8");
    assert.equal(verify(checkedAll).valid, true);
    const afterCheckboxes = collectProjectStatus(tasksPath);
    assert.equal(afterCheckboxes.panorama.state, "COMPLETE");
    assert.equal(afterCheckboxes.globalGates.state, "PASS");
    assert.deepEqual(afterCheckboxes.validationErrors, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

for (const change of ["content", "identity", "file-removed", "binding-removed"] as const) {
  bunTest(`contrato ${change} depois da atestação invalida aceitação e impede COMPLETE`, () => {
    const { root, tasksPath, checked, canonical, canonicalPath, contractPath, contractText } = acceptedCanonicalFixture();
    try {
      assert.equal(collectProjectStatus(tasksPath).panorama.state, "COMPLETE");
      if (change === "content") {
        const contract = JSON.parse(contractText);
        contract.acceptance_contract.commands = [`${process.execPath} --help`];
        writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`, "utf8");
      } else if (change === "identity") {
        // Mesmos bytes em outro contrato: sha256 sozinho não identifica o vínculo.
        canonical.tasks[0].contract_id = "CTR-002";
        writeFileSync(path.join(path.dirname(contractPath), "CTR-002.json"), contractText, "utf8");
        writeFileSync(canonicalPath, `${JSON.stringify(canonical, null, 2)}\n`, "utf8");
        assert.equal(renderTasksMarkdown(canonical).replace("### [ ] [1.1]", "### [x] [1.1]"), checked);
      } else if (change === "file-removed") {
        rmSync(contractPath);
      } else {
        canonical.tasks[0].contract_id = "";
        writeFileSync(canonicalPath, `${JSON.stringify(canonical, null, 2)}\n`, "utf8");
        assert.equal(renderTasksMarkdown(canonical).replace("### [ ] [1.1]", "### [x] [1.1]"), checked);
      }
      const attestation = verifyTaskAttestation({ rootDir: root, todoDirectory: path.join(root, ".todo"), workId: "0001", taskId: "1.1", planText: checked });
      assert.equal(attestation.present, true);
      assert.equal(attestation.valid, false);
      assert.equal(attestation.stale, false, "mudança de contrato invalida, não apenas envelhece, a atestação");
      assert.match(attestation.reason!, /contrato.*(mudou|não encontrado)/);
      const report = collectProjectStatus(tasksPath);
      assert.equal(report.panorama.state, "INCONSISTENT STATE");
      assert.notEqual(report.panorama.state, "COMPLETE");
      assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
      assert.match(report.tasks[0].evidence.attestation!, /contrato/);
      assert.deepEqual(report.validationErrors, [], "o contrato não precisa criar drift no markdown para invalidar aceitação");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

bunTest("drift canônico e plan.json ilegível impedem COMPLETE mesmo com task e gate atestados", () => {
  const { root, tasksPath, checked, canonical, canonicalPath } = acceptedCanonicalFixture();
  try {
    const original = readFileSync(canonicalPath, "utf8");
    const changed = structuredClone(canonical);
    changed.tasks[0].acceptance_criteria[0].description = "critério canônico mudou sem regenerar markdown";
    for (const currentPlan of [JSON.stringify(changed), "{ invalid JSON\n", JSON.stringify({ tasks: null })]) {
      writeFileSync(canonicalPath, currentPlan, "utf8");
      const report = collectProjectStatus(tasksPath);
      assert.equal(report.panorama.state, "INVALID PLAN");
      assert.ok(report.validationErrors.some((error) => error.includes("DRIFT")));
      assert.equal(report.tasks[0].evidence.stage, "VERIFIED");
      assert.match(report.tasks[0].evidence.attestation!, /DRIFT/);
      assert.equal(report.globalGates.state, "PENDING");
      assert.match(report.globalGates.detail, /DRIFT/);
      const attestation = verifyTaskAttestation({ rootDir: root, todoDirectory: path.join(root, ".todo"), workId: "0001", taskId: "1.1", planText: checked });
      assert.equal(attestation.valid, false);
      assert.match(attestation.reason!, /DRIFT/);
    }
    writeFileSync(canonicalPath, original, "utf8");
    assert.equal(collectProjectStatus(tasksPath).panorama.state, "COMPLETE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

bunTest("drift é INVALID PLAN sem atestação, estado de evidência ou gates globais", () => {
  const { root, tasksPath, canonical, canonicalPath } = canonicalFixture();
  try {
    canonical.global_gates = [];
    const content = renderTasksMarkdown(canonical);
    writeFileSync(tasksPath, content, "utf8");
    writeFileSync(canonicalPath, `${JSON.stringify(canonical, null, 2)}\n`, "utf8");
    const clean = collectProjectStatus(tasksPath);
    assert.equal(clean.panorama.state, "NOT STARTED");
    assert.deepEqual(clean.validationErrors, []);
    writeFileSync(tasksPath, content.replace("a asserção ACCOUNT-RED-001 passa", "critério markdown mudou"), "utf8");
    const drifted = collectProjectStatus(tasksPath);
    assert.equal(drifted.panorama.state, "INVALID PLAN");
    assert.ok(drifted.validationErrors.some((error) => error.includes("DRIFT")));
    assert.equal(drifted.tasks[0].evidence.stage, "not started");
    writeFileSync(tasksPath, content, "utf8");
    writeFileSync(canonicalPath, "{ invalid JSON\n", "utf8");
    const unreadable = collectProjectStatus(tasksPath);
    assert.equal(unreadable.panorama.state, "INVALID PLAN");
    assert.ok(unreadable.validationErrors.some((error) => error.includes("DRIFT")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
