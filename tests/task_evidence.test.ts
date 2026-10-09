import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { test as bunTest } from "bun:test";

import { createDefaultContractV4 } from "../src/core/contract-engine.js";
import { renderTasksMarkdown, type Plan } from "../src/core/plan-renderer.js";
import { freezeAcceptanceTests } from "../src/core/task-contract.js";

const script = path.resolve(import.meta.dirname, "../src/core/task_evidence.ts");
/** Runtime que executa a suíte (bun sob `bun test`): o plano declara o mesmo caminho que o operador usa. */
const RUNTIME = process.execPath;

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

interface FixtureTask {
  id: string;
  title: string;
  implementation: string;
  test: string;
  assertion: string;
}

/**
 * Escreve o plano v3 do fixture (`.todo/0001-tasks.md`): a definição de cada task
 * — arquivos, RED e ACs — sai daqui, nunca da linha de comando do operador.
 * O gate global roda a suíte inteira; RED/AC rodam só o teste focado da task.
 */
function planFor(cwd: string, tasks: FixtureTask[]): string {
  const blocks = tasks.map((task) => `
### [ ] [${task.id}] ${task.title}

**Implementation files:** \`${task.implementation}\`

**Test files:** \`${task.test}\`

**RED:**
- \`${RUNTIME} test ${task.test}\` — a asserção ${task.assertion} falha antes da implementação.

**ACs:**
- [ ] \`${RUNTIME} test ${task.test}\` — a asserção ${task.assertion} passa com a implementação.

**Visual:** N/A

**Documentation:** N/A
`).join("\n");
  const text = `# Tasks: fixture do audit

**Contract version:** 3
**Work ID:** 0001

## Global gates
- [ ] \`${RUNTIME} test\` — a suíte completa permanece verde.

${blocks}`;
  mkdirSync(path.join(cwd, ".todo"), { recursive: true });
  writeFileSync(path.join(cwd, ".todo", "0001-tasks.md"), text, "utf8");
  return text;
}

function initRepository(cwd: string): void {
  git(cwd, "init", "-q");
  git(cwd, "config", "user.email", "test@example.invalid");
  git(cwd, "config", "user.name", "Test");
}

function focusedRun(...files: string[]): string[] {
  return [RUNTIME, "test", ...files];
}

function canonicalPlanFor(cwd: string): Plan {
  const plan: Plan = {
    work_id: "0001",
    title: "Audit canônico",
    components: [{ name: "core", purpose: "núcleo do fixture" }],
    global_gates: [`\`${RUNTIME} test\` — a suíte completa permanece verde.`],
    tasks: [{
      id: "1.1",
      title: "Implement value",
      requirement_id: "FR-001",
      depends_on: [],
      behavior: "entrega o valor novo",
      components: ["core"],
      files: ["app.js", "app.test.mjs"],
      implementation_files: ["app.js"],
      test_files: ["app.test.mjs"],
      red: { command: `${RUNTIME} test app.test.mjs`, description: "a asserção CANONICAL-RED-001 falha antes da implementação" },
      implementation_steps: ["Escrever o teste focado", "Implementar o valor novo"],
      acceptance_criteria: [{ command: `${RUNTIME} test app.test.mjs`, description: "a asserção CANONICAL-RED-001 passa" }],
      visual: "N/A",
      documentation: "N/A",
      spec_reference: "CAP-001",
      contract_id: "CTR-001",
      complexity: "standard",
      status: "pending",
    }],
  };
  const workDir = path.join(cwd, ".pwn", "work", "0001");
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
  writeFileSync(path.join(workDir, "CTR-001.json"), `${JSON.stringify(createDefaultContractV4("1.1", "0001", "Implement value", "L3"), null, 2)}\n`);
  mkdirSync(path.join(cwd, ".todo"), { recursive: true });
  writeFileSync(path.join(cwd, ".todo", "0001-tasks.md"), renderTasksMarkdown(plan));
  return plan;
}

test("enforces immutable RED/GREEN evidence", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-"));
  initRepository(cwd);

  const implementation = path.join(cwd, "app.js");
  const tests = path.join(cwd, "app.test.mjs");
  writeFileSync(implementation, "export const value = 'old';\n");
  writeFileSync(tests, "");
  planFor(cwd, [
    { id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "VALUE-NEW" },
    { id: "1.2", title: "Implement value v2", implementation: "app.js", test: "app.test.mjs", assertion: "VALUE-NEW-2" },
  ]);
  commit(cwd, "baseline");

  // baseline recusa arquivo declarado já sujo
  writeFileSync(implementation, "export const value = 'dirty';\n");
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 1);
  writeFileSync(implementation, "export const value = 'old';\n");

  // baseline é amarrado ao plano: arquivos que divergem do declarado são violação
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.js", "--tests", "other.test.mjs").status, 1);

  // os arquivos vêm do plano; o operador não precisa repeti-los
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);

  writeFileSync(implementation, "export const value = 'premature';\n");
  writeFileSync(tests, "throw new Error('expected-new-behavior');\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "expected-new-behavior", "--", ...focusedRun("app.test.mjs")).status, 1);

  writeFileSync(implementation, "export const value = 'old';\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "expected-new-behavior", "--", ...focusedRun("app.test.mjs")).status, 0);

  // GREEN exige os testes congelados pelo RED
  writeFileSync(tests, "// weakened after RED\n");
  writeFileSync(implementation, "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs")).status, 1);

  // O RED precisa do comando declarado no plano: outro comando é violação.
  writeFileSync(implementation, "export const value = 'old';\n");
  writeFileSync(tests, `import { value } from './app.js';\nif (value !== 'new') throw new Error('expected-new-behavior-v2');\n`);
  commit(cwd, "second baseline");
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.2").status, 0);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.2", "--expect", "expected-new-behavior-v2", "--", RUNTIME, "test", "other.test.mjs").status, 1);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.2", "--expect", "expected-new-behavior-v2", "--", ...focusedRun("app.test.mjs")).status, 1);

  writeFileSync(tests, `import { value } from './app.js';\nif (value !== 'new') throw new Error('expected-new-behavior-v3');\n`);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.2", "--expect", "expected-new-behavior-v3", "--", ...focusedRun("app.test.mjs")).status, 0);
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs")).status, 1);

  writeFileSync(implementation, "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs")).status, 0);
  const greenLog = readFileSync(path.join(cwd, ".todo/evidence/0001/1.2-green.log"), "utf8");
  assert.match(greenLog, /MUTATION_EXIT:/);
  assert.match(greenLog, /MUTATION_VERDICT: PASS/);
  assert.equal(readFileSync(implementation, "utf8"), "export const value = 'new';\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs")).status, 0);

  // checks exigem os comandos declarados no plano, com os comandos do plano
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "AC-1", "--", "true").status, 1);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "AC-1", "--", ...focusedRun("app.test.mjs")).status, 0);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "REGRESSION", "--", ...focusedRun("app.test.mjs")).status, 1);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.2", "--name", "REGRESSION", "--", RUNTIME, "test").status, 0);

  // As ações `candidate` e `gate` foram removidas: o uso é inválido e nenhum
  // artefato de atestação/gate é produzido.
  const removedCandidate = run(cwd, "candidate", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs"));
  assert.equal(removedCandidate.status, 1);
  assert.match(removedCandidate.stderr, /unknown or missing action/);
  const removedGate = run(cwd, "gate", "--work", "0001", "--name", "G-1", "--", RUNTIME, "test");
  assert.equal(removedGate.status, 1);
  assert.match(removedGate.stderr, /unknown or missing action/);
  assert.equal(existsSync(path.join(cwd, ".todo/attestations")), false, "a ação removida não grava atestação");

  writeFileSync(implementation, "export const value = 'broken-after-green';\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs")).status, 1);
  writeFileSync(implementation, "export const value = 'new';\n");
  writeFileSync(tests, "// changed after green\n");
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.2", "--", ...focusedRun("app.test.mjs")).status, 1);
});

test("supports a new implementation file during mutation checking", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-new-"));
  initRepository(cwd);
  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  writeFileSync(path.join(cwd, "feature.test.mjs"), "");
  planFor(cwd, [
    { id: "1.3", title: "Create feature", implementation: "feature.js", test: "feature.test.mjs", assertion: "new-file-behavior" },
  ]);
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.3").status, 0);
  // O import dinâmico é o ponto do teste: `feature.js` ainda não existe no RED e só a
  // implementação nova o cria; import estático não compilaria antes da implementação.
  writeFileSync(path.join(cwd, "feature.test.mjs"), `let value;\ntry { ({ value } = await import('./feature.js')); } catch { throw new Error('new-file-behavior'); }\nif (value !== 'created') throw new Error('new-file-behavior');\n`);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.3", "--expect", "new-file-behavior", "--", ...focusedRun("feature.test.mjs")).status, 0);
  writeFileSync(path.join(cwd, "feature.js"), "export const value = 'created';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.3", "--", ...focusedRun("feature.test.mjs")).status, 0);
  assert.equal(readFileSync(path.join(cwd, "feature.js"), "utf8"), "export const value = 'created';\n");
});

test("rejects RED whose output is exclusively a toolchain/environment error", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-toolchain-"));
  initRepository(cwd);
  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  const impl = path.join(cwd, "app.js");
  const tests = path.join(cwd, "app.test.mjs");
  writeFileSync(impl, "export const value = 'old';\n");
  writeFileSync(tests, "");
  planFor(cwd, [
    { id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "assertion-new-behavior" },
  ]);
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
  writeFileSync(tests, "throw new Error('cannot find main module');\n");

  // RED cuja saída é exclusivamente padrão de toolchain/ambiente precisa ser recusado
  const toolchainResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", ...focusedRun("app.test.mjs"));
  assert.equal(toolchainResult.status, 1, "RED must be rejected when output is exclusively a toolchain error");
  assert.match(toolchainResult.stderr, /toolchain|environment|incidental/i);

  // RED cuja saída traz o expect como mensagem de asserção (não só toolchain) deve ser aceito
  writeFileSync(tests, "throw new Error('assertion-new-behavior: value should be X not Y');\n");
  const assertionResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "assertion-new-behavior", "--", ...focusedRun("app.test.mjs"));
  assert.equal(assertionResult.status, 0, "RED must be accepted when output contains assertion-driven failure message");
});

test("rejects generic --expect and non-literal assertion text in v3 plans", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-expect-"));
  initRepository(cwd);
  const impl = path.join(cwd, "app.js");
  const tests = path.join(cwd, "app.test.mjs");
  writeFileSync(impl, "export const value = 'old';\n");
  writeFileSync(tests, "");
  planFor(cwd, [
    { id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "VALUE-NEW" },
  ]);
  commit(cwd, "baseline");
  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);

  writeFileSync(tests, "throw new Error('VALUE-NEW: value should change');\n");
  // marcador genérico do runner não identifica a asserção da task
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "fail", "--", ...focusedRun("app.test.mjs")).status, 1);
  // texto que não está escrito no teste congelado não prova nada
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "outra-assercao-qualquer", "--", ...focusedRun("app.test.mjs")).status, 1);
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", ...focusedRun("app.test.mjs")).status, 0);
});

test("allows incidental RED in legacy v1/v2 plans but warns", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-legacy-red-"));
  initRepository(cwd);

  writeFileSync(path.join(cwd, "package.json"), '{"type":"module"}\n');
  const planPath = path.join(cwd, ".todo");
  mkdirSync(planPath);
  writeFileSync(path.join(planPath, "0001-tasks.md"), `**Contract version:** 2
**Work ID:** 0001

### [ ] [1.1] Legacy task

**Implementation files:** \`app.js\`

**Test files:** \`app.test.mjs\`

**RED:**
- \`${RUNTIME} test app.test.mjs\` — a asserção falha antes da implementação.

**ACs:**
- [ ] \`${RUNTIME} test app.test.mjs\` — a asserção passa com a implementação.
`);

  const impl = path.join(cwd, "app.js");
  const tests = path.join(cwd, "app.test.mjs");
  writeFileSync(impl, "export const value = 'old';\n");
  writeFileSync(tests, "");
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
  writeFileSync(tests, "throw new Error('cannot find main module');\n");

  const legacyResult = run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", ...focusedRun("app.test.mjs"));
  assert.equal(legacyResult.status, 0, "RED must be accepted for v2 plan even if output is incidental");
  assert.match(legacyResult.stderr, /WARNING: RED accepted due to legacy contract/i);
});

test("estado de evidência forjado não executa nada sem definição e baseline válidos", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-forged-"));
  initRepository(cwd);

  const marker = path.join(cwd, "PWNED.txt");
  const payload = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`;
  const stateDir = path.join(cwd, ".todo/evidence/0001/state");
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(stateDir, "1.1.json"), JSON.stringify({
    task: "1.1",
    test_files: [],
    implementation_files: [],
    green_implementation: {},
    green_tests: {},
    red_command: [process.execPath, "-e", payload],
    red_expect: "never-present-string-xyz",
    green_expect: null,
  }, null, 2), "utf8");

  // Sem comando do operador: uso inválido, nada executa.
  assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.1").status, 1);
  assert.equal(existsSync(marker), false, "o comando gravado no estado NÃO pode ser executado sozinho");

  // Qualquer comando exige primeiro um baseline vinculado à definição atual.
  const different = run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", process.execPath, "-e", "0");
  assert.equal(different.status, 2);
  assert.match(different.stderr, /baseline amarrado ao plano/);
  assert.equal(existsSync(marker), false, "comando divergente do estado não pode ser aceito");

  // Mesmo o payload declarado pelo operador não legitima o estado forjado.
  const same = run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", process.execPath, "-e", payload);
  assert.equal(same.status, 2);
  assert.match(same.stderr, /baseline amarrado ao plano/);
  assert.equal(existsSync(marker), false, "nenhum comando executa sem definição válida");
});

// ── Vacuidade e congelamento ────────────────────────────────────────

test("AC que passa sem a implementação é recusado como vácuo", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-vacuo-"));
  initRepository(cwd);
  const implementation = path.join(cwd, "app.js");
  const tests = path.join(cwd, "app.test.mjs");
  writeFileSync(implementation, "export const value = 'old';\n");
  writeFileSync(tests, "");
  planFor(cwd, [
    { id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "VALUE-NEW" },
  ]);
  // AC-2 não exercita comportamento nenhum: passa com e sem a implementação.
  const planPath = path.join(cwd, ".todo", "0001-tasks.md");
  const withVacuousAc = readFileSync(planPath, "utf8").replace(
    "**Visual:** N/A",
    `- [ ] \`${RUNTIME} --version\` — o runtime responde.\n\n**Visual:** N/A`,
  );
  writeFileSync(planPath, withVacuousAc, "utf8");
  commit(cwd, "baseline");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
  writeFileSync(tests, "import { value } from './app.js';\nif (value !== 'new') throw new Error('vacuous-check-001');\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "vacuous-check-001", "--", ...focusedRun("app.test.mjs")).status, 0);
  writeFileSync(implementation, "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs")).status, 0);

  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", ...focusedRun("app.test.mjs")).status, 0);
  const vacuous = run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "AC-2", "--", RUNTIME, "--version");
  assert.equal(vacuous.status, 1);
  assert.match(vacuous.stderr, /AC-2 é vácuo/);
  assert.match(vacuous.stderr, /implementação removida/);
  const log = readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-ac-2.log"), "utf8");
  assert.match(log, /MUTATION_VERDICT: FAIL/);

  // A ação `candidate` foi removida: o uso é inválido e nenhum veredito é consumido do estado.
  const removed = run(cwd, "candidate", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
  assert.equal(removed.status, 1);
  assert.match(removed.stderr, /unknown or missing action/);
});

test("testes de aceitação congelados no contrato são exigidos no baseline", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-frozen-"));
  initRepository(cwd);

  const plan: Plan = {
    work_id: "0001",
    title: "Task congelada",
    components: [{ name: "core", purpose: "núcleo do fixture" }],
    global_gates: [`\`${RUNTIME} test\` — a suíte completa permanece verde.`],
    tasks: [
      {
        id: "1.1",
        title: "Task congelada",
        requirement_id: "FR-001",
        depends_on: [],
        behavior: "entrega o comportamento declarado",
        components: ["core"],
        files: ["app.js", "app.test.mjs", "acceptance.test.mjs"],
        implementation_files: ["app.js"],
        test_files: ["app.test.mjs"],
        red: { command: `${RUNTIME} test app.test.mjs`, description: "a asserção FOCUSED-RED-001 falha antes da implementação" },
        implementation_steps: ["Escrever o teste focado (RED)", "Implementar o mínimo para o GREEN"],
        acceptance_criteria: [{ command: `${RUNTIME} test acceptance.test.mjs`, description: "a asserção ACCEPTANCE-001 é observada no teste congelado" }],
        visual: "N/A",
        documentation: "N/A",
        spec_reference: "CAP-001",
        contract_id: "CTR-001",
        complexity: "standard",
        status: "pending",
      },
    ],
  };
  const workDir = path.join(cwd, ".pwn", "work", "0001");
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`, "utf8");
  mkdirSync(path.join(cwd, ".todo"), { recursive: true });
  const planText = renderTasksMarkdown(plan);
  writeFileSync(path.join(cwd, ".todo", "0001-tasks.md"), planText, "utf8");

  const contract = createDefaultContractV4("1.1", "0001", "Task congelada", "L3");
  contract.acceptance_contract.commands = [`${RUNTIME} test`];
  writeFileSync(path.join(workDir, "CTR-001.json"), `${JSON.stringify(contract, null, 2)}\n`, "utf8");

  writeFileSync(path.join(cwd, "app.js"), "export const value = 'old';\n");
  writeFileSync(path.join(cwd, "app.test.mjs"), "");
  writeFileSync(path.join(cwd, "acceptance.test.mjs"), `import { value } from './app.js';\nimport { expect, test } from 'bun:test';\ntest('o valor novo é observado', () => { expect(value).toBe('new'); });\n`);
  commit(cwd, "teste de aceitação aprovado");

  // Congelar exige o teste commitado e limpo
  writeFileSync(path.join(cwd, "acceptance.test.mjs"), "// alterado depois da aprovação\n");
  assert.throws(
    () => freezeAcceptanceTests({ workId: "0001", taskId: "1.1", paths: ["acceptance.test.mjs"], rootDir: cwd }),
    /commitado e sem alterações/,
  );
  git(cwd, "checkout", "--", "acceptance.test.mjs");
  const frozen = freezeAcceptanceTests({ workId: "0001", taskId: "1.1", paths: ["acceptance.test.mjs"], rootDir: cwd });
  assert.equal(frozen.frozen.length, 1);
  assert.equal(frozen.frozen[0].path, "acceptance.test.mjs");

  // Baseline recusa teste congelado alterado, mesmo fora das listas da task
  writeFileSync(path.join(cwd, "acceptance.test.mjs"), "// alterado depois de congelado\n");
  const dirtyBaseline = run(cwd, "baseline", "--work", "0001", "--task", "1.1");
  assert.equal(dirtyBaseline.status, 1);
  assert.match(dirtyBaseline.stderr, /teste de aceitação congelado alterado ou ausente: acceptance\.test\.mjs/);
  git(cwd, "checkout", "--", "acceptance.test.mjs");

  assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
  writeFileSync(path.join(cwd, "app.test.mjs"), "import { value } from './app.js';\nif (value !== 'new') throw new Error('focused-red-001');\n");
  assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "focused-red-001", "--", ...focusedRun("app.test.mjs")).status, 0);
  writeFileSync(path.join(cwd, "app.js"), "export const value = 'new';\n");
  assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs")).status, 0);

  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", ...focusedRun("acceptance.test.mjs")).status, 0);
  assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", RUNTIME, "test").status, 0);
});

bunTest("Bun imprime redExpect no nome do teste sem invalidar GREEN/VERIFY; falhas, expect e mutation continuam exigidos", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-bun-name-"));
  try {
    initRepository(cwd);
    writeFileSync(path.join(cwd, "app.js"), "export const value = 'old';\n");
    writeFileSync(path.join(cwd, "app.test.mjs"), "");
    planFor(cwd, [{ id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "BUN-NAME-RED-001" }]);
    commit(cwd, "baseline");
    assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
    writeFileSync(path.join(cwd, "app.test.mjs"), `import { expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { value } from './app.js';
test('BUN-NAME-RED-001', () => {
  expect(existsSync('force-failure')).toBe(false);
  expect(existsSync('force-vacuity') ? 'new' : value).toBe('new');
  console.log('BUN-NAME-RED-001');
  if (!existsSync('skip-success')) console.log('BUN-GREEN-SUCCESS-001');
});
`);
    assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "BUN-NAME-RED-001", "--", ...focusedRun("app.test.mjs")).status, 0);
    writeFileSync(path.join(cwd, "app.js"), "export const value = 'still-old';\n");
    const failingGreen = run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(failingGreen.status, 1, failingGreen.stderr);
    assert.match(readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-green.log"), "utf8"), /VERDICT: FAIL/);

    writeFileSync(path.join(cwd, "app.js"), "export const value = 'new';\n");
    const missingExpect = run(cwd, "green", "--work", "0001", "--task", "1.1", "--expect", "NOT-IN-SUCCESS-OUTPUT-001", "--", ...focusedRun("app.test.mjs"));
    assert.equal(missingExpect.status, 1, missingExpect.stderr);
    writeFileSync(path.join(cwd, "force-vacuity"), "force mutation to stay green\n");
    const vacuous = run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(vacuous.status, 1);
    assert.match(vacuous.stderr, /mutation check failed/);
    assert.equal(readFileSync(path.join(cwd, "app.js"), "utf8"), "export const value = 'new';\n");
    rmSync(path.join(cwd, "force-vacuity"));

    const green = run(cwd, "green", "--work", "0001", "--task", "1.1", "--expect", "BUN-GREEN-SUCCESS-001", "--", ...focusedRun("app.test.mjs"));
    assert.equal(green.status, 0, green.stderr);
    const greenLog = readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-green.log"), "utf8");
    assert.match(greenLog, /MUTATION_VERDICT: PASS/);
    const verified = run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(verified.status, 0, verified.stderr);

    writeFileSync(path.join(cwd, "skip-success"), "omit successful output\n");
    const missingVerifyExpect = run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(missingVerifyExpect.status, 1);
    assert.match(missingVerifyExpect.stderr, /current focused test no longer passes/);
    const missingVerifyLog = readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-verify.log"), "utf8");
    assert.match(missingVerifyLog, /VERDICT: FAIL/);
    rmSync(path.join(cwd, "skip-success"));

    // O comando falha sem alterar nenhum snapshot de implementação/teste.
    writeFileSync(path.join(cwd, "force-failure"), "force verify to fail\n");
    const failingVerify = run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(failingVerify.status, 1);
    assert.match(failingVerify.stderr, /current focused test no longer passes/);
    assert.match(readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-verify.log"), "utf8"), /VERDICT: FAIL/);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}, 60_000);

bunTest("drift e plan.json ilegível recusam verify e todas as fases antes de executar ou gravar PASS", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-drift-"));
  try {
    initRepository(cwd);
    writeFileSync(path.join(cwd, "app.js"), "export const value = 'old';\n");
    writeFileSync(path.join(cwd, "app.test.mjs"), "");
    const plan = canonicalPlanFor(cwd);
    const markdownPath = path.join(cwd, ".todo", "0001-tasks.md");
    const canonicalPath = path.join(cwd, ".pwn", "work", "0001", "plan.json");
    const markdown = readFileSync(markdownPath, "utf8");
    const canonical = readFileSync(canonicalPath, "utf8");
    const marker = path.join(cwd, "COMMAND-RAN");
    const changedPlan = structuredClone(plan);
    changedPlan.tasks[0].acceptance_criteria[0].description = "critério canônico alterado";
    const corruptions = [
      () => writeFileSync(markdownPath, markdown.replace("a asserção CANONICAL-RED-001 passa", "critério markdown alterado")),
      () => writeFileSync(canonicalPath, JSON.stringify(changedPlan)),
      () => writeFileSync(canonicalPath, "{ invalid JSON\n"),
    ];
    const evidenceFiles = [
      ".todo/evidence/0001/state/1.1.json",
      ".todo/evidence/0001/1.1-chain.jsonl",
      ...["red", "green", "verify", "ac-1", "regression"].map((phase) => `.todo/evidence/0001/1.1-${phase}.log`),
    ];
    const refuse = (...args: string[]) => {
      for (const corrupt of corruptions) {
        rmSync(marker, { force: true });
        const before = evidenceFiles.map((file) => existsSync(path.join(cwd, file)) ? readFileSync(path.join(cwd, file), "utf8") : null);
        corrupt();
        const result = run(cwd, ...args);
        assert.equal(result.status, 1, `${args[0]}: ${result.stderr}`);
        assert.match(result.stderr, /DRIFT/);
        assert.doesNotMatch(result.stdout, /PASS:/);
        assert.equal(existsSync(marker), false, `${args[0]} não deve executar o comando`);
        const after = evidenceFiles.map((file) => existsSync(path.join(cwd, file)) ? readFileSync(path.join(cwd, file), "utf8") : null);
        assert.deepEqual(after, before, `${args[0]} não deve gravar evidência antes de recusar`);
        writeFileSync(markdownPath, markdown);
        writeFileSync(canonicalPath, canonical);
      }
    };
    commit(cwd, "baseline canônico");
    refuse("baseline", "--work", "0001", "--task", "1.1");
    assert.equal(run(cwd, "baseline", "--work", "0001", "--task", "1.1").status, 0);
    writeFileSync(path.join(cwd, "app.test.mjs"), `import { expect, test } from 'bun:test';
import { writeFileSync } from 'node:fs';
import { value } from './app.js';
writeFileSync('COMMAND-RAN', 'executed');
test('CANONICAL-RED-001', () => { expect(value).toBe('new'); });
`);
    refuse("red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", ...focusedRun("app.test.mjs"));
    assert.equal(run(cwd, "red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", ...focusedRun("app.test.mjs")).status, 0);
    writeFileSync(path.join(cwd, "app.js"), "export const value = 'new';\n");
    refuse("green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(run(cwd, "green", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs")).status, 0);
    // verify e check também recusam o drift antes de executar ou gravar PASS
    refuse("verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    assert.equal(run(cwd, "verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs")).status, 0);
    refuse("check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", ...focusedRun("app.test.mjs"));

    assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", ...focusedRun("app.test.mjs")).status, 0);
    assert.equal(run(cwd, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", RUNTIME, "test").status, 0);
    assert.equal(existsSync(marker), true, "o fixture legítimo realmente executa o comando com marcador");
    // Com toda a evidência no disco, o drift continua recusando verify e check
    refuse("verify", "--work", "0001", "--task", "1.1", "--", ...focusedRun("app.test.mjs"));
    refuse("check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", ...focusedRun("app.test.mjs"));
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}, 60_000);

bunTest("comando auditado não herda PWN_VERIFIER_KEY do ambiente explícito do subprocesso", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "task-evidence-child-env-"));
  try {
    initRepository(cwd);
    writeFileSync(path.join(cwd, "app.js"), "export const value = 'old';\n");
    writeFileSync(path.join(cwd, "app.test.mjs"), "");
    planFor(cwd, [{ id: "1.1", title: "Implement value", implementation: "app.js", test: "app.test.mjs", assertion: "ENV-RED-001" }]);
    commit(cwd, "baseline");
    const env = { ...process.env, PWN_VERIFIER_KEY: "subprocess-only-secret-001", PWN_AUDIT_ENV_CONTROL: "explicit-control" };
    const baseline = spawnSync(RUNTIME, [script, "baseline", "--work", "0001", "--task", "1.1"], { cwd, encoding: "utf8", env });
    assert.equal(baseline.status, 0, baseline.stderr);
    // O comando auditado falha com ENV-RED-001 só quando a chave do verificador NÃO é herdada;
    // se fosse herdada, a falha teria outra mensagem e o RED seria recusado.
    writeFileSync(path.join(cwd, "app.test.mjs"), `import { expect, test } from 'bun:test';
test('ambiente auditado sem chave do verificador', () => {
  expect(process.env.PWN_AUDIT_ENV_CONTROL).toBe('explicit-control');
  if (process.env.PWN_VERIFIER_KEY !== undefined) throw new Error('chave do verificador herdada do ambiente');
  throw new Error('ENV-RED-001');
});
`);
    const result = spawnSync(RUNTIME, [script, "red", "--work", "0001", "--task", "1.1", "--expect", "ENV-RED-001", "--", RUNTIME, "test", "app.test.mjs"], {
      cwd,
      encoding: "utf8",
      env,
    });
    assert.equal(result.status, 0, result.stderr);
    const log = readFileSync(path.join(cwd, ".todo/evidence/0001/1.1-red.log"), "utf8");
    assert.match(log, /VERDICT: PASS/);
    assert.doesNotMatch(log, /subprocess-only-secret-001/);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}, 60_000);
