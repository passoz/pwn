import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { renderTasksMarkdown, type Plan } from "../src/core/plan-renderer.js";
import {
  approvalPath,
  approvedFileContent,
  createApproval,
  currentApproval,
  type Approval,
} from "../src/core/acceptance-approval.js";
import { captureDependencyDigest, captureSnapshot } from "../src/core/candidate-snapshot.js";
import {
  buildReceipt,
  evaluateAcceptance,
  storeReceipt,
  signatureIsValid,
} from "../src/core/verification-receipt.js";
import { looksEnvironmental, runVerification, type VerificationRunResult } from "../src/core/verification-runner.js";
import {
  approvalsDir,
  assertProtectedOutsideRepository,
  initializeVerifierHome,
  receiptDir,
  VerificationUnavailable,
  writeJsonAtomic,
} from "../src/core/verifier-home.js";

/** Runtime aprovado: o próprio executável que roda o verificador. */
const BUN = process.execPath;

/** bwrap é pré-requisito da aceitação independente; sem ele os testes de execução são pulados. */
const hasBwrap =
  spawnSync("sh", ["-c", "command -v bwrap"], { encoding: "utf8" }).status === 0;

const scratch: string[] = [];
function tmp(prefix: string): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function sha(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function write(rootDir: string, relative: string, content: string): void {
  const absolute = path.join(rootDir, relative);
  mkdirSync(path.dirname(absolute), { recursive: true });
  writeFileSync(absolute, content, "utf8");
}

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr || result.error?.message}`);
  return (result.stdout ?? "").trim();
}

const ACCEPTANCE_PATH = "tests/acceptance.test.ts";
const IMPLEMENTATION_PATH = "src/lib.ts";
const WORK_ID = "0001";
const TASK_ID = "1.1";

const NEW_IMPLEMENTATION = 'export function value() { return "NEW"; }\n';
const OLD_IMPLEMENTATION = 'export function value() { return "OLD"; }\n';
const WRONG_IMPLEMENTATION = 'export function value() { return "WRONG"; }\n';
const ACCEPTANCE_IMPORT = 'import { expect, test } from "bun:test";\nimport { value } from "../src/lib.ts";\n';

function acceptanceAsserting(expected: string): string {
  return `${ACCEPTANCE_IMPORT}test("value", () => { expect(value()).toBe(${JSON.stringify(expected)}); });\n`;
}

const TRIVIAL_ACCEPTANCE = 'import { expect, test } from "bun:test";\ntest("trivial", () => { expect(1).toBe(1); });\n';

interface FixtureOptions {
  acCommand?: string;
  regressionCommand?: string;
  acceptanceTest?: string;
  candidateImplementation?: string;
  baselineImplementation?: string;
  /** `false` deixa o contrato sem `frozen_tests`. */
  frozen?: boolean;
  /** Sobrescreve o sha256 congelado (para testar a divergência). */
  frozenSha?: string;
}

interface Fixture {
  rootDir: string;
  verifierRoot: string;
  acceptancePath: string;
  implementationPath: string;
}

/**
 * Fixture mínima do recipe: plan.json (componente com coluna Regression), tasks.md
 * renderizado, contrato V4 com `frozen_tests`, repositório git com um commit.
 * Quando a implementação do candidato difere da commitada, ela fica sem commit —
 * exatamente a situação do baseline reverter para o commit aprovado.
 */
function buildFixture(options: FixtureOptions = {}): Fixture {
  const rootDir = tmp("pwn-fixture-");
  const acCommand = options.acCommand ?? `${BUN} test ${ACCEPTANCE_PATH}`;
  const regressionCommand = options.regressionCommand ?? `${BUN} test ${ACCEPTANCE_PATH}`;
  const acceptanceTest = options.acceptanceTest ?? acceptanceAsserting("NEW");
  const candidateImplementation = options.candidateImplementation ?? NEW_IMPLEMENTATION;
  const baselineImplementation = options.baselineImplementation ?? candidateImplementation;

  const plan: Plan = {
    work_id: WORK_ID,
    title: "Aceitação independente",
    components: [{ name: "core", purpose: "núcleo", regression: regressionCommand }],
    global_gates: [],
    tasks: [
      {
        id: TASK_ID,
        title: "Implementar valor",
        requirement_id: "FR-001",
        depends_on: [],
        behavior: "value() devolve o valor implementado",
        components: ["core"],
        files: [IMPLEMENTATION_PATH, ACCEPTANCE_PATH],
        implementation_files: [IMPLEMENTATION_PATH],
        test_files: [ACCEPTANCE_PATH],
        red: { command: acCommand, description: "falha antes da implementação" },
        implementation_steps: ["implementar value()"],
        acceptance_criteria: [{ command: acCommand, description: "value() satisfaz o AC" }],
        visual: "N/A",
        documentation: "N/A",
        spec_reference: "SPEC-001",
        contract_id: "CTR-001",
        complexity: "L1",
      },
    ],
  };

  write(rootDir, `.pwn/work/${WORK_ID}/plan.json`, `${JSON.stringify(plan, null, 2)}\n`);
  write(rootDir, `.todo/${WORK_ID}-tasks.md`, renderTasksMarkdown(plan));
  write(rootDir, IMPLEMENTATION_PATH, baselineImplementation);
  write(rootDir, ACCEPTANCE_PATH, acceptanceTest);

  const contract: Record<string, unknown> = {
    contract_version: "4.0",
    task_id: TASK_ID,
    work_id: WORK_ID,
    title: "Implementar valor",
    risk: { level: "L1", reasons: ["fixture"] },
    validation_strategy: "tdd-strict",
    behavioral_contract: { scenarios: [] },
    change_contract: { target_files: [IMPLEMENTATION_PATH], affected_components: ["core"] },
    architecture_contract: { invariants: [] },
    acceptance_contract: {
      commands: [acCommand],
      required_evidence: ["evidence.json"],
      ...(options.frozen === false
        ? {}
        : { frozen_tests: [{ path: ACCEPTANCE_PATH, sha256: options.frozenSha ?? sha(acceptanceTest) }] }),
    },
    scope_contract: { write_allow: ["src/**", "tests/**"], write_deny: [".git/**"] },
    budget_contract: { max_agent_attempts: 1 },
    escalation_contract: {
      on_write_violation: "block_and_escalate",
      on_budget_exceeded: "human_review",
      on_attempt_failed: "human_review",
    },
  };
  write(rootDir, `.pwn/work/${WORK_ID}/CTR-001.json`, `${JSON.stringify(contract, null, 2)}\n`);

  git(rootDir, "init", "-q");
  git(rootDir, "config", "user.email", "test@example.com");
  git(rootDir, "config", "user.name", "Test");
  git(rootDir, "add", "-A");
  git(rootDir, "commit", "-q", "-m", "baseline");

  if (candidateImplementation !== baselineImplementation) {
    write(rootDir, IMPLEMENTATION_PATH, candidateImplementation);
  }

  const verifierRoot = tmp("pwn-verifier-");
  initializeVerifierHome(verifierRoot);

  return { rootDir, verifierRoot, acceptancePath: ACCEPTANCE_PATH, implementationPath: IMPLEMENTATION_PATH };
}

function approve(fixture: Fixture): Approval {
  return createApproval({
    rootDir: fixture.rootDir,
    workId: WORK_ID,
    taskId: TASK_ID,
    approvedBy: "operator",
    verifierRootDir: fixture.verifierRoot,
  });
}

/** Resultado de execução sintético com `outcome: pass`, casando com a árvore atual. */
function passingResult(rootDir: string): VerificationRunResult {
  return {
    checks: [
      {
        id: "AC-1",
        command: [BUN, "test", ACCEPTANCE_PATH],
        outcome: "pass",
        exit_code: 0,
        output_digest: sha("ok"),
        output_tail: "ok",
      },
    ],
    snapshot_digest: captureSnapshot(rootDir).digest,
    dependency_digest: captureDependencyDigest(rootDir).digest,
    sandbox_digest: sha("policy"),
    sandbox_policy: {} as VerificationRunResult["sandbox_policy"],
  };
}

function findCheck(result: VerificationRunResult, id: string) {
  const check = result.checks.find((entry) => entry.id === id);
  if (!check) throw new Error(`check ${id} ausente no resultado: ${result.checks.map((c) => c.id).join(", ")}`);
  return check;
}

function runFixture(fixture: Fixture, approval: Approval): VerificationRunResult {
  return runVerification({
    rootDir: fixture.rootDir,
    approval,
    timeoutSeconds: 120,
    verifierRootDir: fixture.verifierRoot,
  });
}

// ── (1)(2) Assinatura Ed25519 e verificador alheio ──────────────────────────

describe("recibo de aceitação independente", () => {
  test("recibo adulterado (outcome/checks/snapshot) é recusado por signatureIsValid e evaluateAcceptance", () => {
    const fixture = buildFixture();
    const approval = approve(fixture);
    const valid = buildReceipt({ approval, result: passingResult(fixture.rootDir), verifierRootDir: fixture.verifierRoot });

    expect(signatureIsValid(valid, fixture.verifierRoot)).toBe(true);

    const tampers: Array<[string, (receipt: typeof valid) => typeof valid]> = [
      ["outcome", (receipt) => ({ ...receipt, outcome: "fail" })],
      ["checks", (receipt) => ({ ...receipt, checks: [] })],
      ["snapshot", (receipt) => ({ ...receipt, candidate_snapshot_digest: sha("outra árvore") })],
    ];

    for (const [label, tamper] of tampers) {
      const forged = tamper(valid);
      expect(signatureIsValid(forged, fixture.verifierRoot), `${label} adulterado não deve validar`).toBe(false);

      writeJsonAtomic(path.join(receiptDir(fixture.verifierRoot), `${WORK_ID}-${TASK_ID}.json`), forged);
      const evaluation = evaluateAcceptance({
        rootDir: fixture.rootDir,
        workId: WORK_ID,
        taskId: TASK_ID,
        verifierRootDir: fixture.verifierRoot,
      });
      expect(evaluation.accepted, `${label} adulterado não deve ser aceito`).toBe(false);
      expect(evaluation.reason).toContain("assinatura");
    }
  });

  test("recibo assinado por outro verificador (chave diferente) é recusado", () => {
    const fixture = buildFixture();
    const approval = approve(fixture);
    const receipt = buildReceipt({ approval, result: passingResult(fixture.rootDir), verifierRootDir: fixture.verifierRoot });

    const otherRoot = tmp("pwn-verifier-other-");
    initializeVerifierHome(otherRoot);

    expect(signatureIsValid(receipt, fixture.verifierRoot)).toBe(true);
    expect(signatureIsValid(receipt, otherRoot)).toBe(false);

    // A MESMA aprovação existe no outro verificador, mas o recibo foi assinado pelo primeiro.
    writeJsonAtomic(approvalPath(approval.approval_id, otherRoot), approval);
    writeJsonAtomic(path.join(approvalsDir(otherRoot), "index.json"), {
      version: 1,
      current: { [`${WORK_ID}:${TASK_ID}`]: approval.approval_id },
    });
    writeJsonAtomic(path.join(receiptDir(otherRoot), `${WORK_ID}-${TASK_ID}.json`), receipt);

    const evaluation = evaluateAcceptance({
      rootDir: fixture.rootDir,
      workId: WORK_ID,
      taskId: TASK_ID,
      verifierRootDir: otherRoot,
    });
    expect(evaluation.accepted).toBe(false);
    expect(evaluation.reason).toContain("verificador desconhecido");
  });
});

// ── (3) Pacote de aprovação ────────────────────────────────────────────────

describe("pacote de aprovação", () => {
  test("createApproval exige testes de aceitação congelados no contrato", () => {
    const fixture = buildFixture({ frozen: false });
    expect(() => approve(fixture)).toThrow(/congelados/);
  });

  test("createApproval exige que o sha256 do teste bata com o congelado", () => {
    const fixture = buildFixture({ frozenSha: sha("conteúdo que não está no repositório") });
    expect(() => approve(fixture)).toThrow(/diverge do congelado/);
  });

  test("approvedFileContent devolve o conteúdo aprovado mesmo após alterar o arquivo do repositório", () => {
    const fixture = buildFixture();
    const approval = approve(fixture);
    const approved = readFileSync(path.join(fixture.rootDir, fixture.acceptancePath), "utf8");

    write(fixture.rootDir, fixture.acceptancePath, "// enfraquecido depois da aprovação\n");
    expect(readFileSync(path.join(fixture.rootDir, fixture.acceptancePath), "utf8")).not.toBe(approved);

    expect(approvedFileContent(approval, fixture.acceptancePath, fixture.verifierRoot)).toBe(approved);
    expect(currentApproval(WORK_ID, TASK_ID, fixture.verifierRoot)?.approval_id).toBe(approval.approval_id);
  });
});

// ── (4) Snapshot determinístico ────────────────────────────────────────────

describe("captureSnapshot", () => {
  test("é determinístico, muda com arquivo indireto e ignora estado do harness/dependências", () => {
    const rootDir = tmp("pwn-snapshot-");
    write(rootDir, "src/a.ts", "a");
    write(rootDir, "src/deep/b.ts", "b");
    write(rootDir, "package.json", '{"name":"x"}');

    const first = captureSnapshot(rootDir).digest;
    const second = captureSnapshot(rootDir).digest;
    expect(first).toBe(second);

    // Arquivo indireto (não declarado na task) muda o estado executável.
    write(rootDir, "src/deep/b.ts", "b-alterado");
    const afterIndirect = captureSnapshot(rootDir).digest;
    expect(afterIndirect).not.toBe(first);

    // Estado do harness e dependências nunca entram no snapshot.
    write(rootDir, ".todo/x.md", "x");
    write(rootDir, ".pwn/work/0001/plan.json", "{}");
    write(rootDir, ".work/tmp.txt", "tmp");
    write(rootDir, ".git/HEAD", "ref: refs/heads/main\n");
    write(rootDir, "queue/q.json", "{}");
    write(rootDir, "node_modules/pkg/index.js", "module.exports = 1;\n");

    const snapshot = captureSnapshot(rootDir);
    expect(snapshot.digest).toBe(afterIndirect);
    const paths = snapshot.files.map((entry) => entry.path);
    for (const prefix of [".todo/", ".pwn/", ".work/", ".git/", "queue/", "node_modules/"]) {
      expect(paths.some((entry) => entry.startsWith(prefix)), `${prefix} não deve entrar no snapshot`).toBe(false);
    }
  });
});

// ── (5) evaluateAcceptance ─────────────────────────────────────────────────

describe("evaluateAcceptance", () => {
  test("aceita somente quando aprovação, assinatura, outcome e árvore coincidem", () => {
    const fixture = buildFixture();
    const approval = approve(fixture);
    const receipt = buildReceipt({ approval, result: passingResult(fixture.rootDir), verifierRootDir: fixture.verifierRoot });
    storeReceipt(receipt, fixture.rootDir, fixture.verifierRoot);

    const evaluation = evaluateAcceptance({
      rootDir: fixture.rootDir,
      workId: WORK_ID,
      taskId: TASK_ID,
      verifierRootDir: fixture.verifierRoot,
    });
    expect(evaluation.accepted).toBe(true);
    expect(evaluation.receipt?.receipt_id).toBe(receipt.receipt_id);
  });

  test("recusa quando a árvore muda depois do recibo", () => {
    const fixture = buildFixture();
    const approval = approve(fixture);
    const receipt = buildReceipt({ approval, result: passingResult(fixture.rootDir), verifierRootDir: fixture.verifierRoot });
    storeReceipt(receipt, fixture.rootDir, fixture.verifierRoot);

    write(fixture.rootDir, "src/indireto.ts", "export const mudou = true;\n");

    const evaluation = evaluateAcceptance({
      rootDir: fixture.rootDir,
      workId: WORK_ID,
      taskId: TASK_ID,
      verifierRootDir: fixture.verifierRoot,
    });
    expect(evaluation.accepted).toBe(false);
    expect(evaluation.reason).toContain("árvore mudou");
  });

  test("recusa quando o contrato muda e uma nova aprovação substitui a vigente", () => {
    const fixture = buildFixture();
    const first = approve(fixture);
    const receipt = buildReceipt({ approval: first, result: passingResult(fixture.rootDir), verifierRootDir: fixture.verifierRoot });
    storeReceipt(receipt, fixture.rootDir, fixture.verifierRoot);

    const contractPath = path.join(fixture.rootDir, `.pwn/work/${WORK_ID}/CTR-001.json`);
    const contract = JSON.parse(readFileSync(contractPath, "utf8"));
    contract.extra = "contrato alterado";
    write(fixture.rootDir, `.pwn/work/${WORK_ID}/CTR-001.json`, `${JSON.stringify(contract, null, 2)}\n`);

    const second = approve(fixture);
    expect(second.approval_id).not.toBe(first.approval_id);

    const evaluation = evaluateAcceptance({
      rootDir: fixture.rootDir,
      workId: WORK_ID,
      taskId: TASK_ID,
      verifierRootDir: fixture.verifierRoot,
    });
    expect(evaluation.accepted).toBe(false);
    expect(evaluation.reason).toContain("aprovação anterior");
  });
});

// ── (6) Fronteira da raiz protegida ────────────────────────────────────────

describe("assertProtectedOutsideRepository", () => {
  test("recusa a raiz protegida dentro do repositório avaliado", () => {
    const repository = tmp("pwn-repo-");
    expect(() => assertProtectedOutsideRepository(path.join(repository, ".pwn-verifier"), repository)).toThrow(
      VerificationUnavailable,
    );
    expect(() => assertProtectedOutsideRepository(repository, repository)).toThrow(VerificationUnavailable);

    const outside = tmp("pwn-outside-");
    expect(() => assertProtectedOutsideRepository(outside, repository)).not.toThrow();
    // Prefixo textual não é ancestralidade: `<repo>-vizinho` é externo.
    expect(() => assertProtectedOutsideRepository(`${repository}-vizinho`, repository)).not.toThrow();
  });
});

// ── (7) Classificação de falha ambiental ───────────────────────────────────

describe("looksEnvironmental", () => {
  test("classifica erro de import/módulo como ambiente", () => {
    expect(looksEnvironmental("error: Cannot find module 'x'")).toBe(true);
    expect(looksEnvironmental("Module not found: ./y")).toBe(true);
    expect(looksEnvironmental("no such file or directory")).toBe(true);
  });

  test("não classifica uma falha de asserção como ambiente", () => {
    expect(looksEnvironmental("expect(received).toBe(expected) // Object.is equality")).toBe(false);
    expect(looksEnvironmental("AssertionError: expected 2 to be 3")).toBe(false);
  });
});

// ── (8)(9) Execução em sandbox (requer bwrap) ───────────────────────────────

const bwrapTest = (hasBwrap ? test : test.skip) as typeof test;
const BWRAP_HINT = " (requer bwrap — pulado)";

describe("runVerification (sandbox bwrap)", () => {
  bwrapTest(`rejeita AC que passa também com a implementação revertida ao baseline${BWRAP_HINT}`, () => {
    const fixture = buildFixture({
      acceptanceTest: TRIVIAL_ACCEPTANCE,
      candidateImplementation: NEW_IMPLEMENTATION,
      baselineImplementation: OLD_IMPLEMENTATION,
    });
    const approval = approve(fixture);
    const result = runFixture(fixture, approval);

    const ac = findCheck(result, "AC-1");
    expect(ac.outcome).toBe("fail");
    expect(ac.reason).toContain("sem a implementação");
    expect(ac.baseline?.exit_code).toBe(0);
  });

  bwrapTest(`aceita quando passa no candidato e falha no baseline${BWRAP_HINT}`, () => {
    const fixture = buildFixture({
      acceptanceTest: acceptanceAsserting("NEW"),
      candidateImplementation: NEW_IMPLEMENTATION,
      baselineImplementation: OLD_IMPLEMENTATION,
    });
    const approval = approve(fixture);
    const result = runFixture(fixture, approval);

    const ac = findCheck(result, "AC-1");
    expect(ac.outcome).toBe("pass");
    expect(ac.exit_code).toBe(0);
    expect(ac.baseline?.exit_code).not.toBe(0);
    expect(ac.baseline?.suspect_environmental).toBe(false);
  });

  bwrapTest(`executa o teste de aceitação aprovado mesmo com o arquivo do repositório enfraquecido${BWRAP_HINT}`, () => {
    const fixture = buildFixture({
      acceptanceTest: acceptanceAsserting("NEW"),
      candidateImplementation: NEW_IMPLEMENTATION,
      baselineImplementation: OLD_IMPLEMENTATION,
    });
    const approval = approve(fixture);

    // Enfraquece no repositório: agora afirmaria "OLD", que FALHA contra o candidato "NEW".
    write(fixture.rootDir, fixture.acceptancePath, acceptanceAsserting("OLD"));

    const result = runFixture(fixture, approval);
    const ac = findCheck(result, "AC-1");
    // Se o runner tivesse usado o arquivo do repositório, o candidato falharia.
    expect(ac.outcome).toBe("pass");
    expect(ac.exit_code).toBe(0);
    expect(ac.baseline?.exit_code).not.toBe(0);
  });

  bwrapTest(`comando que imprime PASS e sai 0 sem satisfazer o teste aprovado não torna o check pass${BWRAP_HINT}`, () => {
    const fixture = buildFixture({
      // Não executa o teste aprovado: apenas imprime PASS e sai 0.
      acCommand: `${BUN} -e 'console.log("PASS")'`,
      regressionCommand: `${BUN} -e 'console.log("PASS")'`,
      acceptanceTest: acceptanceAsserting("NEW"),
      candidateImplementation: WRONG_IMPLEMENTATION,
      baselineImplementation: OLD_IMPLEMENTATION,
    });
    const approval = approve(fixture);
    const result = runFixture(fixture, approval);

    const ac = findCheck(result, "AC-1");
    expect(ac.exit_code).toBe(0);
    expect(ac.output_tail).toContain("PASS");
    expect(ac.outcome).not.toBe("pass");
  });
});
