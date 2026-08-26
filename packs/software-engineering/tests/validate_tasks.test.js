import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  CURRENT_TASK_CONTRACT_VERSION,
  migrateTasksContent,
  validateTasks,
  validateTasksDetailed,
} from "../scripts/validate_tasks.js";

const SCRIPT = path.resolve("scripts/validate_tasks.js");

const VALID = `# Tasks: auth
**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}
**Work ID:** 0001

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| backend-go | \`.\` | \`go test ./...\` | \`N/A\` | \`go build ./...\` | \`N/A\` | \`N/A\` | \`N/A\` |

## Global gates
N/A

### [ ] [1.1] Reject invalid login

**Requirement:** FR-001
**Depends on:** none
**Behavior:** Invalid passwords return unauthorized.
**Components:** backend-go
**Files:** internal/auth.go, internal/auth_test.go
**Implementation files:** internal/auth.go
**Test files:** internal/auth_test.go

**RED:**
- \`go test -run TestInvalidLogin ./internal/...\` — exit non-zero and failure names the test.

**Implementation:**
1. Return unauthorized for an invalid password.

**ACs:**
- [ ] \`go test -run TestInvalidLogin ./internal/...\` — exit 0.

**Visual:** N/A

**Documentation:** N/A
`;

function validate(content) {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-"));
  const file = path.join(directory, ".todo", "0001-tasks.md");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content, "utf8");
  return validateTasks(file);
}

function validateWithSpec(content, specContent) {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-spec-"));
  const file = path.join(directory, ".todo", "0001-tasks.md");
  const spec = path.join(directory, ".specs", "system.md");
  mkdirSync(path.dirname(file), { recursive: true });
  mkdirSync(path.dirname(spec), { recursive: true });
  writeFileSync(file, content, "utf8");
  writeFileSync(spec, specContent, "utf8");
  return validateTasks(file);
}

test("accepts a canonical current-contract task", () => {
  const result = validateTasksDetailed((() => {
    const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-current-"));
    const file = path.join(directory, ".todo", "0001-tasks.md");
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, VALID, "utf8");
    return file;
  })());
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.contractVersion, CURRENT_TASK_CONTRACT_VERSION);
});


test("keeps executable legacy plans compatible and reports upgrade warnings", () => {
  const legacy = VALID
    .replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, "")
    .replace("**Requirement:** FR-001\n", "")
    .replace("**Depends on:** none\n", "");
  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-legacy-"));
  const file = path.join(directory, "tasks.md");
  writeFileSync(file, legacy, "utf8");
  const result = validateTasksDetailed(file);
  assert.deepEqual(result.errors, []);
  assert.equal(result.contractVersion, 1);
  assert.ok(result.warnings.some((warning) => warning.includes("contract version is missing")));
  assert.ok(result.warnings.some((warning) => warning.includes("missing field **Requirement:**")));
  assert.ok(result.warnings.some((warning) => warning.includes("missing field **Depends on:**")));
});

test("keeps task contract v2 readable and migrates it to numbered v3", () => {
  const previous = VALID
    .replace("**Contract version:** 3", "**Contract version:** 2")
    .replace("**Work ID:** 0001\n", "");
  const analyzed = (() => {
    const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-v2-"));
    const file = path.join(directory, "tasks.md");
    writeFileSync(file, previous, "utf8");
    return validateTasksDetailed(file);
  })();
  assert.deepEqual(analyzed.errors, []);
  assert.equal(analyzed.contractVersion, 2);
  assert.ok(analyzed.warnings.some((warning) => warning.includes("contract version 2 is legacy")));

  const migrated = migrateTasksContent(previous, { workId: "0042" });
  assert.deepEqual(migrated.errors, []);
  assert.match(migrated.content, /\*\*Contract version:\*\* 3/);
  assert.match(migrated.content, /\*\*Migrated from task contract:\*\* 2/);
  assert.match(migrated.content, /\*\*Work ID:\*\* 0042/);
});


test("strict mode promotes legacy compatibility warnings to errors", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-strict-"));
  const file = path.join(directory, "tasks.md");
  writeFileSync(file, VALID.replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, ""), "utf8");
  const result = validateTasksDetailed(file, { strict: true });
  assert.ok(result.errors.some((error) => error.includes("compatibility warning treated as error")));
  assert.deepEqual(result.warnings, []);
});


test("migrates a legacy plan mechanically and idempotently", () => {
  const legacy = VALID
    .replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, "")
    .replace("**Requirement:** FR-001\n", "")
    .replace("**Depends on:** none\n", "");
  const migrated = migrateTasksContent(legacy, { workId: "0001" });
  assert.deepEqual(migrated.errors, []);
  assert.match(migrated.content, /\*\*Contract version:\*\* 3/);
  assert.match(migrated.content, /\*\*Migrated from task contract:\*\* 1/);
  assert.match(migrated.content, /\*\*Requirement:\*\* SOURCE-001/);
  assert.match(migrated.content, /\*\*Depends on:\*\* none/);

  const repeated = migrateTasksContent(migrated.content, { workId: "0001" });
  assert.deepEqual(repeated.errors, []);
  assert.deepEqual(repeated.changes, []);
  assert.equal(repeated.content, migrated.content);
});


test("migrates exact legacy atomicity exceptions without weakening current plans", () => {
  const legacy = VALID
    .replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, "")
    .replace(
      "**Files:** internal/auth.go, internal/auth_test.go",
      "**Files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go, internal/auth_test.go",
    )
    .replace(
      "**Implementation files:** internal/auth.go",
      "**Implementation files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go",
    );
  const migrated = migrateTasksContent(legacy, { workId: "0001" });
  assert.deepEqual(migrated.errors, []);
  assert.match(migrated.content, /\*\*Legacy allowances:\*\* implementation-files=4/);

  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-allowance-"));
  const file = path.join(directory, "tasks.md");
  writeFileSync(file, migrated.content, "utf8");
  const result = validateTasksDetailed(file, { strict: true });
  assert.deepEqual(result.errors, []);
  assert.ok(result.exceptions.some((entry) => entry.includes("implementation-files=4")));

  const expanded = migrated.content
    .replace("internal/c.go, internal/auth_test.go", "internal/c.go, internal/d.go, internal/auth_test.go")
    .replace("internal/c.go\n**Test files", "internal/c.go, internal/d.go\n**Test files");
  writeFileSync(file, expanded, "utf8");
  const expandedResult = validateTasksDetailed(file);
  assert.ok(expandedResult.errors.some((error) => error.includes("5 implementation files (max 3)")));
  assert.ok(expandedResult.errors.some((error) => error.includes("stale legacy allowance implementation-files=4")));
});


test("rejects invented legacy allowances on current plans", () => {
  const invented = VALID.replace("**Depends on:** none", "**Depends on:** none\n**Legacy allowances:** implementation-files=4");
  assert.ok(validate(invented).some((error) => error.includes("require a v3 plan marked as migrated from v1 or v2")));
});


test("previews and applies legacy migration through the CLI", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-tasks-migrate-cli-"));
  const file = path.join(directory, ".todo", "0001-tasks.md");
  mkdirSync(path.dirname(file), { recursive: true });
  const legacy = VALID
    .replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, "")
    .replace("**Requirement:** FR-001\n", "")
    .replace("**Depends on:** none\n", "");
  writeFileSync(file, legacy, "utf8");

  const preview = spawnSync(process.execPath, [SCRIPT, "--migrate", "--work", "0001", file], { encoding: "utf8" });
  assert.equal(preview.status, 0, preview.stderr);
  assert.match(preview.stdout, /MIGRATION PREVIEW/);
  assert.equal(readFileSync(file, "utf8"), legacy);

  const applied = spawnSync(process.execPath, [SCRIPT, "--migrate", "--work", "0001", "--write", file], { encoding: "utf8" });
  assert.equal(applied.status, 0, applied.stderr);
  assert.match(applied.stdout, /MIGRATED/);
  assert.match(readFileSync(file, "utf8"), /\*\*Contract version:\*\* 3/);

  const strict = spawnSync(process.execPath, [SCRIPT, "--strict", file], { encoding: "utf8" });
  assert.equal(strict.status, 0, strict.stdout + strict.stderr);

  const repeated = spawnSync(process.execPath, [SCRIPT, "--migrate", "--work", "0001", "--write", file], { encoding: "utf8" });
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.match(repeated.stdout, /MIGRATION N\/A/);
});


test("does not hide safety failures in legacy compatibility mode", () => {
  const legacy = VALID
    .replace(`**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}\n`, "")
    .replace("go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin");
  assert.ok(validate(legacy).some((error) => error.includes("unsafe command")));
});

test("rejects unsafe commands", () => {
  const errors = validate(VALID.replace("go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin"));
  assert.ok(errors.some((error) => error.includes("unsafe command")));
});

test("allows an exact dependency installation declared in a governing spec", () => {
  const plan = VALID.replace(
    "**Depends on:** none",
    `**Depends on:** none
**Dependency installations:**
- \`npm install fastify@4\` — declared in \`.specs/system.md\`.`,
  );
  assert.deepEqual(
    validateWithSpec(plan, "# System spec\n\n**Dependencies:** `fastify`\n"),
    [],
  );

  const scopedPlan = plan.replace("npm install fastify@4", "npm install @fastify/cors@8");
  assert.deepEqual(
    validateWithSpec(scopedPlan, "# System spec\n\n**Dependencies:** `@fastify/cors`\n"),
    [],
  );

  const goPlan = plan.replace("npm install fastify@4", "go get github.com/google/uuid@v1.6.0");
  assert.deepEqual(
    validateWithSpec(goPlan, "# System spec\n\n**Dependencies:** `github.com/google/uuid`\n"),
    [],
  );

  const twoPackages = plan.replace("npm install fastify@4", "npm install fastify@4 pino@9");
  assert.deepEqual(
    validateWithSpec(twoPackages, "# System spec\n\n**Dependencies:** `fastify`, `pino`\n"),
    [],
  );
  const partialSpec = validateWithSpec(twoPackages, "# System spec\n\n**Dependencies:** `fastify`\n");
  assert.ok(partialSpec.some((error) => error.includes("dependency pino is not declared")));
});

test("rejects dependency installation when the package is absent from the declared spec", () => {
  const plan = VALID.replace(
    "**Depends on:** none",
    `**Depends on:** none
**Dependency installations:**
- \`npm install fastify@4\` — declared in \`.specs/system.md\`.`,
  );
  const errors = validateWithSpec(plan, "# System spec\n\nNo HTTP framework is selected.\n");
  assert.ok(errors.some((error) => error.includes("dependency fastify is not declared")));
  assert.ok(errors.some((error) => error.includes("unsafe command (package installation)")));

  const proseOnly = validateWithSpec(
    plan,
    "# System spec\n\nDo not use fastify; the selected HTTP transport is different.\n",
  );
  assert.ok(proseOnly.some((error) => error.includes("dependency fastify is not declared")));
});

test("rejects undeclared package installation and keeps other safety checks active", () => {
  const undeclared = validate(VALID.replace(
    "`go test -run TestInvalidLogin ./internal/...` — exit 0.",
    "`npm install fastify@4` — exit 0.",
  ));
  assert.ok(undeclared.some((error) => error.includes("unsafe command (package installation)")));

  const declaredWithSudo = VALID.replace(
    "**Depends on:** none",
    `**Depends on:** none
**Dependency installations:**
- \`sudo npm install fastify@4\` — declared in \`.specs/system.md\`.`,
  );
  const sudoErrors = validateWithSpec(declaredWithSudo, "# System spec\n\n**Dependencies:** `fastify`\n");
  assert.ok(sudoErrors.some((error) => error.includes("unsafe command (sudo)")));

  const globalInstall = VALID.replace(
    "**Depends on:** none",
    `**Depends on:** none
**Dependency installations:**
- \`npm install -g fastify@4\` — declared in \`.specs/system.md\`.`,
  );
  const globalErrors = validateWithSpec(globalInstall, "# System spec\n\n**Dependencies:** `fastify`\n");
  assert.ok(globalErrors.some((error) => error.includes("invalid dependency installation")));
});

test("rejects unresolved markers", () => {
  const errors = validate(VALID.replace("Reject invalid login", "Reject <kind> login"));
  assert.ok(errors.some((error) => error.includes("unresolved marker")));
});

test("rejects unknown components", () => {
  const errors = validate(VALID.replace("**Components:** backend-go", "**Components:** frontend"));
  assert.ok(errors.some((error) => error.includes("unknown component")));
});

test("requires atomicity metadata", () => {
  let errors = validate(VALID.replace("**Requirement:** FR-001\n", ""));
  assert.ok(errors.some((error) => error.includes("missing field **Requirement:**")));
  errors = validate(VALID.replace("**Requirement:** FR-001", "**Requirement:** FR-001, FR-002"));
  assert.ok(errors.some((error) => error.includes("Requirement must contain exactly one")));
  errors = validate(VALID.replace("**Depends on:** none", "**Depends on:** 9.9"));
  assert.ok(errors.some((error) => error.includes("dependency must reference an earlier task")));
});

test("enforces mechanical atomicity limits", () => {
  let errors = validate(VALID.replace(
    "**Implementation files:** internal/auth.go",
    "**Implementation files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go",
  ).replace(
    "**Files:** internal/auth.go, internal/auth_test.go",
    "**Files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go, internal/auth_test.go",
  ));
  assert.ok(errors.some((error) => error.includes("implementation files (max 3)")));

  errors = validate(VALID.replace(
    "1. Return unauthorized for an invalid password.",
    "1. Validate the password.\n2. Return unauthorized.\n3. Record the attempt.",
  ));
  assert.ok(errors.some((error) => error.includes("implementation steps (max 2)")));

  errors = validate(VALID.replace(
    "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.",
    "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.\n- `go test -run TestOther ./internal/...` — exit non-zero and failure names the test.",
  ));
  assert.ok(errors.some((error) => error.includes("RED must contain exactly one focused command")));
});

test("accepts dependencies only when they point backward", () => {
  const second = VALID.slice(VALID.indexOf("### [ ] [1.1]"))
    .replace("### [ ] [1.1]", "### [ ] [1.2]")
    .replace("**Requirement:** FR-001", "**Requirement:** FR-002")
    .replace("**Depends on:** none", "**Depends on:** 1.1");
  assert.deepEqual(validate(`${VALID}\n${second}`), []);
});

test("assigns each primary requirement to only one task", () => {
  const second = VALID.slice(VALID.indexOf("### [ ] [1.1]"))
    .replace("### [ ] [1.1]", "### [ ] [1.2]")
    .replace("**Depends on:** none", "**Depends on:** 1.1");
  const errors = validate(`${VALID}\n${second}`);
  assert.ok(errors.some((error) => error.includes("primary Requirement FR-001 already belongs to task 1.1")));
});

test("requires implementation and test files", () => {
  let errors = validate(VALID.replace("**Implementation files:** internal/auth.go\n", ""));
  assert.ok(errors.some((error) => error.includes("missing field **Implementation files:**")));
  errors = validate(VALID.replace("**Test files:** internal/auth_test.go\n", ""));
  assert.ok(errors.some((error) => error.includes("missing field **Test files:**")));
});

test("keeps implementation and tests disjoint and included in Files", () => {
  let errors = validate(VALID.replace("**Test files:** internal/auth_test.go", "**Test files:** internal/auth.go"));
  assert.ok(errors.some((error) => error.includes("implementation/test files overlap")));
  errors = validate(VALID.replace("**Files:** internal/auth.go, internal/auth_test.go", "**Files:** internal/auth.go"));
  assert.ok(errors.some((error) => error.includes("declared file missing from Files")));
});

test("requires canonical headings", () => {
  const errors = validate(VALID.replace("### [ ] [1.1]", "### [1.1]"));
  assert.ok(errors.some((error) => error.includes("malformed task heading")));
  assert.ok(errors.some((error) => error.includes("no canonical task headings")));
});

test("requires complete documentation metadata and evidence", () => {
  let errors = validate(VALID.replace("**Documentation:** N/A", "**Documentation:** REQUIRED"));
  assert.ok(errors.some((error) => error.includes("documentation missing Audience")));

  const documented = VALID.replace(
    "**Documentation:** N/A",
    `**Documentation:** REQUIRED
- **Audience:** API consumers
- **Files:** \`README.md\`
- **Sections:** Authentication
- **Sources:** \`internal/auth.go\`, \`internal/auth_test.go\`
- **Evidence:** \`grep -Fq -- 'invalid password' README.md\` — exit 0.`,
  );
  assert.deepEqual(validate(documented), []);
});

test("rejects RED with incidental environment/toolchain description in v3 plans", () => {
  const incidentalDescriptions = [
    "go test ./... — falha com go.mod ausente antes do módulo existir",
    "go test ./... — fails because file not found",
    "node test.mjs — cannot find main module",
    "go test ./... — no such file or directory",
    "go test ./... — missing module xyz",
    "go test ./... — no module provides package",
  ];
  for (const desc of incidentalDescriptions) {
    const plan = VALID.replace(
      "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.",
      `- \`go test -run TestSomething ./...\` — ${desc}`,
    );
    const errors = validate(plan);
    assert.ok(
      errors.some((e) => e.includes("incidental") || e.includes("toolchain") || e.includes("environment")),
      `expected incidental RED rejection for: ${desc}\ngot errors: ${errors.join("; ")}`,
    );
  }

  // Must NOT reject a RED whose description is assertion-driven
  const assertionPlan = VALID.replace(
    "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.",
    "- `go test -run TestModulePath ./...` — assertion fails: expected module path github.com/example/app",
  );
  assert.deepEqual(validate(assertionPlan), [], "assertion-driven RED must not be rejected");

  // Must emit warning (not error) for v2 plan with incidental RED
  const v2Plan = VALID
    .replace("**Contract version:** 3", "**Contract version:** 2")
    .replace("**Work ID:** 0001\n", "")
    .replace(
      "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.",
      "- `go test ./...` — falha com go.mod ausente",
    );
  const { errors: v2errors, warnings: v2warnings } = validateTasksDetailed((() => {
    const directory = mkdtempSync(path.join(tmpdir(), "v2-incidental-"));
    const file = path.join(directory, "tasks.md");
    writeFileSync(file, v2Plan, "utf8");
    return file;
  })());
  assert.ok(!v2errors.some((e) => e.includes("incidental") || e.includes("toolchain")), "v2 incidental RED must not be an error");
  assert.ok(v2warnings.some((w) => w.includes("incidental") || w.includes("toolchain") || w.includes("environment") || w.includes("legacy")), "v2 incidental RED should produce a warning");
});

test("execute-task.md documents invalid RED and greenfield instruction", () => {
  const ref = readFileSync(
    new URL("../skills/engineering-workflow/references/execute-task.md", import.meta.url),
    "utf8",
  );
  assert.ok(
    /toolchain|incidental/i.test(ref),
    "execute-task.md must define invalid RED (toolchain/incidental failure)",
  );
  assert.ok(
    /greenfield/i.test(ref),
    "execute-task.md must instruct how to handle greenfield tasks for assertion-driven RED",
  );
});
