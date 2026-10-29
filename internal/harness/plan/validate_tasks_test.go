package plan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
)

// validTasksTemplate é o plano v3 válido do teste de referência. O símbolo §
// representa uma crase, que não cabe em uma string crua de Go.
const validTasksTemplate = `# Tasks: auth
**Contract version:** 3
**Work ID:** 0001

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| backend-go | §.§ | §go test ./...§ | §N/A§ | §go build ./...§ | §N/A§ | §N/A§ | §N/A§ |

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
- §go test -run TestInvalidLogin ./internal/...§ — exit non-zero and failure names the test.

**Implementation:**
1. Return unauthorized for an invalid password.

**ACs:**
- [ ] §go test -run TestInvalidLogin ./internal/...§ — exit 0.

**Visual:** N/A

**Documentation:** N/A
`

func validTasks() string {
	return strings.ReplaceAll(validTasksTemplate, "§", "`")
}

// writePlan grava content em <dir>/.todo/0001-tasks.md e devolve o caminho.
func writePlan(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, ".todo", "0001-tasks.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writePlanWithSpec grava o plano e a spec do sistema usada nas declarações de
// dependência.
func writePlanWithSpec(t *testing.T, dir, content, specContent string) string {
	t.Helper()
	path := writePlan(t, dir, content)
	spec := filepath.Join(dir, ".specs", "system.md")
	if err := os.MkdirAll(filepath.Dir(spec), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec, []byte(specContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func validateContent(t *testing.T, content string) []string {
	t.Helper()
	return plan.ValidateTasks(writePlan(t, t.TempDir(), content), plan.AnalyzeOptions{})
}

func validateContentDetailed(t *testing.T, content string) plan.TaskAnalysis {
	t.Helper()
	return plan.ValidateTasksDetailed(writePlan(t, t.TempDir(), content), plan.AnalyzeOptions{})
}

func mustContain(t *testing.T, issues []string, substr string) {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue, substr) {
			return
		}
	}
	t.Fatalf("nenhum diagnóstico contém %q; issues=%q", substr, issues)
}

func TestAcceptsCanonicalCurrentContractTask(t *testing.T) {
	result := validateContentDetailed(t, validTasks())
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("avisos inesperados: %q", result.Warnings)
	}
	if result.ContractVersion == nil || *result.ContractVersion != plan.CurrentTaskContractVersion {
		t.Fatalf("contractVersion=%v", result.ContractVersion)
	}
	if result.WorkID == nil || *result.WorkID != "0001" {
		t.Fatalf("workId=%v", result.WorkID)
	}
}

func TestLegacyPlanStillExecutable(t *testing.T) {
	legacy := validTasks()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "**Requirement:** FR-001\n", "", 1)
	legacy = strings.Replace(legacy, "**Depends on:** none\n", "", 1)
	result := plan.ValidateTasksDetailed(writePlan(t, t.TempDir(), legacy), plan.AnalyzeOptions{})
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	if result.ContractVersion == nil || *result.ContractVersion != plan.LegacyTaskContractVersion {
		t.Fatalf("contractVersion=%v", result.ContractVersion)
	}
	mustContain(t, result.Warnings, "contract version is missing")
	mustContain(t, result.Warnings, "missing field **Requirement:**")
	mustContain(t, result.Warnings, "missing field **Depends on:**")
}

func TestTaskContractV2ReadableAndMigratable(t *testing.T) {
	previous := strings.Replace(validTasks(), "**Contract version:** 3", "**Contract version:** 2", 1)
	previous = strings.Replace(previous, "**Work ID:** 0001\n", "", 1)
	analyzed := plan.ValidateTasksDetailed(writePlan(t, t.TempDir(), previous), plan.AnalyzeOptions{})
	if len(analyzed.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", analyzed.Errors)
	}
	if analyzed.ContractVersion == nil || *analyzed.ContractVersion != plan.PreviousTaskContractVersion {
		t.Fatalf("contractVersion=%v", analyzed.ContractVersion)
	}
	mustContain(t, analyzed.Warnings, "contract version 2 is legacy")

	migrated := plan.MigrateTasksContent(previous, plan.MigrateOptions{WorkID: "0042"})
	if len(migrated.Errors) != 0 {
		t.Fatalf("erros de migração: %q", migrated.Errors)
	}
	mustContain(t, []string{migrated.Content}, "**Contract version:** 3")
	mustContain(t, []string{migrated.Content}, "**Migrated from task contract:** 2")
	mustContain(t, []string{migrated.Content}, "**Work ID:** 0042")
}

func TestStrictModePromotesCompatibilityWarnings(t *testing.T) {
	legacy := strings.Replace(validTasks(), "**Contract version:** 3\n", "", 1)
	result := plan.ValidateTasksDetailed(writePlan(t, t.TempDir(), legacy), plan.AnalyzeOptions{Strict: true})
	mustContain(t, result.Errors, "compatibility warning treated as error")
	if len(result.Warnings) != 0 {
		t.Errorf("avisos deveriam ter sido promovidos: %q", result.Warnings)
	}
}

func TestMigratesLegacyPlanMechanically(t *testing.T) {
	legacy := validTasks()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "**Requirement:** FR-001\n", "", 1)
	legacy = strings.Replace(legacy, "**Depends on:** none\n", "", 1)
	migrated := plan.MigrateTasksContent(legacy, plan.MigrateOptions{WorkID: "0001"})
	if len(migrated.Errors) != 0 {
		t.Fatalf("erros de migração: %q", migrated.Errors)
	}
	mustContain(t, []string{migrated.Content}, "**Contract version:** 3")
	mustContain(t, []string{migrated.Content}, "**Migrated from task contract:** 1")
	mustContain(t, []string{migrated.Content}, "**Requirement:** SOURCE-001")
	mustContain(t, []string{migrated.Content}, "**Depends on:** none")

	repeated := plan.MigrateTasksContent(migrated.Content, plan.MigrateOptions{WorkID: "0001"})
	if len(repeated.Errors) != 0 {
		t.Fatalf("erros da segunda migração: %q", repeated.Errors)
	}
	if len(repeated.Changes) != 0 {
		t.Errorf("migração deveria ser idempotente; changes=%q", repeated.Changes)
	}
	if repeated.Content != migrated.Content {
		t.Error("migração repetida alterou o conteúdo")
	}
}

func TestMigratesLegacyAtomicityAllowances(t *testing.T) {
	legacy := validTasks()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy,
		"**Files:** internal/auth.go, internal/auth_test.go",
		"**Files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go, internal/auth_test.go", 1)
	legacy = strings.Replace(legacy,
		"**Implementation files:** internal/auth.go",
		"**Implementation files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go", 1)
	migrated := plan.MigrateTasksContent(legacy, plan.MigrateOptions{WorkID: "0001"})
	if len(migrated.Errors) != 0 {
		t.Fatalf("erros de migração: %q", migrated.Errors)
	}
	mustContain(t, []string{migrated.Content}, "**Legacy allowances:** implementation-files=4")

	path := writePlan(t, t.TempDir(), migrated.Content)
	result := plan.ValidateTasksDetailed(path, plan.AnalyzeOptions{Strict: true})
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	mustContain(t, result.Exceptions, "implementation-files=4")

	expanded := strings.Replace(migrated.Content, "internal/c.go, internal/auth_test.go", "internal/c.go, internal/d.go, internal/auth_test.go", 1)
	expanded = strings.Replace(expanded, "internal/c.go\n**Test files", "internal/c.go, internal/d.go\n**Test files", 1)
	if err := os.WriteFile(path, []byte(expanded), 0o644); err != nil {
		t.Fatal(err)
	}
	expandedResult := plan.ValidateTasksDetailed(path, plan.AnalyzeOptions{})
	mustContain(t, expandedResult.Errors, "5 implementation files (max 3)")
	mustContain(t, expandedResult.Errors, "stale legacy allowance implementation-files=4")
}

func TestRejectsInventedLegacyAllowances(t *testing.T) {
	invented := strings.Replace(validTasks(), "**Depends on:** none", "**Depends on:** none\n**Legacy allowances:** implementation-files=4", 1)
	mustContain(t, validateContent(t, invented), "require a v3 plan marked as migrated from v1 or v2")
}

func TestValidateTasksCLIMigrates(t *testing.T) {
	legacy := validTasks()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "**Requirement:** FR-001\n", "", 1)
	legacy = strings.Replace(legacy, "**Depends on:** none\n", "", 1)
	path := writePlan(t, t.TempDir(), legacy)

	var stdout, stderr bytes.Buffer
	if code := plan.ValidateTasksMain([]string{"--migrate", "--work", "0001", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("preview falhou: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "MIGRATION PREVIEW") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if data, _ := os.ReadFile(path); string(data) != legacy {
		t.Fatal("preview alterou o arquivo")
	}

	stdout.Reset()
	if code := plan.ValidateTasksMain([]string{"--migrate", "--work", "0001", "--write", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("aplicação falhou: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "MIGRATED") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "**Contract version:** 3") {
		t.Fatal("arquivo não foi migrado")
	}

	stdout.Reset()
	if code := plan.ValidateTasksMain([]string{"--strict", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("strict falhou: code=%d out=%q", code, stdout.String())
	}
	stdout.Reset()
	if code := plan.ValidateTasksMain([]string{"--migrate", "--work", "0001", "--write", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("repetição falhou: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "MIGRATION N/A") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestDoesNotHideSafetyFailuresInLegacyMode(t *testing.T) {
	legacy := strings.Replace(validTasks(), "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin", 1)
	mustContain(t, validateContent(t, legacy), "unsafe command")
}

func TestRejectsUnsafeCommands(t *testing.T) {
	unsafe := strings.Replace(validTasks(), "go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin", 1)
	mustContain(t, validateContent(t, unsafe), "unsafe command")
}

func TestAllowsDeclaredDependencyInstallation(t *testing.T) {
	planText := strings.Replace(validTasks(), "**Depends on:** none", `**Depends on:** none
**Dependency installations:**
- §npm install fastify@4§ — declared in §.specs/system.md§.`, 1)
	planText = strings.ReplaceAll(planText, "§", "`")

	cases := []struct {
		name      string
		command   string
		spec      string
		wantError string
	}{
		{name: "npm", command: "npm install fastify@4", spec: "# System spec\n\n**Dependencies:** `fastify`\n"},
		{name: "escopo npm", command: "npm install @fastify/cors@8", spec: "# System spec\n\n**Dependencies:** `@fastify/cors`\n"},
		{name: "go get", command: "go get github.com/google/uuid@v1.6.0", spec: "# System spec\n\n**Dependencies:** `github.com/google/uuid`\n"},
		{name: "dois pacotes", command: "npm install fastify@4 pino@9", spec: "# System spec\n\n**Dependencies:** `fastify`, `pino`\n"},
		{name: "spec parcial", command: "npm install fastify@4 pino@9", spec: "# System spec\n\n**Dependencies:** `fastify`\n", wantError: "dependency pino is not declared"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			content := strings.Replace(planText, "npm install fastify@4", testCase.command, 1)
			path := writePlanWithSpec(t, t.TempDir(), content, testCase.spec)
			errors := plan.ValidateTasks(path, plan.AnalyzeOptions{})
			if testCase.wantError == "" {
				if len(errors) != 0 {
					t.Fatalf("erros inesperados: %q", errors)
				}
				return
			}
			mustContain(t, errors, testCase.wantError)
		})
	}
}

func TestRejectsDependencyInstallationAbsentFromSpec(t *testing.T) {
	planText := strings.Replace(validTasks(), "**Depends on:** none", `**Depends on:** none
**Dependency installations:**
- §npm install fastify@4§ — declared in §.specs/system.md§.`, 1)
	planText = strings.ReplaceAll(planText, "§", "`")

	path := writePlanWithSpec(t, t.TempDir(), planText, "# System spec\n\nNo HTTP framework is selected.\n")
	errors := plan.ValidateTasks(path, plan.AnalyzeOptions{})
	mustContain(t, errors, "dependency fastify is not declared")
	mustContain(t, errors, "unsafe command (package installation)")

	path = writePlanWithSpec(t, t.TempDir(), planText, "# System spec\n\nDo not use fastify; the selected HTTP transport is different.\n")
	mustContain(t, plan.ValidateTasks(path, plan.AnalyzeOptions{}), "dependency fastify is not declared")
}

func TestDependencyInstallationVariants(t *testing.T) {
	planText := strings.Replace(validTasks(), "**Depends on:** none", `**Depends on:** none
**Dependency installations:**
- §npm install fastify@4§ — declared in §.specs/system.md§.`, 1)
	planText = strings.ReplaceAll(planText, "§", "`")

	t.Run("sudo na instalação", func(t *testing.T) {
		content := strings.Replace(planText, "npm install fastify@4", "sudo npm install fastify@4", 1)
		path := writePlanWithSpec(t, t.TempDir(), content, "# System spec\n\n**Dependencies:** `fastify`\n")
		mustContain(t, plan.ValidateTasks(path, plan.AnalyzeOptions{}), "unsafe command (sudo)")
	})
	t.Run("instalação global", func(t *testing.T) {
		content := strings.Replace(planText, "npm install fastify@4", "npm install -g fastify@4", 1)
		path := writePlanWithSpec(t, t.TempDir(), content, "# System spec\n\n**Dependencies:** `fastify`\n")
		mustContain(t, plan.ValidateTasks(path, plan.AnalyzeOptions{}), "invalid dependency installation")
	})
}

func TestRejectsUnresolvedMarkers(t *testing.T) {
	mustContain(t, validateContent(t, strings.Replace(validTasks(), "Reject invalid login", "Reject <kind> login", 1)), "unresolved marker")
}

func TestRejectsUnknownComponents(t *testing.T) {
	mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Components:** backend-go", "**Components:** frontend", 1)), "unknown component")
}

func TestRequiresAtomicityMetadata(t *testing.T) {
	t.Run("requirement ausente", func(t *testing.T) {
		mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Requirement:** FR-001\n", "", 1)), "missing field **Requirement:**")
	})
	t.Run("dois requisitos", func(t *testing.T) {
		mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Requirement:** FR-001", "**Requirement:** FR-001, FR-002", 1)), "Requirement must contain exactly one")
	})
	t.Run("dependência futura", func(t *testing.T) {
		mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Depends on:** none", "**Depends on:** 9.9", 1)), "dependency must reference an earlier task")
	})
}

func TestEnforcesMechanicalAtomicityLimits(t *testing.T) {
	t.Run("arquivos de implementação", func(t *testing.T) {
		content := strings.Replace(validTasks(),
			"**Implementation files:** internal/auth.go",
			"**Implementation files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go", 1)
		content = strings.Replace(content,
			"**Files:** internal/auth.go, internal/auth_test.go",
			"**Files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go, internal/auth_test.go", 1)
		mustContain(t, validateContent(t, content), "implementation files (max 3)")
	})
	t.Run("passos de implementação", func(t *testing.T) {
		content := strings.Replace(validTasks(),
			"1. Return unauthorized for an invalid password.",
			"1. Validate the password.\n2. Return unauthorized.\n3. Record the attempt.", 1)
		mustContain(t, validateContent(t, content), "implementation steps (max 2)")
	})
	t.Run("dois comandos de RED", func(t *testing.T) {
		red := "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test."
		content := strings.Replace(validTasks(), red, red+"\n- `go test -run TestOther ./internal/...` — exit non-zero and failure names the test.", 1)
		mustContain(t, validateContent(t, content), "RED must contain exactly one focused command")
	})
}

func TestAcceptsBackwardDependencies(t *testing.T) {
	base := validTasks()
	second := base[strings.Index(base, "### [ ] [1.1]"):]
	second = strings.Replace(second, "### [ ] [1.1]", "### [ ] [1.2]", 1)
	second = strings.Replace(second, "**Requirement:** FR-001", "**Requirement:** FR-002", 1)
	second = strings.Replace(second, "**Depends on:** none", "**Depends on:** 1.1", 1)
	if errors := validateContent(t, base+"\n"+second); len(errors) != 0 {
		t.Fatalf("erros inesperados: %q", errors)
	}
}

func TestAssignsRequirementToSingleTask(t *testing.T) {
	base := validTasks()
	second := base[strings.Index(base, "### [ ] [1.1]"):]
	second = strings.Replace(second, "### [ ] [1.1]", "### [ ] [1.2]", 1)
	second = strings.Replace(second, "**Depends on:** none", "**Depends on:** 1.1", 1)
	mustContain(t, validateContent(t, base+"\n"+second), "primary Requirement FR-001 already belongs to task 1.1")
}

func TestRequiresImplementationAndTestFiles(t *testing.T) {
	t.Run("implementation files", func(t *testing.T) {
		mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Implementation files:** internal/auth.go\n", "", 1)), "missing field **Implementation files:**")
	})
	t.Run("test files", func(t *testing.T) {
		mustContain(t, validateContent(t, strings.Replace(validTasks(), "**Test files:** internal/auth_test.go\n", "", 1)), "missing field **Test files:**")
	})
}

func TestKeepsImplementationAndTestsDisjoint(t *testing.T) {
	t.Run("sobreposição", func(t *testing.T) {
		content := strings.Replace(validTasks(), "**Test files:** internal/auth_test.go", "**Test files:** internal/auth.go", 1)
		mustContain(t, validateContent(t, content), "implementation/test files overlap")
	})
	t.Run("arquivo fora de Files", func(t *testing.T) {
		content := strings.Replace(validTasks(), "**Files:** internal/auth.go, internal/auth_test.go", "**Files:** internal/auth.go", 1)
		mustContain(t, validateContent(t, content), "declared file missing from Files")
	})
}

func TestRequiresCanonicalHeadings(t *testing.T) {
	errors := validateContent(t, strings.Replace(validTasks(), "### [ ] [1.1]", "### [1.1]", 1))
	mustContain(t, errors, "malformed task heading")
	mustContain(t, errors, "no canonical task headings")
}

func TestRequiresDocumentationMetadataAndEvidence(t *testing.T) {
	content := strings.Replace(validTasks(), "**Documentation:** N/A", "**Documentation:** REQUIRED", 1)
	mustContain(t, validateContent(t, content), "documentation missing Audience")

	documented := strings.Replace(validTasks(), "**Documentation:** N/A", `**Documentation:** REQUIRED
- **Audience:** API consumers
- **Files:** §README.md§
- **Sections:** Authentication
- **Sources:** §internal/auth.go§, §internal/auth_test.go§
- **Evidence:** §grep -Fq -- 'invalid password' README.md§ — exit 0.`, 1)
	documented = strings.ReplaceAll(documented, "§", "`")
	if errors := validateContent(t, documented); len(errors) != 0 {
		t.Fatalf("erros inesperados: %q", errors)
	}
}

func TestRejectsIncidentalRedDescription(t *testing.T) {
	red := "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test."
	descriptions := []string{
		"go test ./... — falha com go.mod ausente antes do módulo existir",
		"go test ./... — fails because file not found",
		"node test.mjs — cannot find main module",
		"go test ./... — no such file or directory",
		"go test ./... — missing module xyz",
		"go test ./... — no module provides package",
	}
	for _, description := range descriptions {
		content := strings.Replace(validTasks(), red, "- `go test -run TestSomething ./...` — "+description, 1)
		errors := validateContent(t, content)
		found := false
		for _, issue := range errors {
			if strings.Contains(issue, "incidental") || strings.Contains(issue, "toolchain") || strings.Contains(issue, "environment") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("esperava rejeição incidental para %q; erros=%q", description, errors)
		}
	}

	assertion := strings.Replace(validTasks(), red, "- `go test -run TestModulePath ./...` — assertion fails: expected module path github.com/example/app", 1)
	if errors := validateContent(t, assertion); len(errors) != 0 {
		t.Fatalf("RED com asserção não deveria ser recusado: %q", errors)
	}

	v2 := strings.Replace(validTasks(), "**Contract version:** 3", "**Contract version:** 2", 1)
	v2 = strings.Replace(v2, "**Work ID:** 0001\n", "", 1)
	v2 = strings.Replace(v2, red, "- `go test ./...` — falha com go.mod ausente", 1)
	result := plan.ValidateTasksDetailed(writePlan(t, t.TempDir(), v2), plan.AnalyzeOptions{})
	for _, issue := range result.Errors {
		if strings.Contains(issue, "incidental") || strings.Contains(issue, "toolchain") {
			t.Fatalf("v2 não deveria ter erro incidental: %q", issue)
		}
	}
	found := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "incidental") || strings.Contains(warning, "toolchain") || strings.Contains(warning, "environment") || strings.Contains(warning, "legacy") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("v2 deveria emitir aviso incidental; warnings=%q", result.Warnings)
	}
}

func TestRejectsGenericAcceptanceCriteria(t *testing.T) {
	ac := "- [ ] `go test -run TestInvalidLogin ./internal/...` — exit 0."
	t.Run("suíte inteira", func(t *testing.T) {
		content := strings.Replace(validTasks(), ac, "- [ ] `bun test` — exit 0.", 1)
		mustContain(t, validateContent(t, content), "suíte inteira sem alvo")
	})
	t.Run("vácuo", func(t *testing.T) {
		content := strings.Replace(validTasks(), ac, "- [ ] `true` — exit 0.", 1)
		mustContain(t, validateContent(t, content), "não exercita comportamento")
	})
	t.Run("repete gate", func(t *testing.T) {
		content := strings.Replace(validTasks(), "## Global gates\nN/A", "## Global gates\n- [ ] `go test ./...` — a suíte passa.", 1)
		content = strings.Replace(content, ac, "- [ ] `go test ./...` — a suíte passa.", 1)
		mustContain(t, validateContent(t, content), "repete um gate global")
	})
}

func TestRejectsGenericRed(t *testing.T) {
	red := "- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test."
	content := strings.ReplaceAll(validTasks(), "`go test ./...`", "`N/A`")
	content = strings.Replace(content, red, "- `go test ./...` — a suíte falha.", 1)
	mustContain(t, validateContent(t, content), "suíte inteira sem alvo")
}

func TestRejectsNonConcretePaths(t *testing.T) {
	directory := strings.Replace(validTasks(), "**Implementation files:** internal/auth.go", "**Implementation files:** src/", 1)
	mustContain(t, validateContent(t, directory), "é diretório, não arquivo")
	glob := strings.Replace(validTasks(), "**Test files:** internal/auth_test.go", "**Test files:** tests/**", 1)
	mustContain(t, validateContent(t, glob), "é glob, não arquivo")
}

func TestRejectsGateWithoutCommand(t *testing.T) {
	content := strings.Replace(validTasks(), "## Global gates\nN/A", "## Global gates\n- [ ] a suíte passa.", 1)
	mustContain(t, validateContent(t, content), "global gate without an executable command in backticks")
}
