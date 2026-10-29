package work_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/cryptox"
)

// statusTaskBlock monta um bloco de task v3 estruturalmente válido.
func statusTaskBlock(id, marker, requirement, dependsOn, title string) string {
	return "### [" + marker + "] [" + id + "] " + title + "\n\n" +
		"**Requirement:** " + requirement + "\n" +
		"**Depends on:** " + dependsOn + "\n" +
		"**Behavior:** " + title + " produz um resultado observável.\n" +
		"**Components:** backend\n" +
		"**Files:** src/" + id + ".ts, tests/" + id + ".test.ts\n" +
		"**Implementation files:** src/" + id + ".ts\n" +
		"**Test files:** tests/" + id + ".test.ts\n\n" +
		"**RED:**\n" +
		"- `bun test tests/" + id + ".test.ts` — exit não-zero nomeando a nova asserção.\n\n" +
		"**Implementation:**\n" +
		"1. Implemente apenas o resultado observável declarado.\n\n" +
		"**ACs:**\n" +
		"- [ ] `bun test tests/" + id + ".test.ts` — exit 0 verificando o resultado observável.\n\n" +
		"**Visual:** N/A\n" +
		"**Documentation:** N/A\n"
}

// statusPlanMarkdown monta o plano com um gate global.
func statusPlanMarkdown(tasks []string, global, workID string) string {
	content := "# Tasks: status\n\n**Contract version:** 3\n**Work ID:** " + workID + "\n\n" +
		"## Execution contract\n\n| Component | Purpose |\n|-----------|---------|\n| `backend` | fixture do status |\n\n" +
		"## Global gates\n" + global + "\n\n"
	for _, task := range tasks {
		content += task + "\n"
	}
	return content
}

// writeStatusFixture grava o plano e devolve o caminho do markdown.
func writeStatusFixture(t *testing.T, root, content string) string {
	t.Helper()
	writeFile(t, root, ".todo/0001-tasks.md", content)
	return filepath.Join(root, ".todo", "0001-tasks.md")
}

// collectWithNeutralVerifier roda o status sem aceitação real.
func collectWithNeutralVerifier(t *testing.T, tasksPath string) work.ProjectStatus {
	t.Helper()
	neutralVerifier(t)
	report, err := work.CollectProjectStatus(tasksPath)
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	return report
}

// evidenceStateJSON grava um estado de evidência por task.
func evidenceStateJSON(t *testing.T, root, taskID, body string) {
	t.Helper()
	writeFile(t, root, filepath.Join(".todo", "evidence", "0001", "state", taskID+".json"), body)
}

func TestPanoramaStates(t *testing.T) {
	cases := []struct {
		name      string
		plan      string
		evidence  func(t *testing.T, root string)
		want      string
		stoppedAt string
	}{
		{
			name:      "NOT STARTED",
			plan:      statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"),
			want:      work.PanoramaNotStarted,
			stoppedAt: "Next task: 1.1 — Criar conta",
		},
		{
			name: "IN PROGRESS com evidência parcial",
			plan: statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"),
			evidence: func(t *testing.T, root string) {
				evidenceStateJSON(t, root, "1.1",
					`{"task":"1.1","baseline_implementation":{},"baseline_tests":{},"red_tests":{}}`)
			},
			want:      work.PanoramaInProgress,
			stoppedAt: "Stopped during 1.1 at RED",
		},
		{
			name: "INCONSISTENT STATE com marcador sem recibo",
			plan: statusPlanMarkdown([]string{
				statusTaskBlock("1.1", "x", "FR-001", "none", "Criar conta"),
				statusTaskBlock("1.2", " ", "FR-002", "1.1", "Rejeitar duplicata"),
			}, "N/A", "0001"),
			want:      work.PanoramaInconsistent,
			stoppedAt: "Task 1.1 is checked but evidence stage is not started (sem aprovação de aceitação independente)",
		},
		{
			name: "STALE EVIDENCE",
			plan: statusPlanMarkdown([]string{statusTaskBlock("1.1", "x", "FR-001", "none", "Criar conta")}, "N/A", "0001"),
			evidence: func(t *testing.T, root string) {
				writeFile(t, root, "implementation.ts", "changed\n")
				writeFile(t, root, "implementation.test.ts", "test\n")
				baseline := cryptox.SHA256HexText("original\n")
				testDigest := cryptox.SHA256HexText("test\n")
				body := `{"task":"1.1","baseline_implementation":{},"baseline_tests":{},` +
					`"red_tests":{"` + filepath.Join(root, "implementation.test.ts") + `":{"exists":true,"sha256":"` + testDigest + `"}},` +
					`"green_implementation":{"` + filepath.Join(root, "implementation.ts") + `":{"exists":true,"sha256":"` + baseline + `"}},` +
					`"green_tests":{"` + filepath.Join(root, "implementation.test.ts") + `":{"exists":true,"sha256":"` + testDigest + `"}}}`
				evidenceStateJSON(t, root, "1.1", body)
			},
			want:      work.PanoramaStaleEvidence,
			stoppedAt: "Evidence no longer matches files at 1.1",
		},
		{
			name: "BLOCKED",
			plan: statusPlanMarkdown([]string{
				statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta"),
				"### [!] [1.2] Rejeitar duplicata — bloqueada: contrato externo ausente\n",
			}, "N/A", "0001"),
			want:      work.PanoramaBlocked,
			stoppedAt: "Blocked at 1.2: Rejeitar duplicata — bloqueada: contrato externo ausente",
		},
		{
			name: "INVALID PLAN",
			plan: statusPlanMarkdown([]string{
				"### [ ] [1.1] Criar conta\n\n**Depends on:** none\n**Behavior:** x\n**Components:** backend\n" +
					"**Files:** src/1.1.ts, tests/1.1.test.ts\n**Implementation files:** src/1.1.ts\n**Test files:** tests/1.1.test.ts\n\n" +
					"**RED:**\n- `bun test tests/1.1.test.ts` — falha\n\n**Implementation:**\n1. Implemente.\n\n" +
					"**ACs:**\n- [ ] `bun test tests/1.1.test.ts` — passa\n\n**Visual:** N/A\n**Documentation:** N/A\n",
			}, "N/A", "0001"),
			want:      work.PanoramaInvalidPlan,
			stoppedAt: "Structural validation failed with 1 error(s)",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.evidence != nil {
				test.evidence(t, root)
			}
			tasksPath := writeStatusFixture(t, root, test.plan)
			report := collectWithNeutralVerifier(t, tasksPath)
			if report.Panorama.State != test.want {
				t.Fatalf("panorama = %q, quer %q (stoppedAt=%q)", report.Panorama.State, test.want, report.Panorama.StoppedAt)
			}
			if report.Panorama.StoppedAt != test.stoppedAt {
				t.Fatalf("stoppedAt = %q, quer %q", report.Panorama.StoppedAt, test.stoppedAt)
			}
		})
	}
}

func TestInvalidPlanKeepsTasksAndRendersIssues(t *testing.T) {
	root := t.TempDir()
	content := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001")
	content = replaceOnce(content, "**Requirement:** FR-001\n", "")
	tasksPath := writeStatusFixture(t, root, content)
	report := collectWithNeutralVerifier(t, tasksPath)
	if len(report.Tasks) != 1 {
		t.Fatalf("tasks = %d", len(report.Tasks))
	}
	if len(report.ValidationErrors) != 1 {
		t.Fatalf("validation errors = %v", report.ValidationErrors)
	}
	rendered := work.RenderMarkdown(work.PlanStatus{ProjectStatus: report})
	if !contains(rendered, "## Structural issues") {
		t.Fatalf("markdown sem issues:\n%s", rendered)
	}
}

func TestGlobalGatesBlockedAndNA(t *testing.T) {
	root := t.TempDir()
	blocked := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")},
		"- [!] `node --version` — adiado até o runtime externo ficar disponível.", "0001")
	report := collectWithNeutralVerifier(t, writeStatusFixture(t, root, blocked))
	if report.GlobalGates.State != "BLOCKED" || !contains(report.GlobalGates.Detail, "1 blocked") {
		t.Fatalf("gates = %+v", report.GlobalGates)
	}

	rootNA := t.TempDir()
	na := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001")
	reportNA := collectWithNeutralVerifier(t, writeStatusFixture(t, rootNA, na))
	if reportNA.GlobalGates.State != "N/A" {
		t.Fatalf("gates = %+v", reportNA.GlobalGates)
	}
}

// statusSpec é uma task do fixture com repositório git e verificador.
type statusSpec struct {
	ID          string
	Title       string
	Requirement string
	ContractID  string
	TestPath    string
	ImplPath    string
	TestBody    string
	Baseline    string
	Candidate   string
}

func defaultStatusSpec() statusSpec {
	return statusSpec{
		ID:          "1.1",
		Title:       "Create account",
		Requirement: "FR-001",
		ContractID:  "CTR-001",
		TestPath:    "tests/1.1.test.js",
		ImplPath:    "src/1.1.js",
		TestBody:    "export const test = 1;\n",
		Baseline:    "export const answer = 1;\n",
		Candidate:   "export const answer = 2;\n",
	}
}

// buildStatusPlan monta o plano canônico do fixture.
func buildStatusPlan(specs []statusSpec) plan.Plan {
	command := runtimeExecutable()
	tasks := make([]plan.PlanTask, 0, len(specs))
	for _, spec := range specs {
		tasks = append(tasks, plan.PlanTask{
			ID:                  spec.ID,
			Title:               spec.Title,
			RequirementID:       spec.Requirement,
			DependsOn:           []string{},
			Behavior:            spec.Title + " produces one observable result.",
			Components:          []string{"backend"},
			Files:               []string{spec.ImplPath, spec.TestPath},
			ImplementationFiles: []string{spec.ImplPath},
			TestFiles:           []string{spec.TestPath},
			Red: plan.PlanRed{
				Command:     command + " test " + spec.TestPath,
				Description: "a asserção " + spec.ID + "-RED falha antes da implementação",
			},
			ImplementationSteps: []string{"Implement only the declared observable result."},
			AcceptanceCriteria: []plan.PlanAC{{
				Command:     command + " test " + spec.TestPath,
				Description: "a asserção " + spec.ID + "-AC passa",
			}},
			Visual:        "N/A",
			Documentation: "N/A",
			SpecReference: "CAP-001",
			ContractID:    spec.ContractID,
			Complexity:    "standard",
			Status:        "pending",
		})
	}
	return plan.Plan{
		WorkID: "0001",
		Title:  "Project canônico",
		Components: []plan.PlanComponent{{
			Name:       "backend",
			Purpose:    "fixture do status",
			Root:       new("."),
			Regression: new(command + " test"),
			Lint:       new("N/A"),
			Build:      new("N/A"),
			Security:   new("N/A"),
			Dev:        new("N/A"),
			Health:     new("N/A"),
		}},
		GlobalGates: []string{"`" + command + " --version` — o runtime responde."},
		Tasks:       tasks,
	}
}

// runtimeExecutable devolve o executável do runtime de teste.
func runtimeExecutable() string {
	return runtime.GOROOT() + "/bin/go"
}

// statusVerifierFixture cria o repositório git, o plano, os contratos e a raiz
// do verificador.
func statusVerifierFixture(t *testing.T, specs []statusSpec, checked map[string]bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	verifierRoot := t.TempDir()
	t.Setenv("PWN_VERIFIER_HOME", verifierRoot)

	planValue := buildStatusPlan(specs)
	for index := range planValue.Tasks {
		if checked[planValue.Tasks[index].ID] {
			planValue.Tasks[index].Status = "done"
		}
	}
	markdown := plan.RenderTasksMarkdown(planValue)
	writeFile(t, root, ".todo/0001-tasks.md", markdown)
	writeFile(t, root, ".pwn/work/0001/plan.json", mustJSON(t, planValue))

	for _, spec := range specs {
		writeFile(t, root, spec.ImplPath, spec.Baseline)
		writeFile(t, root, spec.TestPath, spec.TestBody)
		taskContract, err := contract.CreateDefaultContractV4(spec.ID, "0001", spec.Title, contract.RiskL3, nil)
		if err != nil {
			t.Fatalf("CreateDefaultContractV4: %v", err)
		}
		taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{
			Path:   spec.TestPath,
			SHA256: cryptox.SHA256HexText(spec.TestBody),
		}}
		writeFile(t, root, ".pwn/work/0001/"+spec.ContractID+".json", mustJSON(t, taskContract))
	}
	initRepo(t, root)
	commitAll(t, root, "baseline")
	// A entrega candidata difere do baseline aprovado.
	for _, spec := range specs {
		writeFile(t, root, spec.ImplPath, spec.Candidate)
	}
	if _, err := verify.InitializeVerifierHome(verifierRoot); err != nil {
		t.Fatalf("InitializeVerifierHome: %v", err)
	}
	return root, verifierRoot
}

// approveAndStore aprova a task e grava o recibo assinado.
func approveAndStore(t *testing.T, root, verifierRoot, taskID, global string) verify.Approval {
	t.Helper()
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         root,
		WorkID:          "0001",
		TaskID:          taskID,
		Global:          global,
		ApprovedBy:      "verifier-test",
		VerifierRootDir: verifierRoot,
	})
	if err != nil {
		t.Fatalf("CreateApproval(%s/%s): %v", taskID, global, err)
	}
	snapshot, err := verify.CaptureSnapshot(root)
	if err != nil {
		t.Fatalf("CaptureSnapshot: %v", err)
	}
	dependency, err := verify.CaptureDependencyDigest(root)
	if err != nil {
		t.Fatalf("CaptureDependencyDigest: %v", err)
	}
	checks := make([]verify.CheckObservation, 0, len(approval.Checks))
	for _, check := range approval.Checks {
		observation := verify.CheckObservation{
			ID:           check.ID,
			Command:      check.Command,
			Outcome:      "pass",
			ExitCode:     0,
			OutputDigest: cryptox.SHA256HexText("output:" + check.ID),
			OutputTail:   "ok",
		}
		if check.RequireBaselineFailure {
			observation.Baseline = &verify.BaselineObservation{
				ExitCode:     1,
				OutputDigest: cryptox.SHA256HexText("baseline:" + check.ID),
				OutputTail:   "assertion failed",
			}
		}
		checks = append(checks, observation)
	}
	receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
		Approval: approval,
		Result: verify.VerificationRunResult{
			Checks:           checks,
			SnapshotDigest:   snapshot.Digest,
			DependencyDigest: dependency.Digest,
			SandboxDigest:    cryptox.SHA256HexText("sandbox"),
		},
		VerifierRootDir: verifierRoot,
	})
	if err != nil {
		t.Fatalf("BuildReceipt: %v", err)
	}
	if _, err := verify.StoreReceipt(receipt, root, verifierRoot); err != nil {
		t.Fatalf("StoreReceipt: %v", err)
	}
	return approval
}

// writeGreenEvidence grava o estado RED/GREEN mínimo e o log de verify PASS.
func writeGreenEvidence(t *testing.T, root, taskID string) {
	t.Helper()
	evidenceStateJSON(t, root, taskID,
		`{"task":"`+taskID+`","baseline_implementation":{},"baseline_tests":{},"red_tests":{},`+
			`"green_implementation":{},"green_tests":{}}`)
	writeFile(t, root, filepath.Join(".todo", "evidence", "0001", taskID+"-verify.log"), "VERDICT: PASS\n")
}

func TestStatusTasksCompleteAndComplete(t *testing.T) {
	specs := []statusSpec{defaultStatusSpec()}
	root, verifierRoot := statusVerifierFixture(t, specs, map[string]bool{"1.1": true})
	writeGreenEvidence(t, root, "1.1")
	approveAndStore(t, root, verifierRoot, "1.1", "")

	report, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	if report.Tasks[0].Evidence.Stage != "ACCEPTED" {
		t.Fatalf("stage = %s", report.Tasks[0].Evidence.Stage)
	}
	if report.Panorama.State != work.PanoramaTasksComplete {
		t.Fatalf("panorama = %s (%s)", report.Panorama.State, report.Panorama.StoppedAt)
	}
	if report.GlobalGates.State != "PENDING" {
		t.Fatalf("gates = %s — %s", report.GlobalGates.State, report.GlobalGates.Detail)
	}
	if !contains(report.GlobalGates.Detail, "0/1 with independent receipt") || !contains(report.GlobalGates.Detail, "G-1: ") {
		t.Fatalf("detail = %s", report.GlobalGates.Detail)
	}
	rendered := work.RenderMarkdown(work.PlanStatus{ProjectStatus: report})
	if !contains(rendered, "| `1.1` | [x] checked |") || !contains(rendered, "ACCEPTED") {
		t.Fatalf("markdown sem task aceita:\n%s", rendered)
	}

	approveAndStore(t, root, verifierRoot, "", "G-1")
	complete, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	if complete.Panorama.State != work.PanoramaComplete {
		t.Fatalf("panorama = %s (%s)", complete.Panorama.State, complete.Panorama.StoppedAt)
	}
	if complete.Panorama.Progress != 100 {
		t.Fatalf("progress = %d", complete.Panorama.Progress)
	}
	if complete.GlobalGates.State != "PASS" {
		t.Fatalf("gates = %+v", complete.GlobalGates)
	}
}

func TestAcceptedTaskWithOpenMarkerIsInconsistent(t *testing.T) {
	root, verifierRoot := statusVerifierFixture(t, []statusSpec{defaultStatusSpec()}, nil)
	writeGreenEvidence(t, root, "1.1")
	approveAndStore(t, root, verifierRoot, "1.1", "")

	report, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	if report.Tasks[0].Evidence.Stage != "ACCEPTED" {
		t.Fatalf("stage = %s", report.Tasks[0].Evidence.Stage)
	}
	if report.Panorama.State != work.PanoramaInconsistent {
		t.Fatalf("panorama = %s", report.Panorama.State)
	}
	if report.Panorama.StoppedAt != "Task 1.1 has ACCEPTED evidence but marker is not checked" {
		t.Fatalf("stoppedAt = %s", report.Panorama.StoppedAt)
	}
	if report.Panorama.Counts.VerifiedOpen != 1 {
		t.Fatalf("verifiedOpen = %d", report.Panorama.Counts.VerifiedOpen)
	}
}

func TestTreeChangeAfterReceiptRevertsToVerified(t *testing.T) {
	root, verifierRoot := statusVerifierFixture(t, []statusSpec{defaultStatusSpec()}, map[string]bool{"1.1": true})
	writeGreenEvidence(t, root, "1.1")
	approveAndStore(t, root, verifierRoot, "1.1", "")
	approveAndStore(t, root, verifierRoot, "", "G-1")

	before, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Panorama.State != work.PanoramaComplete {
		t.Fatalf("panorama = %s", before.Panorama.State)
	}

	writeFile(t, root, "src/1.1.js", "export const answer = 3;\n")
	after, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Tasks[0].Evidence.Stage != "VERIFIED" {
		t.Fatalf("stage = %s", after.Tasks[0].Evidence.Stage)
	}
	if !contains(after.Tasks[0].Evidence.Attestation, "a árvore mudou depois da verificação independente") {
		t.Fatalf("attestation = %q", after.Tasks[0].Evidence.Attestation)
	}
	if after.Panorama.State != work.PanoramaInconsistent {
		t.Fatalf("panorama = %s", after.Panorama.State)
	}
}

func TestInconsistentOrder(t *testing.T) {
	specs := []statusSpec{
		defaultStatusSpec(),
		{ID: "1.2", Title: "Segunda", Requirement: "FR-002", ContractID: "CTR-002", TestPath: "tests/1.2.test.js", ImplPath: "src/1.2.js", TestBody: "t\n", Baseline: "a\n", Candidate: "b\n"},
		{ID: "1.3", Title: "Terceira", Requirement: "FR-003", ContractID: "CTR-003", TestPath: "tests/1.3.test.js", ImplPath: "src/1.3.js", TestBody: "t\n", Baseline: "a\n", Candidate: "b\n"},
	}
	root, verifierRoot := statusVerifierFixture(t, specs, map[string]bool{"1.1": true, "1.3": true})
	for _, id := range []string{"1.1", "1.3"} {
		writeGreenEvidence(t, root, id)
		approveAndStore(t, root, verifierRoot, id, "")
	}
	report, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Panorama.State != work.PanoramaInconsistentSort {
		t.Fatalf("panorama = %s (%s)", report.Panorama.State, report.Panorama.StoppedAt)
	}
	if report.Panorama.StoppedAt != "Task 1.3 is checked after open task 1.2" {
		t.Fatalf("stoppedAt = %s", report.Panorama.StoppedAt)
	}
}

func TestRealWork0002ReportsInconsistentWithoutReceipts(t *testing.T) {
	neutralVerifier(t)
	source := filepath.Join(repoRoot(t), ".pwn", "work", "0002")
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, ".pwn", "work", "0002"), os.DirFS(source)); err != nil {
		t.Fatalf("copiar Work 0002: %v", err)
	}
	writeFile(t, root, ".todo/0002-tasks.md", readFile(t, repoRoot(t), ".todo/0002-tasks.md"))

	report, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0002-tasks.md"))
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	if len(report.ValidationErrors) != 0 {
		t.Fatalf("Work 0002 real divergiu: %v", report.ValidationErrors)
	}
	if len(report.Tasks) != 5 {
		t.Fatalf("tasks = %d", len(report.Tasks))
	}
	if report.WorkID == nil || *report.WorkID != "0002" {
		t.Fatalf("workId = %v", report.WorkID)
	}
	if report.Panorama.State != work.PanoramaInconsistent {
		t.Fatalf("panorama = %s (%s)", report.Panorama.State, report.Panorama.StoppedAt)
	}
	if report.Panorama.Counts.UnverifiedChecked != 5 {
		t.Fatalf("unverifiedChecked = %d", report.Panorama.Counts.UnverifiedChecked)
	}
}

func TestCollectWorkIndexAndRenderWorkIndex(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	writeFile(t, root, ".pwn/work/0001/intake.json", "{}")
	writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"))
	report, err := work.CollectWorkIndex(root)
	if err != nil {
		t.Fatalf("CollectWorkIndex: %v", err)
	}
	if len(report.Works) != 1 || report.Works[0].Panorama == nil {
		t.Fatalf("works = %+v", report.Works)
	}
	rendered := work.RenderWorkIndex(work.WorkIndexReport{})
	if !contains(rendered, "No work artifacts found") {
		t.Fatalf("índice vazio:\n%s", rendered)
	}
}

// mustJSON serializa value com indentação de dois espaços.
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return string(data) + "\n"
}

// replaceOnce substitui a primeira ocorrência.
func replaceOnce(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}

// contains informa se value contém substr.
func contains(value, substr string) bool {
	for index := 0; index+len(substr) <= len(value); index++ {
		if value[index:index+len(substr)] == substr {
			return true
		}
	}
	return false
}
