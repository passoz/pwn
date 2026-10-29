package work_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
)

// reconcileFixture cria um repositório com um commit-base e uma mudança feita
// fora do pwn.
type reconcileFixture struct {
	root string
	base string
}

func newReconcileFixture(t *testing.T) reconcileFixture {
	t.Helper()
	root := t.TempDir()
	initRepo(t, root)
	writeFile(t, root, "package.json", "{\"name\":\"x\"}\n")
	writeFile(t, root, "src/add.ts", "export const add = (a: number, b: number) => a - b;\n")
	base := commitAll(t, root, "base")
	writeFile(t, root, "src/add.ts", "export const add = (a: number, b: number) => a + b;\n")
	writeFile(t, root, "tests/add.test.ts", "import { test } from 'bun:test';\ntest('soma', () => {});\n")
	return reconcileFixture{root: root, base: base}
}

func TestDetectChangesIgnoresGovernanceAndSecrets(t *testing.T) {
	fx := newReconcileFixture(t)
	writeFile(t, fx.root, ".env.local", "SECRET=1\n")
	writeFile(t, fx.root, ".todo/0001-tasks.md", "x\n")
	writeFile(t, fx.root, "queue/review/a.json", "{}\n")

	detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatalf("DetectChanges: %v", err)
	}
	if detected.BaseCommit != fx.base {
		t.Fatalf("base = %s, quer %s", detected.BaseCommit, fx.base)
	}
	if len(detected.Changes) != 2 {
		t.Fatalf("changes = %+v", detected.Changes)
	}
	if detected.Changes[0].Path != "src/add.ts" || detected.Changes[0].Status != work.ChangeModified || detected.Changes[0].Kind != "implementation" {
		t.Fatalf("change 0 = %+v", detected.Changes[0])
	}
	if detected.Changes[1].Path != "tests/add.test.ts" || detected.Changes[1].Status != work.ChangeAdded || detected.Changes[1].Kind != "test" {
		t.Fatalf("change 1 = %+v", detected.Changes[1])
	}
	if len(detected.Skipped) != 1 || detected.Skipped[0].Path != ".env.local" {
		t.Fatalf("skipped = %+v", detected.Skipped)
	}
}

func TestDetectChangesPathsAndSince(t *testing.T) {
	fx := newReconcileFixture(t)
	commitAll(t, fx.root, "fora do pwn")
	if detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root}); err != nil || len(detected.Changes) != 0 {
		t.Fatalf("sem mudanças desde HEAD: %+v err=%v", detected.Changes, err)
	}
	since, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root, Since: fx.base, Paths: []string{"src"}})
	if err != nil {
		t.Fatalf("DetectChanges: %v", err)
	}
	if since.BaseCommit != fx.base || len(since.Changes) != 1 || since.Changes[0].Path != "src/add.ts" {
		t.Fatalf("since = %+v", since)
	}
	if _, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root, Since: "nao-existe"}); err == nil {
		t.Fatal("--since inválido devia falhar")
	}
}

func TestDetectChangesDeletedFile(t *testing.T) {
	fx := newReconcileFixture(t)
	if err := os.Remove(filepath.Join(fx.root, "src/add.ts")); err != nil {
		t.Fatal(err)
	}
	detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range detected.Changes {
		if change.Path != "src/add.ts" {
			continue
		}
		if change.Status != work.ChangeDeleted || change.SHA256 != nil {
			t.Fatalf("change = %+v", change)
		}
		return
	}
	t.Fatalf("arquivo removido ausente: %+v", detected.Changes)
}

func TestReconcileCreatesWorkThatPassesGates(t *testing.T) {
	fx := newReconcileFixture(t)
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Title: "Corrige soma do add"})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if result.WorkID == nil || *result.WorkID != "0001" {
		t.Fatalf("WorkID = %v", result.WorkID)
	}
	if len(result.Tasks) != 1 {
		t.Fatalf("tasks = %+v", result.Tasks)
	}
	task := result.Tasks[0]
	if task.ID != "1.1" || len(task.ImplementationFiles) != 1 || task.ImplementationFiles[0] != "src/add.ts" ||
		len(task.TestFiles) != 1 || task.TestFiles[0] != "tests/add.test.ts" || task.TestsToWrite {
		t.Fatalf("task = %+v", task)
	}

	taskContract, err := plan.LoadTaskContract("0001", "1.1", fx.root)
	if err != nil {
		t.Fatalf("LoadTaskContract: %v", err)
	}
	if len(taskContract.ScopeContract.WriteAllow) != 2 ||
		taskContract.ScopeContract.WriteAllow[0] != "src/add.ts" ||
		taskContract.ScopeContract.WriteAllow[1] != "tests/add.test.ts" {
		t.Fatalf("write_allow = %v", taskContract.ScopeContract.WriteAllow)
	}
	if !containsSlice(taskContract.ScopeContract.WriteDeny, "package.json") {
		t.Fatalf("write_deny = %v", taskContract.ScopeContract.WriteDeny)
	}

	record := work.ReadReconciliation(fx.root, "0001")
	if record == nil || record.BaseCommit != fx.base {
		t.Fatalf("record = %+v", record)
	}
	if len(record.Files) != 2 || record.Files[0].Path != "src/add.ts" || record.Files[1].Path != "tests/add.test.ts" {
		t.Fatalf("files = %+v", record.Files)
	}

	outputs := gates.EvaluateAllGates("0001", work.GetWorkArtifactsPaths("0001", fx.root).WorkDir)
	for _, output := range outputs {
		if output.Result != gates.ResultPass {
			t.Fatalf("%s = %s: %+v", output.Gate, output.Result, output.Findings)
		}
	}
	// O teste ainda não está commitado: congelar fica pendente, nunca é fingido.
	if len(result.Frozen) != 0 {
		t.Fatalf("frozen = %v", result.Frozen)
	}
	if len(result.PendingFreeze) != 1 || result.PendingFreeze[0].Task != "1.1" {
		t.Fatalf("pendingFreeze = %+v", result.PendingFreeze)
	}
}

func TestReconcileFreezesCommittedTestsAndUsesBaseCommit(t *testing.T) {
	fx := newReconcileFixture(t)
	commitAll(t, fx.root, "fora do pwn")
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Since: fx.base})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if len(result.Frozen) != 1 || result.Frozen[0] != "1.1" {
		t.Fatalf("frozen = %v", result.Frozen)
	}
	taskContract, err := plan.LoadTaskContract(*result.WorkID, "1.1", fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(taskContract.AcceptanceContract.FrozenTests) != 1 ||
		taskContract.AcceptanceContract.FrozenTests[0].Path != "tests/add.test.ts" {
		t.Fatalf("frozen_tests = %+v", taskContract.AcceptanceContract.FrozenTests)
	}

	record := work.ReadReconciliation(fx.root, *result.WorkID)
	if record == nil {
		t.Fatal("registro ausente")
	}
	verifierRoot := t.TempDir()
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fx.root,
		WorkID:          *result.WorkID,
		TaskID:          "1.1",
		ApprovedBy:      "teste",
		VerifierRootDir: verifierRoot,
		BaselineCommit:  record.BaseCommit,
	})
	if err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	head := trimSpace(git(t, fx.root, "rev-parse", "HEAD"))
	if approval.BaselineCommit != fx.base || approval.BaselineCommit == head {
		t.Fatalf("baseline = %s, base = %s, head = %s", approval.BaselineCommit, fx.base, head)
	}
	if _, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fx.root,
		WorkID:          *result.WorkID,
		TaskID:          "1.1",
		ApprovedBy:      "teste",
		VerifierRootDir: verifierRoot,
		BaselineCommit:  "0000000000000000000000000000000000000000",
	}); err == nil {
		t.Fatal("baseline inexistente devia falhar")
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	fx := newReconcileFixture(t)
	if _, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root}); err != nil {
		t.Fatalf("primeira conciliação: %v", err)
	}
	if _, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root}); err == nil ||
		!contains(err.Error(), "já conciliado no Work 0001") {
		t.Fatalf("segunda conciliação devia recusar: %v", err)
	}

	writeFile(t, fx.root, "src/add.ts", "export const add = (a: number, b: number) => b + a;\n")
	again, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Tests: []string{"tests/add.test.ts"}, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(again.Changes) != 1 || again.Changes[0].Path != "src/add.ts" {
		t.Fatalf("changes = %+v", again.Changes)
	}
}

func TestReconcileWithoutTestDeclaresTestToWrite(t *testing.T) {
	fx := newReconcileFixture(t)
	if err := os.RemoveAll(filepath.Join(fx.root, "tests")); err != nil {
		t.Fatal(err)
	}
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if len(result.Tasks) != 1 || !result.Tasks[0].TestsToWrite ||
		len(result.Tasks[0].TestFiles) != 1 || result.Tasks[0].TestFiles[0] != "tests/add.test.ts" {
		t.Fatalf("tasks = %+v", result.Tasks)
	}
	if len(result.Frozen) != 0 {
		t.Fatalf("frozen = %v", result.Frozen)
	}
	if len(result.PendingFreeze) != 1 || !contains(result.PendingFreeze[0].Reason, "teste a escrever") {
		t.Fatalf("pendingFreeze = %+v", result.PendingFreeze)
	}
	if _, err := os.Stat(filepath.Join(fx.root, "tests/add.test.ts")); !os.IsNotExist(err) {
		t.Fatal("o pwn não pode escrever no projeto")
	}
	taskContract, err := plan.LoadTaskContract(*result.WorkID, "1.1", fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSlice(taskContract.ScopeContract.WriteAllow, "tests/add.test.ts") {
		t.Fatalf("write_allow = %v", taskContract.ScopeContract.WriteAllow)
	}
	for _, output := range gates.EvaluateAllGates(*result.WorkID, work.GetWorkArtifactsPaths(*result.WorkID, fx.root).WorkDir) {
		if output.Result != gates.ResultPass {
			t.Fatalf("%s = %s", output.Gate, output.Result)
		}
	}

	// Depois: o teste é escrito e commitado, congela, e a aprovação usa a base.
	writeFile(t, fx.root, "tests/add.test.ts", "import { test } from 'bun:test';\ntest('soma', () => {});\n")
	commitAll(t, fx.root, "teste escrito depois")
	if _, err := plan.FreezeAcceptanceTests(t.Context(), plan.FreezeOptions{
		WorkID: *result.WorkID, TaskID: "1.1", Paths: []string{"tests/add.test.ts"}, RootDir: fx.root,
	}); err != nil {
		t.Fatalf("FreezeAcceptanceTests: %v", err)
	}
	verifierRoot := t.TempDir()
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fx.root,
		WorkID:          *result.WorkID,
		TaskID:          "1.1",
		ApprovedBy:      "teste",
		VerifierRootDir: verifierRoot,
		BaselineCommit:  work.ReadReconciliation(fx.root, *result.WorkID).BaseCommit,
	})
	if err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	if approval.BaselineCommit != fx.base {
		t.Fatalf("baseline = %s", approval.BaselineCommit)
	}
}

func TestReconcileSkeletonNeverReusesExistingPath(t *testing.T) {
	fx := newReconcileFixture(t)
	git(t, fx.root, "add", "tests")
	git(t, fx.root, "commit", "-q", "-m", "teste existente")

	fresh, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !fresh.Tasks[0].TestsToWrite || fresh.Tasks[0].TestFiles[0] != "tests/add-reconcile.test.ts" {
		t.Fatalf("skeleton = %+v", fresh.Tasks[0])
	}
	declared, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Tests: []string{"tests/add.test.ts"}, DryRun: true})
	if err != nil {
		t.Fatalf("dry run declarado: %v", err)
	}
	if declared.Tasks[0].TestsToWrite || declared.Tasks[0].TestFiles[0] != "tests/add.test.ts" {
		t.Fatalf("declarado = %+v", declared.Tasks[0])
	}
}

func TestReconcileChunksImplementationFiles(t *testing.T) {
	fx := newReconcileFixture(t)
	for index := range 8 {
		writeFile(t, fx.root, fmt.Sprintf("src/mod%d.ts", index), "export const v = 1;\n")
	}
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Title: "Muitos modulos"})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if len(result.Tasks) != 2 {
		t.Fatalf("tasks = %+v", result.Tasks)
	}
	if len(result.Tasks[0].ImplementationFiles) != 6 || len(result.Tasks[1].ImplementationFiles) != 3 {
		t.Fatalf("grupos = %d, %d", len(result.Tasks[0].ImplementationFiles), len(result.Tasks[1].ImplementationFiles))
	}
	if result.Tasks[0].ID != "1.1" || result.Tasks[1].ID != "1.2" {
		t.Fatalf("ids = %s, %s", result.Tasks[0].ID, result.Tasks[1].ID)
	}
	for _, output := range gates.EvaluateAllGates(*result.WorkID, work.GetWorkArtifactsPaths(*result.WorkID, fx.root).WorkDir) {
		if output.Result != gates.ResultPass {
			t.Fatalf("%s = %s: %+v", output.Gate, output.Result, output.Findings)
		}
	}
}

func TestReconcileRejectsTestOnlyAndDryRunWritesNothing(t *testing.T) {
	fx := newReconcileFixture(t)
	if _, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Paths: []string{"tests"}}); err == nil ||
		!contains(err.Error(), "só há arquivos de teste") {
		t.Fatalf("só testes devia falhar: %v", err)
	}
	if _, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, DryRun: true}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fx.root, ".pwn/work/0001/plan.json")); !os.IsNotExist(err) {
		t.Fatal("dry run escreveu o Work")
	}
}

func TestReconcileRiskIsFrozen(t *testing.T) {
	fx := newReconcileFixture(t)
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Risk: contract.RiskL3})
	if err != nil {
		t.Fatal(err)
	}
	taskContract, err := plan.LoadTaskContract(*result.WorkID, "1.1", fx.root)
	if err != nil {
		t.Fatal(err)
	}
	if taskContract.Risk.Level != contract.RiskL3 {
		t.Fatalf("risco = %s", taskContract.Risk.Level)
	}
}

// containsSlice informa se values contém want.
func containsSlice(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
