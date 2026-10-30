package work_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/work"
)

func TestDetectChangesRejectsNonRepositoryAndEmptyRepository(t *testing.T) {
	plain := t.TempDir()
	if _, err := work.DetectChanges(work.ReconcileOptions{RootDir: plain}); err == nil ||
		!strings.Contains(err.Error(), "não é um repositório git") {
		t.Fatalf("diretório sem git devia falhar: %v", err)
	}

	empty := t.TempDir()
	initRepo(t, empty)
	if _, err := work.DetectChanges(work.ReconcileOptions{RootDir: empty}); err == nil ||
		!strings.Contains(err.Error(), "nenhum commit") {
		t.Fatalf("repositório sem commit devia falhar: %v", err)
	}
}

func TestDetectChangesSinceMustBeAncestorOfHead(t *testing.T) {
	fx := newReconcileFixture(t)
	git(t, fx.root, "checkout", "-q", "-b", "lateral")
	writeFile(t, fx.root, "src/lateral.ts", "export const l = 1;\n")
	lateral := commitAll(t, fx.root, "ramo lateral")
	git(t, fx.root, "checkout", "-q", "-")
	git(t, fx.root, "reset", "-q", "--hard", fx.base)

	_, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root, Since: lateral})
	if err == nil || !strings.Contains(err.Error(), "não é ancestral do HEAD") {
		t.Fatalf("since fora da história do HEAD devia falhar: %v", err)
	}
}

func TestDetectChangesSkipsPlaceholderNonRegularAndEnvFiles(t *testing.T) {
	fx := newReconcileFixture(t)
	writeFile(t, fx.root, "src/<nome>.ts", "x\n")
	writeFile(t, fx.root, "src/TODO.ts", "x\n")
	writeFile(t, fx.root, "config/.env.production", "SEGREDO=1\n")
	if err := os.Symlink(filepath.Join(fx.root, "src"), filepath.Join(fx.root, "link-dir")); err != nil {
		t.Skipf("symlink indisponível: %v", err)
	}

	detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatalf("DetectChanges: %v", err)
	}
	reasons := map[string]string{}
	for _, skip := range detected.Skipped {
		reasons[skip.Path] = skip.Reason
	}
	if !strings.Contains(reasons["src/<nome>.ts"], "é placeholder") {
		t.Fatalf("placeholder = %q", reasons["src/<nome>.ts"])
	}
	if !strings.Contains(reasons["src/TODO.ts"], "é placeholder") {
		t.Fatalf("TODO = %q", reasons["src/TODO.ts"])
	}
	if !strings.Contains(reasons["config/.env.production"], "segredo") {
		t.Fatalf("env = %q", reasons["config/.env.production"])
	}
	if reasons["link-dir"] != "não é um arquivo regular" {
		t.Fatalf("symlink para diretório = %q", reasons["link-dir"])
	}
	paths := make([]string, 0)
	for _, change := range detected.Changes {
		paths = append(paths, change.Path)
	}
	if strings.Join(paths, ",") != "src/add.ts,tests/add.test.ts" {
		t.Fatalf("changes = %v", paths)
	}
}

func TestDetectChangesNormalizesPathPrefixes(t *testing.T) {
	fx := newReconcileFixture(t)
	writeFile(t, fx.root, "srcother/x.ts", "x\n")
	for _, prefix := range []string{"./src/", "src", `src\`} {
		detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root, Paths: []string{prefix}})
		if err != nil {
			t.Fatalf("prefixo %q: %v", prefix, err)
		}
		if len(detected.Changes) != 1 || detected.Changes[0].Path != "src/add.ts" {
			t.Fatalf("prefixo %q: changes = %+v", prefix, detected.Changes)
		}
	}
}

func TestDetectChangesSkipsFilesAlreadyReconciledInAnotherWork(t *testing.T) {
	fx := newReconcileFixture(t)
	first, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}

	detected, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatalf("DetectChanges: %v", err)
	}
	if len(detected.Changes) != 0 {
		t.Fatalf("mudanças já conciliadas reapareceram: %+v", detected.Changes)
	}
	found := false
	for _, skip := range detected.Skipped {
		if skip.Path == "src/add.ts" && skip.Reason == "já conciliado no Work "+*first.WorkID {
			found = true
		}
	}
	if !found {
		t.Fatalf("skipped = %+v", detected.Skipped)
	}

	// Ignorar o próprio Work (reconciliação com --force) devolve as mudanças.
	again, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root, WorkID: *first.WorkID})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Changes) != 2 {
		t.Fatalf("changes ignorando o próprio Work = %+v", again.Changes)
	}

	// Conteúdo diferente do conciliado volta a ser mudança.
	writeFile(t, fx.root, "src/add.ts", "export const add = (a: number, b: number) => b + a;\n")
	changed, err := work.DetectChanges(work.ReconcileOptions{RootDir: fx.root})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed.Changes) != 1 || changed.Changes[0].Path != "src/add.ts" {
		t.Fatalf("arquivo modificado depois da conciliação = %+v", changed.Changes)
	}
}

func TestReadReconciliationRejectsMissingAndMalformedRecords(t *testing.T) {
	root := t.TempDir()
	if work.ReadReconciliation(root, "0001") != nil {
		t.Fatal("Work sem registro devia devolver nil")
	}
	writeFile(t, root, ".pwn/work/0001/reconciliation.json", "{não é json")
	if work.ReadReconciliation(root, "0001") != nil {
		t.Fatal("JSON inválido devia devolver nil")
	}
	writeFile(t, root, ".pwn/work/0002/reconciliation.json", `{"version":2,"files":[]}`)
	if work.ReadReconciliation(root, "0002") != nil {
		t.Fatal("versão desconhecida devia devolver nil")
	}
	writeFile(t, root, ".pwn/work/0003/reconciliation.json", `{"version":1}`)
	if work.ReadReconciliation(root, "0003") != nil {
		t.Fatal("registro sem files devia devolver nil")
	}
	writeFile(t, root, ".pwn/work/0004/reconciliation.json", `{"version":1,"work_id":"0004","base_commit":"abc","files":[]}`)
	record := work.ReadReconciliation(root, "0004")
	if record == nil || record.BaseCommit != "abc" || record.WorkID != "0004" {
		t.Fatalf("registro válido = %+v", record)
	}
}

func TestReconcileChangesNothingToReconcile(t *testing.T) {
	fx := newReconcileFixture(t)
	commitAll(t, fx.root, "tudo commitado")
	_, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root})
	if err == nil || !strings.Contains(err.Error(), "nenhuma mudança fora da governança") {
		t.Fatalf("sem mudanças: %v", err)
	}

	skippedOnly := newReconcileFixture(t)
	if err := os.RemoveAll(filepath.Join(skippedOnly.root, "tests")); err != nil {
		t.Fatal(err)
	}
	git(t, skippedOnly.root, "checkout", "--", "src/add.ts")
	writeFile(t, skippedOnly.root, ".env", "A=1\n")
	_, err = work.ReconcileChanges(work.ReconcileOptions{RootDir: skippedOnly.root})
	if err == nil || !strings.Contains(err.Error(), "todas as mudanças foram ignoradas (.env: segredo") {
		t.Fatalf("somente ignorados: %v", err)
	}
}

func TestReconcileChangesPropagatesDetectionFailure(t *testing.T) {
	if _, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "não é um repositório git") {
		t.Fatalf("erro = %v", err)
	}
}

func TestReconcileChangesValidatesDeclaredTests(t *testing.T) {
	fx := newReconcileFixture(t)
	cases := []struct {
		name  string
		tests []string
		want  string
	}{
		{"placeholder", []string{"tests/<x>.test.ts"}, "é placeholder"},
		{"glob", []string{"tests/*.test.ts"}, "é glob"},
		{"inexistente", []string{"tests/nao-existe.test.ts"}, "não existe"},
		{"diretório", []string{"tests"}, "não existe"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Tests: test.tests})
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "--tests") {
				t.Fatalf("erro = %v, quer conter %q", err, test.want)
			}
		})
	}
}

func TestReconcileChangesDeclaredTestsAreDeduplicatedAndNormalized(t *testing.T) {
	fx := newReconcileFixture(t)
	writeFile(t, fx.root, "extra/cobertura.test.ts", "x\n")
	result, err := work.ReconcileChanges(work.ReconcileOptions{
		RootDir: fx.root,
		Tests:   []string{"./extra/cobertura.test.ts", "extra/cobertura.test.ts"},
		DryRun:  true,
	})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	got := strings.Join(result.Tasks[0].TestFiles, ",")
	if got != "extra/cobertura.test.ts,tests/add.test.ts" {
		t.Fatalf("testFiles = %s", got)
	}
}

func TestReconcileChangesDefaultTitleAndDryRunShape(t *testing.T) {
	fx := newReconcileFixture(t)
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, DryRun: true})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if !result.DryRun || result.WorkID != nil {
		t.Fatalf("dry run = %+v", result)
	}
	if result.BaseCommit != fx.base || result.HeadCommit != fx.base {
		t.Fatalf("commits = %s/%s", result.BaseCommit, result.HeadCommit)
	}
	if result.Skipped == nil || result.Generated == nil || result.Frozen == nil || result.PendingFreeze == nil {
		t.Fatalf("listas do dry run não podem ser nil: %+v", result)
	}
	if len(result.Changes) != 2 {
		t.Fatalf("changes = %+v", result.Changes)
	}
}

func TestReconcileChangesDoesNotDenyPackageJSONWhenItChanged(t *testing.T) {
	fx := newReconcileFixture(t)
	writeFile(t, fx.root, "package.json", "{\"name\":\"y\"}\n")
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, Title: "Atualiza pacote"})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	taskContract, err := plan.LoadTaskContract(*result.WorkID, "1.1", fx.root)
	if err != nil {
		t.Fatalf("LoadTaskContract: %v", err)
	}
	if containsSlice(taskContract.ScopeContract.WriteDeny, "package.json") {
		t.Fatalf("package.json alterado não pode ficar em write_deny: %v", taskContract.ScopeContract.WriteDeny)
	}
	if !containsSlice(taskContract.ScopeContract.WriteAllow, "package.json") {
		t.Fatalf("package.json devia estar em write_allow: %v", taskContract.ScopeContract.WriteAllow)
	}
	record := work.ReadReconciliation(fx.root, *result.WorkID)
	if record == nil {
		t.Fatal("registro de conciliação ausente")
	}
	found := false
	for _, file := range record.Files {
		if file.Path == "package.json" && file.Kind == "implementation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("package.json devia ser conciliado como implementação: %+v", record.Files)
	}
}

func TestReconcileChangesRecordsSinceSkippedAndDeclaredTests(t *testing.T) {
	fx := newReconcileFixture(t)
	commitAll(t, fx.root, "mudança commitada")
	writeFile(t, fx.root, ".env", "A=1\n")
	result, err := work.ReconcileChanges(work.ReconcileOptions{
		RootDir: fx.root,
		Since:   fx.base,
		Title:   "Soma de dois números",
		Tests:   []string{"tests/add.test.ts"},
	})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if result.BaseCommit != fx.base {
		t.Fatalf("base = %s", result.BaseCommit)
	}
	record := work.ReadReconciliation(fx.root, *result.WorkID)
	if record == nil {
		t.Fatal("registro ausente")
	}
	if record.Since == nil || *record.Since != fx.base {
		t.Fatalf("since = %v", record.Since)
	}
	if len(record.DeclaredTests) != 1 || record.DeclaredTests[0] != "tests/add.test.ts" {
		t.Fatalf("declared = %v", record.DeclaredTests)
	}
	if len(record.Skipped) != 1 || record.Skipped[0].Path != ".env" {
		t.Fatalf("skipped = %+v", record.Skipped)
	}
	if len(result.Frozen) != 1 || result.Frozen[0] != "1.1" || len(result.PendingFreeze) != 0 {
		t.Fatalf("frozen=%v pending=%+v", result.Frozen, result.PendingFreeze)
	}
	last := result.Generated[len(result.Generated)-1]
	if last != ".pwn/work/"+*result.WorkID+"/reconciliation.json" {
		t.Fatalf("último gerado = %s", last)
	}
}

func TestReconcileChangesExistingWorkNeedsForce(t *testing.T) {
	fx := newReconcileFixture(t)
	first, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, WorkID: "0007", Title: "Primeira"})
	if err != nil {
		t.Fatalf("primeira conciliação: %v", err)
	}
	if *first.WorkID != "0007" {
		t.Fatalf("WorkID = %s", *first.WorkID)
	}
	_, err = work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, WorkID: "0007", Title: "Segunda"})
	if err == nil || !strings.Contains(err.Error(), "Work 0007 já existe") {
		t.Fatalf("sem --force devia falhar: %v", err)
	}
	forced, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, WorkID: "0007", Title: "Segunda", Force: true})
	if err != nil {
		t.Fatalf("com --force: %v", err)
	}
	if *forced.WorkID != "0007" {
		t.Fatalf("WorkID forçado = %s", *forced.WorkID)
	}
}

func TestReconcileChangesSkeletonAvoidsReservedAndExistingNames(t *testing.T) {
	fx := newReconcileFixture(t)
	if err := os.RemoveAll(filepath.Join(fx.root, "tests")); err != nil {
		t.Fatal(err)
	}
	// Dois candidatos já existem em disco; o terceiro nome livre é escolhido.
	writeFile(t, fx.root, "tests/add.test.ts", "x\n")
	writeFile(t, fx.root, "tests/add-reconcile.test.ts", "x\n")
	git(t, fx.root, "add", "tests")
	git(t, fx.root, "commit", "-q", "-m", "testes existentes")
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, DryRun: true})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if got := result.Tasks[0].TestFiles[0]; got != "tests/add-reconcile-2.test.ts" {
		t.Fatalf("esqueleto = %s", got)
	}
}

func TestReconcileChangesSkeletonStemFallsBackForSymbolOnlyNames(t *testing.T) {
	root := t.TempDir()
	initRepo(t, root)
	writeFile(t, root, "README.md", "base\n")
	commitAll(t, root, "base")
	writeFile(t, root, "src/++.ts", "x\n")
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: root, DryRun: true})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if got := result.Tasks[0].TestFiles[0]; got != "tests/task.test.ts" {
		t.Fatalf("esqueleto = %s", got)
	}
}

func TestReconcileChangesSplitsManyFilesWithTwoSkeletons(t *testing.T) {
	fx := newReconcileFixture(t)
	if err := os.RemoveAll(filepath.Join(fx.root, "tests")); err != nil {
		t.Fatal(err)
	}
	for index := range 7 {
		writeFile(t, fx.root, "src/part"+string(rune('a'+index))+".ts", "export const v = 1;\n")
	}
	result, err := work.ReconcileChanges(work.ReconcileOptions{RootDir: fx.root, DryRun: true, Title: "Lote"})
	if err != nil {
		t.Fatalf("ReconcileChanges: %v", err)
	}
	if len(result.Tasks) != 2 {
		t.Fatalf("tasks = %+v", result.Tasks)
	}
	if len(result.Tasks[0].ImplementationFiles) != work.MaxImplementationFiles || len(result.Tasks[1].ImplementationFiles) != 2 {
		t.Fatalf("grupos = %d/%d", len(result.Tasks[0].ImplementationFiles), len(result.Tasks[1].ImplementationFiles))
	}
	if result.Tasks[0].TestFiles[0] == result.Tasks[1].TestFiles[0] {
		t.Fatalf("esqueletos duplicados: %v", result.Tasks)
	}
}
