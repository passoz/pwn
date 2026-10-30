package batch_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/batch"
)

// prepareTwo prepara o lote {1.1, 1.2} e entrega as duas tasks.
func prepareTwo(t *testing.T, fx *fixture) *batch.BatchManifest {
	t.Helper()
	prepared, err := batch.PrepareBatch(context.Background(), batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %+v (%v)", prepared.Schedule, err)
	}
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.1").Worktree, specs[0], prepared.Manifest.Base)
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.2").Worktree, specs[1], prepared.Manifest.Base)
	return prepared.Manifest
}

// syncHead acompanha na manifesto o commit externo que o teste acabou de fazer:
// integrate e rebase recusam HEAD fora do lote.
func syncHead(t *testing.T, fx *fixture) string {
	t.Helper()
	manifest, err := batch.ReadBatch(fx.root)
	if err != nil || manifest == nil {
		t.Fatalf("ler o lote: %+v (%v)", manifest, err)
	}
	manifest.Head = strings.TrimSpace(git(t, fx.root, "rev-parse", "HEAD"))
	writeManifestRaw(t, fx.root, manifest)
	return manifest.Head
}

// commitExternal commita um arquivo novo na árvore principal e ajusta o HEAD do
// manifesto.
func commitExternal(t *testing.T, fx *fixture, relative, content string) string {
	t.Helper()
	writeFile(t, fx.root, relative, content)
	git(t, fx.root, "add", relative)
	git(t, fx.root, "commit", "-q", "-m", "externo: "+relative)
	return syncHead(t, fx)
}

// commitScript troca a regressão declarada no plano e commita antes do prepare.
func commitScript(t *testing.T, fx *fixture, script string) {
	t.Helper()
	writeFile(t, fx.root, "bin/regression", script)
	if err := os.Chmod(filepath.Join(fx.root, "bin", "regression"), 0o755); err != nil {
		t.Fatalf("tornar a regressão executável: %v", err)
	}
	git(t, fx.root, "commit", "-q", "-am", "regressão de teste")
}

func regressionOf(timeout int) *batch.RegressionOptions {
	return &batch.RegressionOptions{Command: []string{"./bin/regression"}, TimeoutSeconds: timeout}
}

func joinedReasons(result batch.IntegrationResult) string {
	var all []string
	for _, held := range result.Failed {
		all = append(all, string(held.Kind)+"|"+held.ID+"|"+strings.Join(held.Reasons, "\n"))
	}
	return strings.Join(all, "\n")
}

func TestReadBatchRejectsInvalidManifest(t *testing.T) {
	root := t.TempDir()
	if manifest, err := batch.ReadBatch(root); err != nil || manifest != nil {
		t.Fatalf("sem manifesto = %+v (%v)", manifest, err)
	}

	writeFile(t, root, ".pwn/batch.json", "isto não é json")
	if _, err := batch.ReadBatch(root); err == nil || !strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("json inválido: %v", err)
	}
	writeFile(t, root, ".pwn/batch.json", `{"version": 2, "tasks": []}`)
	if _, err := batch.ReadBatch(root); err == nil || !strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("versão desconhecida: %v", err)
	}

	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, ".pwn", "batch.json"), 0o777); err != nil {
		t.Fatalf("criar diretório no lugar do manifesto: %v", err)
	}
	if _, err := batch.ReadBatch(other); err == nil || !strings.Contains(err.Error(), "batch: ler") {
		t.Fatalf("manifesto ilegível: %v", err)
	}
}

func TestOperationsRejectCorruptManifest(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	writeFile(t, fx.root, ".pwn/batch.json", "{")

	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1}); err == nil ||
		!strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root}); err == nil ||
		!strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("integrate: %v", err)
	}
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		!strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("rebase: %v", err)
	}
	if manifest, err := batch.AbortBatch(ctx, fx.root); err == nil || manifest != nil ||
		!strings.Contains(err.Error(), "manifesto de lote inválido") {
		t.Fatalf("abort: %+v (%v)", manifest, err)
	}
}

func TestBlockingChangesFailsOutsideGitRepository(t *testing.T) {
	root := t.TempDir()
	if _, err := batch.BlockingChanges(context.Background(), root); err == nil || !strings.Contains(err.Error(), "ler o status de") {
		t.Fatalf("fora de um repositório git: %v", err)
	}
	if _, err := batch.PrepareBatch(context.Background(), batch.PrepareOptions{Root: root, WorkID: workID, Jobs: 1}); err == nil ||
		!strings.Contains(err.Error(), "ler o status de") {
		t.Fatalf("prepare fora de um repositório git: %v", err)
	}
}

func TestBlockingChangesIgnoresHarnessState(t *testing.T) {
	fx := newFixture(t)
	writeFile(t, fx.root, ".todo/rascunho.md", "estado do harness\n")
	writeFile(t, fx.root, ".pwn/cache.json", "{}\n")
	writeFile(t, fx.root, "src/novo.js", "export const novo = 1;\n")
	files, err := batch.BlockingChanges(context.Background(), fx.root)
	if err != nil {
		t.Fatalf("blocking changes: %v", err)
	}
	equalStrings(t, "bloqueantes", files, []string{"src/novo.js"})
}

func TestCollectSchedulableTasksFailures(t *testing.T) {
	ctx := context.Background()

	if _, err := batch.CollectSchedulableTasks(ctx, workID, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "plan.json ausente para o Work 0001") {
		t.Fatalf("sem plano: %v", err)
	}

	missing := newFixture(t)
	if err := os.Remove(filepath.Join(missing.root, ".todo", workID+"-tasks.md")); err != nil {
		t.Fatalf("remover o plano derivado: %v", err)
	}
	if _, err := batch.CollectSchedulableTasks(ctx, workID, missing.root); err == nil ||
		!strings.Contains(err.Error(), "plano derivado ausente: .todo/0001-tasks.md") {
		t.Fatalf("sem markdown: %v", err)
	}

	drift := newFixture(t)
	writeFile(t, drift.root, ".todo/"+workID+"-tasks.md", "# plano editado à mão\n")
	if _, err := batch.CollectSchedulableTasks(ctx, workID, drift.root); err == nil ||
		!strings.Contains(err.Error(), "DRIFT: .todo/0001-tasks.md diverge de plan.json") {
		t.Fatalf("markdown divergente: %v", err)
	}

	noContract := newFixture(t)
	if err := os.Remove(filepath.Join(noContract.root, ".pwn", "work", workID, "CTR-002.json")); err != nil {
		t.Fatalf("remover o contrato: %v", err)
	}
	if _, err := batch.CollectSchedulableTasks(ctx, workID, noContract.root); err == nil {
		t.Fatalf("contrato ausente aceito")
	}

	ok := newFixture(t)
	tasks, err := batch.CollectSchedulableTasks(ctx, workID, ok.root)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	equalIDs(t, "tasks", ids(tasks), []string{"1.1", "1.2", "1.3"})
	for _, task := range tasks {
		if !task.Approved || task.Stage != "not started" || task.Risk != "L3" {
			t.Fatalf("task %s = %+v", task.ID, task)
		}
	}
	equalStrings(t, "escopo de 1.2", tasks[1].WriteAllow, []string{"src/b.js"})
}

func TestPlanNextBatchIgnoresCrossWorkDependencyPrefix(t *testing.T) {
	schedule := batch.PlanNextBatch([]batch.SchedulableTask{
		schedulable("1.1", func(task *batch.SchedulableTask) { task.DependsOn = []string{"0002/1.1"} }),
	}, 2, "0001", nil)
	equalIDs(t, "batch", ids(schedule.Batch), []string{"1.1"})
	if len(schedule.Deferred) != 0 {
		t.Fatalf("adiadas = %+v", schedule.Deferred)
	}
}

func TestPrepareOnlySelection(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2, Only: []string{"9.9", "8.8"}}); err == nil ||
		!strings.Contains(err.Error(), "task(s) fora do plano do Work 0001: 9.9, 8.8") {
		t.Fatalf("task inexistente: %v", err)
	}
	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2, Only: []string{"1.3"}}); err == nil ||
		!strings.Contains(err.Error(), "--tasks não forma um lote válido") ||
		!strings.Contains(err.Error(), "1.3: depende de 1.1, ainda não integrada") {
		t.Fatalf("task com dependência pendente: %v", err)
	}
	if manifest, err := batch.ReadBatch(fx.root); err != nil || manifest != nil {
		t.Fatalf("lote criado por uma seleção inválida: %+v (%v)", manifest, err)
	}

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2, Only: []string{"1.2"}})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare só com 1.2: %+v (%v)", prepared.Schedule, err)
	}
	equalIDs(t, "lote", idsOf(prepared.Manifest), []string{"1.2"})
	if _, err := batch.AbortBatch(ctx, fx.root); err != nil {
		t.Fatalf("abort: %v", err)
	}
}

func TestPrepareOnlyRejectsAlreadyIntegratedTask(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %+v (%v)", prepared.Schedule, err)
	}
	deliver(t, fx, prepared.Manifest.Tasks[0].Worktree, specs[0], prepared.Manifest.Base)
	done, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(done), []string{"1.1"})

	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1, Only: []string{"1.1"}}); err == nil ||
		!strings.Contains(err.Error(), "1.1: já integrada") {
		t.Fatalf("task já integrada: %v", err)
	}
}

func TestIntegrateRefusesBeforeTouchingAnything(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root}); err == nil ||
		!strings.Contains(err.Error(), "nenhum lote ativo") {
		t.Fatalf("sem lote: %v", err)
	}
	manifest := prepareTwo(t, fx)
	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, WorkID: "9999"}); err == nil ||
		!strings.Contains(err.Error(), "o lote ativo é do Work 0001, não do 9999") {
		t.Fatalf("Work divergente: %v", err)
	}
	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: &batch.RegressionOptions{}}); err == nil ||
		!strings.Contains(err.Error(), "comando de regressão vazio") {
		t.Fatalf("regressão vazia: %v", err)
	}
	writeFile(t, fx.root, "src/sujo.js", "export const sujo = 1;\n")
	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root}); err == nil ||
		!strings.Contains(err.Error(), "alterações não commitadas (src/sujo.js)") {
		t.Fatalf("árvore suja: %v", err)
	}
	if head := strings.TrimSpace(git(t, fx.root, "rev-parse", "HEAD")); head != manifest.Head {
		t.Fatalf("HEAD mudou: %s", head)
	}
	if active, err := batch.ReadBatch(fx.root); err != nil || len(active.Tasks) != 2 {
		t.Fatalf("lote alterado: %+v (%v)", active, err)
	}
}

func TestIntegrateWithoutRegressionWarnsAndHoldsEmptyDelivery(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	if len(result.Integrated) != 0 || len(result.Failed) != 2 {
		t.Fatalf("resultado = %+v", result)
	}
	for _, held := range result.Failed {
		if held.Kind != batch.HoldDelivery || len(held.Reasons) != 1 ||
			held.Reasons[0] != "nenhuma alteração em relação ao base da task" {
			t.Fatalf("retida %s = %+v", held.ID, held)
		}
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "nenhuma regressão executada") {
		t.Fatalf("avisos = %v", result.Warnings)
	}
	equalIDs(t, "restantes", result.Remaining, []string{"1.1", "1.2"})
}

func TestIntegrateHoldsTamperedWorktrees(t *testing.T) {
	ctx := context.Background()

	t.Run("worktree removido", func(t *testing.T) {
		fx := newFixture(t)
		manifest := prepareTwo(t, fx)
		first := taskOf(t, manifest, "1.1")
		if err := os.RemoveAll(first.Worktree); err != nil {
			t.Fatalf("remover o worktree: %v", err)
		}
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		equalIDs(t, "integradas", integratedIDs(result), []string{"1.2"})
		if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" ||
			!strings.Contains(result.Failed[0].Reasons[0], "worktree ausente: "+first.Worktree) {
			t.Fatalf("retidas = %+v", result.Failed)
		}
	})

	t.Run("worktree sem apontar para o repositório do lote", func(t *testing.T) {
		fx := newFixture(t)
		manifest := prepareTwo(t, fx)
		first := taskOf(t, manifest, "1.1")
		if err := os.Remove(filepath.Join(first.Worktree, ".git")); err != nil {
			t.Fatalf("remover o .git do worktree: %v", err)
		}
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" ||
			!strings.Contains(result.Failed[0].Reasons[0], "não aponta mais para o repositório do lote") {
			t.Fatalf("retidas = %+v", result.Failed)
		}
		equalIDs(t, "integradas", integratedIDs(result), []string{"1.2"})
	})

	t.Run("artefato injetado substituído", func(t *testing.T) {
		fx := newFixture(t)
		manifest := prepareTwo(t, fx)
		first := taskOf(t, manifest, "1.1")
		link := filepath.Join(first.Worktree, "node_modules")
		if err := os.Remove(link); err != nil {
			t.Fatalf("remover o link de node_modules: %v", err)
		}
		writeFile(t, first.Worktree, "node_modules/pacote/index.js", "instalado pelo agente\n")
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" ||
			!strings.Contains(result.Failed[0].Reasons[0], "artefato do harness substituído no worktree: node_modules") {
			t.Fatalf("retidas = %+v", result.Failed)
		}
	})

	t.Run("índice travado", func(t *testing.T) {
		fx := newFixture(t)
		manifest := prepareTwo(t, fx)
		first := taskOf(t, manifest, "1.1")
		writeFile(t, first.GitDir, "index.lock", "")
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" ||
			!strings.Contains(result.Failed[0].Reasons[0], "git add no worktree falhou") {
			t.Fatalf("retidas = %+v", result.Failed)
		}
	})
}

func TestIntegrateWarnsAboutHarnessArtifactChanges(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	second := taskOf(t, manifest, "1.2")
	writeFile(t, second.Worktree, ".pwn/work/"+workID+"/plan.json", "{}\n")

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.1", "1.2"})
	found := false
	for _, warning := range result.Warnings {
		if strings.HasPrefix(warning, "1.2: alterações em artefatos do harness ignoradas (não são entrega): .pwn/work/0001/plan.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("avisos = %v", result.Warnings)
	}
	content, err := os.ReadFile(filepath.Join(fx.root, ".pwn", "work", workID, "plan.json"))
	if err != nil || string(content) == "{}\n" {
		t.Fatalf("o plano da árvore principal foi sobrescrito: %q (%v)", content, err)
	}
}

func TestIntegrateReturnsErrorWhenContractDisappears(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	prepareTwo(t, fx)
	if err := os.Remove(filepath.Join(fx.root, ".pwn", "work", workID, "CTR-001.json")); err != nil {
		t.Fatalf("remover o contrato: %v", err)
	}
	git(t, fx.root, "commit", "-q", "-am", "remove o contrato de 1.1")
	syncHead(t, fx)

	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root}); err == nil {
		t.Fatalf("contrato ausente aceito")
	}
	if active, err := batch.ReadBatch(fx.root); err != nil || len(active.Tasks) != 2 {
		t.Fatalf("lote alterado pela falha: %+v (%v)", active, err)
	}
}

func TestIntegrateHoldsTaskThatDeletesDeclaredFile(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	first := taskOf(t, manifest, "1.1")
	if err := os.Remove(filepath.Join(first.Worktree, "src", "a.js")); err != nil {
		t.Fatalf("remover src/a.js: %v", err)
	}

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" || result.Failed[0].Kind != batch.HoldDelivery {
		t.Fatalf("retidas = %+v", result.Failed)
	}
	joined := strings.Join(result.Failed[0].Reasons, "\n")
	if strings.Contains(joined, "conflito não resolvido") {
		t.Fatalf("arquivo removido não pode virar conflito: %v", joined)
	}
	if !strings.Contains(joined, "evidência local insuficiente") {
		t.Fatalf("motivos = %v", joined)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.2"})
}

func TestIntegrateHoldsClashOnSharedFile(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)

	// O scheduler não deixaria 1.2 tocar em src/a.js; o contrato é ampliado
	// depois do prepare para exercitar a checagem real de arquivos.
	contractFile := filepath.Join(fx.root, ".pwn", "work", workID, "CTR-002.json")
	data, err := os.ReadFile(contractFile)
	if err != nil {
		t.Fatalf("ler o contrato: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decodificar o contrato: %v", err)
	}
	scope, _ := document["scope_contract"].(map[string]any)
	scope["write_allow"] = []string{"src/b.js", "src/a.js"}
	updated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("serializar o contrato: %v", err)
	}
	writeFile(t, fx.root, ".pwn/work/"+workID+"/CTR-002.json", string(updated)+"\n")
	git(t, fx.root, "commit", "-q", "-am", "amplia o escopo de 1.2")
	syncHead(t, fx)
	writeFile(t, taskOf(t, manifest, "1.2").Worktree, "src/a.js", "export const a = 3;\n")

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.1"})
	if len(result.Failed) != 1 || result.Failed[0].ID != "1.2" || result.Failed[0].Kind != batch.HoldClash {
		t.Fatalf("retidas = %+v", result.Failed)
	}
	wanted := "src/a.js também alterado por 1.1, que vem antes no plano; integre 1.1 e rode 'pwn work batch rebase 1.2'"
	if len(result.Failed[0].Reasons) != 1 || result.Failed[0].Reasons[0] != wanted {
		t.Fatalf("motivos = %v", result.Failed[0].Reasons)
	}
	content, err := os.ReadFile(filepath.Join(fx.root, "src", "a.js"))
	if err != nil || string(content) != "export const a = 2;\n" {
		t.Fatalf("src/a.js = %q (%v)", content, err)
	}
	equalIDs(t, "restantes", result.Remaining, []string{"1.2"})
}

func TestIntegrateCommitFailureInterruptsRemainingTasks(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	writeFile(t, fx.root, ".git/hooks/pre-commit", "#!/bin/sh\necho recusado pelo hook >&2\nexit 1\n")
	if err := os.Chmod(filepath.Join(fx.root, ".git", "hooks", "pre-commit"), 0o755); err != nil {
		t.Fatalf("tornar o hook executável: %v", err)
	}

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	if len(result.Integrated) != 0 || len(result.Failed) != 2 {
		t.Fatalf("resultado = %+v", result)
	}
	first, second := result.Failed[0], result.Failed[1]
	if first.ID != "1.1" || first.Kind != batch.HoldCommit ||
		!strings.Contains(strings.Join(first.Reasons, "\n"), "git commit falhou") {
		t.Fatalf("primeira retida = %+v", first)
	}
	if second.ID != "1.2" || second.Kind != batch.HoldInterrupted ||
		second.Reasons[0] != "não aplicada: integração interrompida em 1.1" {
		t.Fatalf("segunda retida = %+v", second)
	}
	// O apply foi desfeito: a árvore principal volta ao estado anterior.
	if dirty, err := batch.BlockingChanges(ctx, fx.root); err != nil || len(dirty) != 0 {
		t.Fatalf("árvore principal suja após a falha: %v (%v)", dirty, err)
	}
	if head := strings.TrimSpace(git(t, fx.root, "rev-parse", "HEAD")); head != manifest.Head {
		t.Fatalf("HEAD mudou para %s", head)
	}
	equalIDs(t, "restantes", result.Remaining, []string{"1.1", "1.2"})
}

func TestRegressionGateOutcomes(t *testing.T) {
	ctx := context.Background()

	t.Run("aprovada passa sem aviso e sem as variáveis do verificador", func(t *testing.T) {
		fx := newFixture(t)
		t.Setenv("PWN_VERIFIER_KEY", "segredo")
		commitScript(t, fx, "#!/bin/sh\n[ -z \"$PWN_VERIFIER_KEY\" ] && [ -z \"$PWN_VERIFIER_HOME\" ] || exit 7\nexit 0\n")
		prepareTwo(t, fx)
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: regressionOf(60)})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		equalIDs(t, "integradas", integratedIDs(result), []string{"1.1", "1.2"})
		if len(result.Failed) != 0 || len(result.Warnings) != 0 {
			t.Fatalf("falhas = %+v; avisos = %v", result.Failed, result.Warnings)
		}
	})

	t.Run("sem saída informa o exit code", func(t *testing.T) {
		fx := newFixture(t)
		commitScript(t, fx, "#!/bin/sh\nexit 3\n")
		prepareTwo(t, fx)
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: regressionOf(60)})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Integrated) != 0 || len(result.Failed) != 2 {
			t.Fatalf("resultado = %s", joinedReasons(result))
		}
		for _, held := range result.Failed {
			if held.Kind != batch.HoldRegression || held.Reasons[len(held.Reasons)-1] != "  | exit 3" {
				t.Fatalf("retida %s = %+v", held.ID, held)
			}
		}
		if dirty, err := batch.BlockingChanges(ctx, fx.root); err != nil || len(dirty) != 0 {
			t.Fatalf("árvore principal suja: %v (%v)", dirty, err)
		}
	})

	t.Run("mostra só as últimas 15 linhas", func(t *testing.T) {
		fx := newFixture(t)
		commitScript(t, fx, "#!/bin/sh\ni=1\nwhile [ $i -le 20 ]; do printf 'L%02d\\n' $i; i=$((i+1)); done\nexit 1\n")
		prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1})
		if err != nil || prepared.Manifest == nil {
			t.Fatalf("prepare: %v", err)
		}
		deliver(t, fx, prepared.Manifest.Tasks[0].Worktree, specs[0], prepared.Manifest.Base)
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: regressionOf(60)})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Failed) != 1 {
			t.Fatalf("resultado = %+v", result)
		}
		reasons := result.Failed[0].Reasons
		if len(reasons) != 16 || reasons[1] != "  | L06" || reasons[15] != "  | L20" {
			t.Fatalf("motivos = %q", reasons)
		}
	})

	t.Run("timeout derruba a regressão", func(t *testing.T) {
		fx := newFixture(t)
		commitScript(t, fx, "#!/bin/sh\nsleep 30\n")
		prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1})
		if err != nil || prepared.Manifest == nil {
			t.Fatalf("prepare: %v", err)
		}
		deliver(t, fx, prepared.Manifest.Tasks[0].Worktree, specs[0], prepared.Manifest.Base)
		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: regressionOf(1)})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		if len(result.Failed) != 1 || result.Failed[0].Kind != batch.HoldRegression ||
			!strings.Contains(strings.Join(result.Failed[0].Reasons, "\n"), "| excedeu 1s") {
			t.Fatalf("retidas = %+v", result.Failed)
		}
	})

	t.Run("diff que não aplica sobre o HEAD integrado", func(t *testing.T) {
		fx := newFixture(t)
		prepareTwo(t, fx)
		writeFile(t, fx.root, "src/a.js", "export const a = 5;\n")
		git(t, fx.root, "commit", "-q", "-am", "mudança concorrente em a.js")
		syncHead(t, fx)

		result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root, Regression: regressionOf(60)})
		if err != nil {
			t.Fatalf("integrate: %v", err)
		}
		equalIDs(t, "integradas", integratedIDs(result), []string{"1.2"})
		if len(result.Failed) != 1 || result.Failed[0].ID != "1.1" || result.Failed[0].Kind != batch.HoldStaleBase {
			t.Fatalf("retidas = %+v", result.Failed)
		}
		reasons := result.Failed[0].Reasons
		if len(reasons) != 2 || !strings.HasPrefix(reasons[0], "o diff não aplica sobre o HEAD integrado:") ||
			reasons[1] != "refaça a task sobre o HEAD atual: pwn work batch rebase 1.1" {
			t.Fatalf("motivos = %q", reasons)
		}
	})
}

func TestRebaseRefusals(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		!strings.Contains(err.Error(), "nenhum lote ativo") {
		t.Fatalf("sem lote: %v", err)
	}
	manifest := prepareTwo(t, fx)

	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.3"}); err == nil ||
		err.Error() != "a task 1.3 não está no lote ativo (1.1, 1.2)" {
		t.Fatalf("task fora do lote: %v", err)
	}
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		err.Error() != "a task 1.1 já está sobre o HEAD atual; não há o que refazer" {
		t.Fatalf("task já sobre o HEAD: %v", err)
	}

	empty := *manifest
	empty.Tasks = nil
	writeManifestRaw(t, fx.root, &empty)
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		err.Error() != "a task 1.1 não está no lote ativo (vazio)" {
		t.Fatalf("lote vazio: %v", err)
	}
	writeManifestRaw(t, fx.root, manifest)

	writeFile(t, fx.root, "docs/nota.txt", "nota\n")
	git(t, fx.root, "add", "docs/nota.txt")
	git(t, fx.root, "commit", "-q", "-m", "externo sem avisar o lote")
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		!strings.Contains(err.Error(), "HEAD mudou fora do lote") {
		t.Fatalf("HEAD externo: %v", err)
	}
	syncHead(t, fx)

	writeFile(t, fx.root, "src/sujo.js", "export const sujo = 1;\n")
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		!strings.Contains(err.Error(), "alterações não commitadas (src/sujo.js)") {
		t.Fatalf("árvore suja: %v", err)
	}
	if err := os.Remove(filepath.Join(fx.root, "src", "sujo.js")); err != nil {
		t.Fatalf("remover src/sujo.js: %v", err)
	}

	first := taskOf(t, manifest, "1.1")
	if err := os.RemoveAll(first.Worktree); err != nil {
		t.Fatalf("remover o worktree: %v", err)
	}
	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		!strings.Contains(err.Error(), "worktree ausente: "+first.Worktree) {
		t.Fatalf("worktree ausente: %v", err)
	}
}

func TestRebaseWithoutDeliveryChanges(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}
	commitExternal(t, fx, "docs/nota.txt", "nota\n")

	if _, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"}); err == nil ||
		err.Error() != "a task 1.1 não tem alterações para reaplicar" {
		t.Fatalf("task sem alterações: %v", err)
	}
	if worktreeCount(t, fx.root) != 3 {
		t.Fatalf("worktrees = %d; o rebase recusado não pode criar nem remover", worktreeCount(t, fx.root))
	}
}

func TestRebaseCleanReapplicationThenIntegrate(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	oldWorktree := taskOf(t, manifest, "1.1").Worktree
	head := commitExternal(t, fx, "docs/nota.txt", "nota\n")

	rebased, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"})
	if err != nil {
		t.Fatalf("rebase: %v", err)
	}
	if len(rebased.Conflicts) != 0 {
		t.Fatalf("conflitos = %v", rebased.Conflicts)
	}
	if rebased.TaskID != "1.1" || rebased.Base != head || rebased.Worktree == oldWorktree {
		t.Fatalf("rebase = %+v", rebased)
	}
	if rebased.Evidence.Stage != "VERIFIED" || rebased.Evidence.Stale {
		t.Fatalf("evidência = %+v", rebased.Evidence)
	}
	if _, err := os.Stat(oldWorktree); !os.IsNotExist(err) {
		t.Fatalf("worktree antigo ainda existe: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(rebased.Worktree, "src", "a.js"))
	if err != nil || string(content) != "export const a = 2;\n" {
		t.Fatalf("src/a.js no worktree novo = %q (%v)", content, err)
	}
	if _, err := os.Stat(filepath.Join(rebased.Worktree, "docs", "nota.txt")); err != nil {
		t.Fatalf("o worktree novo não nasceu do HEAD atual: %v", err)
	}
	active, err := batch.ReadBatch(fx.root)
	if err != nil {
		t.Fatalf("ler o lote: %v", err)
	}
	refeita := taskOf(t, active, "1.1")
	if refeita.Base != head || refeita.Worktree != rebased.Worktree {
		t.Fatalf("task no manifesto = %+v", refeita)
	}

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.1", "1.2"})
	if len(result.Failed) != 0 || len(result.Remaining) != 0 {
		t.Fatalf("resultado = %+v", result)
	}
	if _, err := os.Stat(rebased.PatchFile); !os.IsNotExist(err) {
		t.Fatalf("patch de referência não foi removido: %v", err)
	}
}

func TestRebaseFailsWithoutConflictsWhenFileWasDeleted(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	first := taskOf(t, manifest, "1.1")
	git(t, fx.root, "rm", "-q", "src/a.js")
	git(t, fx.root, "commit", "-q", "-m", "remove src/a.js")
	syncHead(t, fx)

	_, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"})
	if err == nil || !strings.Contains(err.Error(), "git apply --3way falhou sem gerar conflitos") {
		t.Fatalf("rebase = %v", err)
	}
	// O worktree antigo segue intacto e o novo foi descartado.
	if _, statErr := os.Stat(filepath.Join(first.Worktree, "src", "a.js")); statErr != nil {
		t.Fatalf("worktree antigo perdeu a entrega: %v", statErr)
	}
	if count := worktreeCount(t, fx.root); count != 3 {
		t.Fatalf("worktrees = %d", count)
	}
	active, err := batch.ReadBatch(fx.root)
	if err != nil || taskOf(t, active, "1.1").Worktree != first.Worktree {
		t.Fatalf("o manifesto trocou o worktree: %+v (%v)", active, err)
	}
}

func TestRebaseFailsWhenEvidenceDirectoryIsNotReadable(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	manifest := prepareTwo(t, fx)
	first := taskOf(t, manifest, "1.1")
	// Um arquivo no lugar do diretório da evidência faz o ReadDir falhar com
	// ENOTDIR, o que não depende de permissões.
	if err := os.RemoveAll(filepath.Join(first.Worktree, ".todo", "evidence", workID)); err != nil {
		t.Fatalf("remover a evidência: %v", err)
	}
	writeFile(t, first.Worktree, ".todo/evidence/"+workID, "não é um diretório\n")
	commitExternal(t, fx, "docs/nota.txt", "nota\n")

	_, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"})
	if err == nil || !strings.Contains(err.Error(), "batch: ler ") {
		t.Fatalf("rebase = %v", err)
	}
	if count := worktreeCount(t, fx.root); count != 3 {
		t.Fatalf("o worktree novo não foi descartado: %d", count)
	}
}

func TestAbortRemovesPatchFilesOfRebasedTasks(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	prepareTwo(t, fx)
	commitExternal(t, fx, "docs/nota.txt", "nota\n")
	rebased, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.2"})
	if err != nil {
		t.Fatalf("rebase: %v", err)
	}
	if _, err := os.Stat(rebased.PatchFile); err != nil {
		t.Fatalf("patch ausente: %v", err)
	}

	manifest, err := batch.AbortBatch(ctx, fx.root)
	if err != nil || manifest == nil {
		t.Fatalf("abort: %+v (%v)", manifest, err)
	}
	if _, err := os.Stat(rebased.PatchFile); !os.IsNotExist(err) {
		t.Fatalf("patch de referência sobrou: %v", err)
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees = %d", count)
	}
}
