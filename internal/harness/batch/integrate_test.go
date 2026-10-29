package batch_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/batch"
	"github.com/passoz/pwn/internal/harness/verify"
)

func TestPrepareAndIntegratePreservesEvidence(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.Manifest == nil {
		t.Fatalf("prepare não criou o lote: %+v", prepared.Schedule)
	}
	equalIDs(t, "lote 1", idsOf(prepared.Manifest), []string{"1.1", "1.2"})
	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2}); err == nil ||
		!strings.Contains(err.Error(), "já existe um lote ativo") {
		t.Fatalf("segundo prepare com lote ativo: %v", err)
	}
	if reason := findDeferral(prepared.Schedule, "1.3"); !strings.Contains(reason, "depende de 1.1, ainda não integrada") {
		t.Fatalf("motivo de 1.3 = %q", reason)
	}
	first := taskOf(t, prepared.Manifest, "1.1")
	if _, err := os.Stat(filepath.Join(first.Worktree, ".todo", workID+"-tasks.md")); err != nil {
		t.Fatalf("plano não foi copiado para o worktree: %v", err)
	}
	info, err := os.Lstat(filepath.Join(first.Worktree, "node_modules"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("node_modules não foi linkado no worktree: %v", err)
	}

	deliver(t, fx, taskOf(t, prepared.Manifest, "1.1").Worktree, specs[0], prepared.Manifest.Base)
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.2").Worktree, specs[1], prepared.Manifest.Base)
	// Escrita fora do write_allow em 1.1: só ela fica retida; 1.2 entra mesmo assim.
	writeFile(t, first.Worktree, "notes.txt", "rascunho fora do escopo\n")

	partial, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate parcial: %v", err)
	}
	if got := strings.Join(integratedIDs(partial), ","); got != "1.2" {
		t.Fatalf("integradas parciais = %q; retidas = %+v", got, partial.Failed)
	}
	if len(partial.Failed) != 1 || partial.Failed[0].ID != "1.1" || partial.Failed[0].Kind != batch.HoldDelivery {
		t.Fatalf("retidas = %+v", partial.Failed)
	}
	if !strings.Contains(strings.Join(partial.Failed[0].Reasons, "\n"), "DIFF VIOLATION notes.txt") {
		t.Fatalf("motivos = %v", partial.Failed[0].Reasons)
	}
	equalIDs(t, "restantes", partial.Remaining, []string{"1.1"})
	remaining, err := batch.ReadBatch(fx.root)
	if err != nil {
		t.Fatalf("ler o lote: %v", err)
	}
	equalIDs(t, "manifesto parcial", idsOf(remaining), []string{"1.1"})

	// Corrigida no worktree, 1.1 integra sobre o HEAD que já avançou com 1.2.
	if err := os.Remove(filepath.Join(first.Worktree, "notes.txt")); err != nil {
		t.Fatalf("remover notes.txt: %v", err)
	}
	final, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate final: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(final), []string{"1.1"})
	if len(final.Failed) != 0 || len(final.Remaining) != 0 {
		t.Fatalf("resultado final = %+v", final)
	}
	if active, err := batch.ReadBatch(fx.root); err != nil || active != nil {
		t.Fatalf("manifesto ainda ativo: %+v (%v)", active, err)
	}
	equalStrings(t, "commits", logSubjects(t, fx.root), []string{
		"pwn batch 0001/1.1: Entrega a",
		"pwn batch 0001/1.2: Entrega b",
		"baseline",
	})
	if _, err := os.Stat(filepath.Join(fx.root, ".todo", "evidence", workID, "state", "1.1.json")); err != nil {
		t.Fatalf("evidência local não foi copiada: %v", err)
	}
	for _, id := range []string{"1.1", "1.2"} {
		evidence := evidenceOf(t, fx, id)
		if evidence.Stage != "VERIFIED" || evidence.Stale {
			t.Fatalf("evidência de %s = %+v", id, evidence)
		}
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees = %d", count)
	}
	if branches := strings.TrimSpace(git(t, fx.root, "branch", "--list", "pwn-sandbox-*")); branches != "" {
		t.Fatalf("branches restantes: %q", branches)
	}

	second, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil {
		t.Fatalf("prepare 2: %v", err)
	}
	if second.Manifest == nil {
		t.Fatalf("prepare 2 não criou o lote: %+v", second.Schedule)
	}
	equalIDs(t, "lote 2", idsOf(second.Manifest), []string{"1.3"})
	deliver(t, fx, second.Manifest.Tasks[0].Worktree, specs[2], second.Manifest.Base)
	last, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate 1.3: %v", err)
	}
	equalIDs(t, "integradas 1.3", integratedIDs(last), []string{"1.3"})
	for _, entry := range specs {
		evidence := evidenceOf(t, fx, entry.id)
		if evidence.Stage != "VERIFIED" || evidence.Stale {
			t.Fatalf("evidência de %s = %+v", entry.id, evidence)
		}
	}
}

func TestPrepareRejectsDirtyTreeAndUnapprovedTask(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	writeFile(t, fx.root, "src/a.js", "export const a = 99;\n")
	if _, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2}); err == nil ||
		!strings.Contains(err.Error(), "alterações não commitadas (src/a.js)") {
		t.Fatalf("árvore suja: %v", err)
	}
	git(t, fx.root, "checkout", "--", "src/a.js")

	// Sem raiz de verificador não há aprovação: nada vira lote e nenhum worktree nasce.
	t.Setenv(verify.HomeEnv, t.TempDir())
	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil {
		t.Fatalf("prepare sem aprovação: %v", err)
	}
	if prepared.Manifest != nil {
		t.Fatalf("lote criado sem aprovação")
	}
	if reason := findDeferral(prepared.Schedule, "1.1"); !strings.Contains(reason, "sem aprovação vigente") {
		t.Fatalf("motivo de 1.1 = %q", reason)
	}
	if active, err := batch.ReadBatch(fx.root); err != nil || active != nil {
		t.Fatalf("manifesto criado: %+v (%v)", active, err)
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees = %d", count)
	}
}

func TestRegressionGateHoldsOnlyBreakingTask(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.1").Worktree, specs[0], prepared.Manifest.Base)
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.2").Worktree, specs[1], prepared.Manifest.Base)

	// O comando precisa ser o declarado no plano; qualquer outro é recusado antes
	// de qualquer efeito.
	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{
		Root:       fx.root,
		Regression: &batch.RegressionOptions{Command: []string{"go", "test", "./..."}, TimeoutSeconds: 60},
	}); err == nil || !strings.Contains(err.Error(), "comando de regressão diverge do plano") {
		t.Fatalf("regressão não declarada: %v", err)
	}
	active, err := batch.ReadBatch(fx.root)
	if err != nil || active == nil || len(active.Tasks) != 2 {
		t.Fatalf("lote alterado pela recusa: %+v (%v)", active, err)
	}

	// a+b: 2 → 3 (só 1.1) passa; → 4 (com 1.2) quebra o teste cruzado.
	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{
		Root:       fx.root,
		Regression: &batch.RegressionOptions{Command: []string{"./bin/regression"}, TimeoutSeconds: 60},
	})
	if err != nil {
		t.Fatalf("integrate com regressão: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.1"})
	if len(result.Failed) != 1 || result.Failed[0].ID != "1.2" || result.Failed[0].Kind != batch.HoldRegression {
		t.Fatalf("retidas = %+v", result.Failed)
	}
	if !strings.Contains(strings.Join(result.Failed[0].Reasons, "\n"), "regressão falhou com a entrega aplicada") {
		t.Fatalf("motivos = %v", result.Failed[0].Reasons)
	}
	content, err := os.ReadFile(filepath.Join(fx.root, "src", "b.js"))
	if err != nil || string(content) != "export const b = 1;\n" {
		t.Fatalf("a árvore principal foi tocada: %q (%v)", content, err)
	}
	equalStrings(t, "commits", logSubjects(t, fx.root), []string{"pwn batch 0001/1.1: Entrega a", "baseline"})
	active, err = batch.ReadBatch(fx.root)
	if err != nil {
		t.Fatalf("ler o lote: %v", err)
	}
	equalIDs(t, "manifesto", idsOf(active), []string{"1.2"})
	if count := worktreeCount(t, fx.root); count != 2 {
		t.Fatalf("worktrees = %d", count)
	}
	if branches := strings.TrimSpace(git(t, fx.root, "branch", "--list", "pwn-sandbox-*-regression")); branches != "" {
		t.Fatalf("branch do gate sobrou: %q", branches)
	}

	if manifest, err := batch.AbortBatch(ctx, fx.root); err != nil || manifest == nil {
		t.Fatalf("abort: %+v (%v)", manifest, err)
	}
	if _, err := batch.ReadBatch(fx.root); err != nil {
		t.Fatalf("ler o lote após abort: %v", err)
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees após abort = %d", count)
	}
}

func TestRebaseReappliesTaskAndKeepsConflictInWorktree(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.1").Worktree, specs[0], prepared.Manifest.Base)
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.2").Worktree, specs[1], prepared.Manifest.Base)

	// Simula o que a heurística de escopo deveria impedir: o HEAD andou por uma
	// mudança em src/a.js, o arquivo que 1.1 também alterou.
	writeFile(t, fx.root, "src/a.js", "export const a = 5;\n")
	git(t, fx.root, "commit", "-qam", "mudança concorrente em a.js")

	if _, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root}); err == nil ||
		!strings.Contains(err.Error(), "HEAD mudou fora do lote") {
		t.Fatalf("commit externo aceito: %v", err)
	}
	// O manifesto é ajustado à mão porque integrate recusa commits externos;
	// aqui só interessa o caminho de recuperação.
	manifest, err := batch.ReadBatch(fx.root)
	if err != nil {
		t.Fatalf("ler o lote: %v", err)
	}
	manifest.Head = strings.TrimSpace(git(t, fx.root, "rev-parse", "HEAD"))
	writeManifestRaw(t, fx.root, manifest)

	first, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate após o HEAD novo: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(first), []string{"1.2"})
	if len(first.Failed) != 1 || first.Failed[0].ID != "1.1" || first.Failed[0].Kind != batch.HoldStaleBase {
		t.Fatalf("retidas = %+v", first.Failed)
	}
	active, err := batch.ReadBatch(fx.root)
	if err != nil {
		t.Fatalf("ler o lote: %v", err)
	}
	oldWorktree := taskOf(t, active, "1.1").Worktree

	rebased, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: fx.root, TaskID: "1.1"})
	if err != nil {
		t.Fatalf("rebase: %v", err)
	}
	equalStrings(t, "conflitos", rebased.Conflicts, []string{"src/a.js"})
	if rebased.Worktree == oldWorktree {
		t.Fatalf("worktree não foi refeito")
	}
	if _, err := os.Stat(oldWorktree); !os.IsNotExist(err) {
		t.Fatalf("worktree antigo ainda existe: %v", err)
	}
	if _, err := os.Stat(rebased.PatchFile); err != nil {
		t.Fatalf("patch de referência ausente: %v", err)
	}
	conflicted, err := os.ReadFile(filepath.Join(rebased.Worktree, "src", "a.js"))
	if err != nil {
		t.Fatalf("ler o arquivo em conflito: %v", err)
	}
	if !regexp.MustCompile(`(?m)^<{7} `).Match(conflicted) {
		t.Fatalf("conflito não ficou no worktree:\n%s", conflicted)
	}
	if rebased.Evidence.Stage != "VERIFIED" || !rebased.Evidence.Stale {
		t.Fatalf("evidência após o rebase = %+v", rebased.Evidence)
	}

	// Marcadores de conflito nunca entram: o harness não escolhe a resolução.
	blocked, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate bloqueado: %v", err)
	}
	if len(blocked.Failed) != 1 || !strings.Contains(strings.Join(blocked.Failed[0].Reasons, "\n"), "conflito não resolvido") {
		t.Fatalf("retidas = %+v", blocked.Failed)
	}

	// Resolvida pelo agente com o conteúdo que a evidência provou, a task integra.
	writeFile(t, rebased.Worktree, "src/a.js", "export const a = 2;\n")
	git(t, rebased.Worktree, "add", "src/a.js")
	done, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate da task refeita: %v", err)
	}
	equalIDs(t, "integradas finais", integratedIDs(done), []string{"1.1"})
	if active, err := batch.ReadBatch(fx.root); err != nil || active != nil {
		t.Fatalf("manifesto ativo após integrar: %+v (%v)", active, err)
	}
	content, err := os.ReadFile(filepath.Join(fx.root, "src", "a.js"))
	if err != nil || string(content) != "export const a = 2;\n" {
		t.Fatalf("src/a.js = %q (%v)", content, err)
	}
	equalStrings(t, "commits", logSubjects(t, fx.root), []string{
		"pwn batch 0001/1.1: Entrega a",
		"pwn batch 0001/1.2: Entrega b",
		"mudança concorrente em a.js",
		"baseline",
	})
	evidence := evidenceOf(t, fx, "1.1")
	if evidence.Stage != "VERIFIED" || evidence.Stale {
		t.Fatalf("evidência de 1.1 = %+v", evidence)
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees = %d", count)
	}
}

func TestAbortRemovesWorktreesAndManifest(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 1})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}
	worktree := prepared.Manifest.Tasks[0].Worktree
	manifest, err := batch.AbortBatch(ctx, fx.root)
	if err != nil || manifest == nil {
		t.Fatalf("abort: %+v (%v)", manifest, err)
	}
	if _, err := os.Stat(worktree); !os.IsNotExist(err) {
		t.Fatalf("worktree não foi removido: %v", err)
	}
	if active, err := batch.ReadBatch(fx.root); err != nil || active != nil {
		t.Fatalf("manifesto ainda existe: %+v (%v)", active, err)
	}
	if count := worktreeCount(t, fx.root); count != 1 {
		t.Fatalf("worktrees = %d", count)
	}
	if branches := strings.TrimSpace(git(t, fx.root, "branch", "--list", "pwn-sandbox-*")); branches != "" {
		t.Fatalf("branches restantes: %q", branches)
	}
	if again, err := batch.AbortBatch(ctx, fx.root); err != nil || again != nil {
		t.Fatalf("abort sem lote = %+v (%v)", again, err)
	}
}

func TestDeliveryWithoutEvidenceOrMainBaselineIsHeld(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	prepared, err := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: fx.root, WorkID: workID, Jobs: 2})
	if err != nil || prepared.Manifest == nil {
		t.Fatalf("prepare: %v", err)
	}
	worktreeA := taskOf(t, prepared.Manifest, "1.1").Worktree
	deliver(t, fx, taskOf(t, prepared.Manifest, "1.2").Worktree, specs[1], prepared.Manifest.Base)
	// Implementação sem estado local: a entrega não tem evidência.
	writeFile(t, worktreeA, "src/a.js", "export const a = 2;\n")

	result, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate: %v", err)
	}
	equalIDs(t, "integradas", integratedIDs(result), []string{"1.2"})
	if len(result.Failed) != 1 || !strings.Contains(strings.Join(result.Failed[0].Reasons, "\n"), "evidência local insuficiente: not started") {
		t.Fatalf("retidas = %+v", result.Failed)
	}

	// Evidência ancorada num commit que não está na árvore principal: o green
	// posterior leria um baseline inexistente.
	deliver(t, fx, worktreeA, specs[0], strings.Repeat("0", 40))
	result, err = batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate com baseline alheio: %v", err)
	}
	if len(result.Failed) != 1 || !strings.Contains(strings.Join(result.Failed[0].Reasons, "\n"), "baseline do audit capturado sobre") {
		t.Fatalf("retidas = %+v", result.Failed)
	}

	deliver(t, fx, worktreeA, specs[0], prepared.Manifest.Base)
	done, err := batch.IntegrateBatch(ctx, batch.IntegrateOptions{Root: fx.root})
	if err != nil {
		t.Fatalf("integrate final: %v", err)
	}
	equalIDs(t, "integradas finais", integratedIDs(done), []string{"1.1"})
	if active, err := batch.ReadBatch(fx.root); err != nil || active != nil {
		t.Fatalf("manifesto ativo: %+v (%v)", active, err)
	}
}

func integratedIDs(result batch.IntegrationResult) []string {
	ids := make([]string, 0, len(result.Integrated))
	for _, entry := range result.Integrated {
		ids = append(ids, entry.ID)
	}
	return ids
}

func logSubjects(t *testing.T, root string) []string {
	t.Helper()
	return strings.Split(strings.TrimSpace(git(t, root, "log", "--format=%s")), "\n")
}

func equalStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s = %v, queria %v", label, got, want)
	}
}
