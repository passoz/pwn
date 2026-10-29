package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

// gitRepo cria um repositório Git vazio no diretório e devolve a raiz.
func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	command := exec.Command("git", "init", "-q", dir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v (%s)", err, output)
	}
	t.Chdir(dir)
	return dir
}

// isolatedVerifier aponta a raiz do verificador para um diretório temporário.
func isolatedVerifier(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "verifier")
	t.Setenv(verify.HomeEnv, root)
	return root
}

func TestWorkInitCLI(t *testing.T) {
	dir := inTempDir(t)
	code, stdout, stderr := runCLI(t, "work", "init", "0001")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	workDir := filepath.Join(dir, ".pwn", "work", "0001")
	want := strings.Join([]string{
		"=== [pwn work init] Inicializando estrutura de artefatos para Work 0001 ===",
		"✓ Estrutura criada em: " + workDir,
		"Artefatos gerados: intake.json, discovery.json, requirements.json, prd.json, traceability-matrix.json",
		"",
	}, "\n")
	if stdout != want {
		t.Fatalf("stdout = %q, quer %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, quer vazio", stderr)
	}
	for _, file := range []string{"intake.json", "discovery.json", "requirements.json", "prd.json", "traceability-matrix.json"} {
		if _, err := os.Stat(filepath.Join(workDir, file)); err != nil {
			t.Fatalf("artefato %s ausente: %v", file, err)
		}
	}
}

func TestWorkGateCLI(t *testing.T) {
	t.Run("gate desconhecido", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "gate", "GATE-NOPE")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "Gate desconhecido: GATE-NOPE. Opções: GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC, GATE-SPEC-PLAN, GATE-PLAN-CONTRACT\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("clear-cache", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "gate", "--clear-cache")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn work gate] Limpando cache de gates ===\n✓ 0 arquivo(s) de cache removido(s) de .pwn/gate-cache/.\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	t.Run("todos os gates", func(t *testing.T) {
		inTempDir(t)
		if code, _, stderr := runCLI(t, "work", "init", "0001"); code != 0 {
			t.Fatalf("work init: stderr = %q", stderr)
		}
		code, stdout, _ := runCLI(t, "work", "gate", "--all", "--work", "0001")
		if code != 0 && code != 1 {
			t.Fatalf("código = %d, quer 0 ou 1", code)
		}
		for _, want := range []string{
			"=== [pwn work gate] Executando todos os gates para Work 0001 ===\n",
			"\n── GATE-DISC-REQ ──\n",
			"\n── Resumo por gate ──\n",
			"GATE-PLAN-CONTRACT: ",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout sem %q:\n%s", want, stdout)
			}
		}
	})
}

func TestWorkPlanAndContractCLI(t *testing.T) {
	t.Run("plan sem plan.json", func(t *testing.T) {
		dir := inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "plan", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.HasPrefix(stdout, "=== [pwn work plan] Planejando / Validando Grafo de Tarefas ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "Nenhum plan.json encontrado para o Work 0001. Rode 'pwn work init' e crie .pwn/work/0001/plan.json, ou informe um caminho de plano markdown.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q (dir %s)", stderr, want, dir)
		}
	})

	t.Run("contract sem plan.json", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "contract", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stdout, "=== [pwn work contract] Validando contratos V4 congelados do Work ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "Nenhum plan.json encontrado em .pwn/work/0001/. Rode 'pwn work init 0001' e defina as tasks antes de validar os contratos.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("freeze-tests sem task", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "contract", "--freeze-tests", "tests/a.test.ts")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "Uso: pwn work contract --work NNNN --task 1.1 --freeze-tests <arquivo-de-teste>...\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})
}

func TestWorkScaffoldImportReconcileCLI(t *testing.T) {
	t.Run("scaffold sem título", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "scaffold")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "Uso: pwn work scaffold --title \"<titulo>\" [--work NNNN] [--source spec.md] [--risk Lx] [--dir PATH] [--force]\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("scaffold com risco inválido", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "scaffold", "--title", "X", "--risk", "L9")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "--risk inválido: L9. Opções: L0, L1, L2, L3, L4\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("import sem Works v3", func(t *testing.T) {
		dir := inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "import")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.HasPrefix(stdout, "=== [pwn work import] Importando Works do layout v3 para o layout canônico ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "Nenhum Work v3 encontrado em " + filepath.Join(dir, ".todo") + " (esperado NNNN-tasks.md).\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("import com risco inválido", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "import", "--risk", "L9")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "--risk inválido: L9. Opções: auto, L0, L1, L2, L3, L4\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("reconcile com risco inválido", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "reconcile", "--risk", "L9")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "--risk inválido: L9. Opções: L0, L1, L2, L3, L4\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})
}

func TestWorkRunCLI(t *testing.T) {
	t.Run("work ausente bloqueia a cadeia", func(t *testing.T) {
		dir := inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "run", "--work", "0001", "--", "bun", "test")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.HasPrefix(stdout, "=== [pwn work run] Executando Work via Pipeline ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "\n[GATE BLOCKED] Work 0001 não existe em " + filepath.Join(dir, ".pwn", "work", "0001") +
			". Rode 'pwn work init 0001' e complete a cadeia de artefatos antes de 'pwn work run'.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("sem comando e sem gate", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "run", "--no-gate")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "⚠  Gates bypassados (--no-gate): execução sem validação da cadeia determinística.\n") {
			t.Fatalf("stderr sem o aviso: %q", stderr)
		}
		if !strings.Contains(stderr, "Nenhum comando informado. Uso: pwn work run --work NNNN --timeout-seconds N -- <comando>\n") {
			t.Fatalf("stderr sem o uso: %q", stderr)
		}
	})

	t.Run("dry-run sem artefatos", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "run", "--dry-run", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		for _, want := range []string{
			"=== [pwn work run] Simulação (--dry-run) do Work 0001 — nada será executado ===\n",
			"\n── Gates ──\n",
			"\n── Contratos ──\n  (plan.json ausente)\n",
			"\n── Impedimentos ──\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout sem %q:\n%s", want, stdout)
			}
		}
		if !strings.Contains(stderr, "  - plan.json ausente para o Work 0001.\n") {
			t.Fatalf("stderr = %q", stderr)
		}
		if !strings.Contains(stderr, "[DRY-RUN]: ") {
			t.Fatalf("stderr sem o resumo: %q", stderr)
		}
	})
}

func TestWorkRunAllCLI(t *testing.T) {
	t.Run("sem comando", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "run-all")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "=== [pwn work run-all] Executando Works em paralelo (um subprocesso por Work) ===\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
		wantErr := "Nenhum comando informado. Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando>\n"
		if stderr != wantErr {
			t.Fatalf("stderr = %q, quer %q", stderr, wantErr)
		}
	})

	t.Run("jobs inválido", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "run-all", "--jobs", "0", "--", "bun", "test")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "✗ --jobs inválido: '0' (esperado inteiro >= 1)\n" +
			"Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando de aceitação>\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("nenhum Work com plano", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "run-all", "--", "bun", "test")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "Nenhum Work com plano encontrado. Informe --works NNNN,NNNN ou rode `pwn work scaffold`.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})
}

func TestWorkStatusAndSyncCLI(t *testing.T) {
	t.Run("coverage de Work ausente", func(t *testing.T) {
		dir := inTempDir(t)
		code, _, stderr := runCLI(t, "work", "status", "--coverage", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "Work 0001 não encontrado em " + filepath.Join(dir, ".pwn", "work", "0001") + ".\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("coverage completo", func(t *testing.T) {
		dir := inTempDir(t)
		if code, _, stderr := runCLI(t, "work", "init", "0002"); code != 0 {
			t.Fatalf("work init: stderr = %q", stderr)
		}
		code, stdout, _ := runCLI(t, "work", "status", "--coverage", "0002")
		if code != 0 {
			t.Fatalf("código = %d, quer 0", code)
		}
		want := strings.Join([]string{
			"=== [pwn work status --coverage] Cobertura do Work 0002 ===",
			"",
			"  ✓ requisitos aceitos                 1/1",
			"  · capabilities com regras            0/0",
			"  · tasks com contrato congelado       0/0",
			"  · tasks com critérios de aceite      0/0",
			"",
			"[COVERAGE RESULT]: COMPLETO",
			"",
		}, "\n")
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q (dir %s)", stdout, want, dir)
		}
	})

	t.Run("coverage com lacunas", func(t *testing.T) {
		dir := inTempDir(t)
		if code, _, stderr := runCLI(t, "work", "init", "0002"); code != 0 {
			t.Fatalf("work init: stderr = %q", stderr)
		}
		writeFile(t, filepath.Join(dir, ".pwn", "work", "0002", "prd.json"), `{"accepted_requirements":[]}`)
		code, stdout, _ := runCLI(t, "work", "status", "--coverage", "0002")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stdout, "  ⚠ requisitos aceitos                 0/1\n") {
			t.Fatalf("stdout sem a lacuna:\n%s", stdout)
		}
		if !strings.Contains(stdout, "[COVERAGE RESULT]: 1 lacuna(s)\n") {
			t.Fatalf("stdout sem o resumo:\n%s", stdout)
		}
	})

	t.Run("status do projeto", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "status")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if !strings.HasPrefix(stdout, "=== [pwn work status] Relatório de Status do Work ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
	})

	t.Run("status com dois alvos", func(t *testing.T) {
		inTempDir(t)
		code, _, stderr := runCLI(t, "work", "status", "0001", "0002")
		if code != 2 {
			t.Fatalf("código = %d, quer 2", code)
		}
		want := "usage: project_status.js [NNNN | CANONICAL_PLAN_PATH | legacy] [--json]\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("sync sem manifest", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "sync", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stdout != "=== [pwn work sync] Sincronizando estado do manifest .work/NNNN.json ===\n" {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "Manifest .work/0001.json não encontrado. Nada a sincronizar.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})
}

func TestTaskCLI(t *testing.T) {
	t.Run("run sem argumentos", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "task", "run", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stdout != "=== [pwn task run] Executando task atômica sob contrato ===\n" {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "Uso: pwn task run --work NNNN --task 1.1 --timeout-seconds N -- <comando>\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("capsule sem task", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "task", "capsule")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "=== [pwn task capsule] Context Capsule (contrato congelado V4) para (task-id) ===\n\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
		if stderr != "Uso: pwn task capsule <task-id> [work-id]\n" {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("capsule sem contrato", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "task", "capsule", "1.1", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stdout != "=== [pwn task capsule] Context Capsule (contrato congelado V4) para 1.1 ===\n\n" {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.HasPrefix(stderr, "✗ Não foi possível gerar a cápsula: ") {
			t.Fatalf("stderr = %q", stderr)
		}
		if !strings.Contains(stderr, "  O contrato V4 deve estar congelado em .pwn/work/<id>/<contract_id>.json.\n") {
			t.Fatalf("stderr sem a dica: %q", stderr)
		}
	})
}

func TestVerifyCLI(t *testing.T) {
	t.Run("init", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "verify", "init")
		if code != 0 && code != 2 {
			t.Fatalf("código = %d, quer 0 ou 2 (stderr: %q)", code, stderr)
		}
		if !strings.HasPrefix(stdout, "=== [pwn verify init] Raiz protegida do verificador ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		for _, want := range []string{"  Raiz:      ", "  Estado:    ", "  Verifier:  ", "  Runtime:   ", "  bwrap:     "} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout sem %q:\n%s", want, stdout)
			}
		}
		if code == 2 && !strings.Contains(stderr, "[VERIFICATION BLOCKED] ") {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("approve sem alvo", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, _, stderr := runCLI(t, "verify", "approve", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "[VERIFY ERROR] informe --task T ou --global G-n\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("run sem aprovação", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, _, stderr := runCLI(t, "verify", "run", "--work", "0001", "--task", "1.1")
		if code != 2 {
			t.Fatalf("código = %d, quer 2", code)
		}
		want := "[VERIFICATION BLOCKED] não existe aprovação vigente para 0001/1.1.\n" +
			"Aprove antes: pwn verify approve --work 0001 --task 1.1 --by <nome>\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("run-all sem aprovações", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "verify", "run-all", "--work", "0001")
		if code != 2 {
			t.Fatalf("código = %d, quer 2 (stderr: %q)", code, stderr)
		}
		if !strings.HasPrefix(stdout, "=== [pwn verify run-all] Work 0001: 0 task(s), jobs=") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "[VERIFICATION BLOCKED] nenhuma aprovação vigente para o Work 0001.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("run-all com jobs inválido", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, _, stderr := runCLI(t, "verify", "run-all", "--work", "0001", "--jobs", "0")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "[VERIFY ERROR] --jobs deve ser inteiro >= 1\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("status sem aprovação", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, stdout, _ := runCLI(t, "verify", "status", "--work", "0001", "--task", "1.1")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.HasPrefix(stdout, "NOT ACCEPTED 0001/1.1 — ") {
			t.Fatalf("stdout = %q", stdout)
		}
	})

	t.Run("show sem aprovações", func(t *testing.T) {
		root := isolatedVerifier(t)
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "verify", "show", "--work", "0001")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn verify show] Verificador em " + root + " ===\n  (nenhuma aprovação registrada para este Work)\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})
}

func TestInitCLI(t *testing.T) {
	t.Run("fora de repositório Git", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "init")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stdout != "" {
			t.Fatalf("stdout = %q, quer vazio", stdout)
		}
		want := "✗ pwn init precisa rodar dentro de um repositório Git (worktrees, diff guard e recibos dependem dele).\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("sem terminal registra projeto sem decisor", func(t *testing.T) {
		root := isolatedVerifier(t)
		dir := gitRepo(t)
		code, stdout, stderr := runCLI(t, "init")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if !strings.HasPrefix(stdout, "=== [pwn init] "+dir+" ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.Contains(stdout, "✓ sem decisor: as decisões do operador continuam com você\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.Contains(stdout, "  gravado fora do repositório, em "+root+"/deciders/\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		want := "⚠  Sem terminal para perguntar pelo decisor: projeto registrado sem decisor. Para configurar: pwn init --decider jev:jev-latest\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("--decider e --no-decider juntos", func(t *testing.T) {
		isolatedVerifier(t)
		gitRepo(t)
		code, _, stderr := runCLI(t, "init", "--decider", "jev:jev-latest", "--no-decider")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "✗ use --decider ou --no-decider, não os dois\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("--decider sem valor", func(t *testing.T) {
		isolatedVerifier(t)
		gitRepo(t)
		code, _, stderr := runCLI(t, "init", "--decider")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "✗ --decider exige <provedor>:modelo\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("--decider configura e avisa da chave", func(t *testing.T) {
		isolatedVerifier(t)
		gitRepo(t)
		t.Setenv("PWN_TEST_KEY", "")
		code, stdout, stderr := runCLI(t, "init", "--decider", "jev:jev-latest", "--decider-key-env", "PWN_TEST_KEY")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if !strings.Contains(stdout, "✓ decisor jev:jev-latest (chave em $PWN_TEST_KEY, teto de risco L3)\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.Contains(stderr, "⚠  $PWN_TEST_KEY não está definida nesta sessão: sem ela, cada decisão vai para a fila humana.\n") {
			t.Fatalf("stderr = %q", stderr)
		}
	})
}

func TestDeciderCLI(t *testing.T) {
	t.Run("fora de repositório Git", func(t *testing.T) {
		isolatedVerifier(t)
		inTempDir(t)
		code, _, stderr := runCLI(t, "decider", "show")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "✗ pwn decider precisa rodar dentro de um repositório Git.\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})

	t.Run("ciclo show/set/show/log/remove", func(t *testing.T) {
		isolatedVerifier(t)
		gitRepo(t)

		code, stdout, _ := runCLI(t, "decider", "show")
		if code != 0 || stdout != "nenhuma configuração: rode 'pwn decider set' ou 'pwn init'\n" {
			t.Fatalf("show inicial: %d %q", code, stdout)
		}

		t.Setenv("PWN_TEST_KEY", "")
		code, stdout, stderr := runCLI(t, "decider", "set", "--decider", "jev:jev-latest", "--decider-key-env", "PWN_TEST_KEY")
		if code != 0 {
			t.Fatalf("set: código = %d (stderr: %q)", code, stderr)
		}
		if stdout != "✓ decisor jev:jev-latest (chave em $PWN_TEST_KEY, teto de risco L3)\n" {
			t.Fatalf("set stdout = %q", stdout)
		}
		if !strings.Contains(stderr, "⚠  $PWN_TEST_KEY não está definida nesta sessão") {
			t.Fatalf("set stderr = %q", stderr)
		}

		code, stdout, _ = runCLI(t, "decider", "show")
		if code != 0 || stdout != "decisor jev:jev-latest (chave em $PWN_TEST_KEY, teto de risco L3)\n" {
			t.Fatalf("show: %d %q", code, stdout)
		}

		code, stdout, _ = runCLI(t, "decider", "log")
		if code != 0 || stdout != "nenhuma decisão registrada\n" {
			t.Fatalf("log: %d %q", code, stdout)
		}

		code, stdout, _ = runCLI(t, "decider", "remove")
		if code != 0 || stdout != "✓ configuração removida: o projeto não usa decisor\n" {
			t.Fatalf("remove: %d %q", code, stdout)
		}

		code, stdout, _ = runCLI(t, "decider", "remove")
		if code != 0 || stdout != "nenhuma configuração para remover\n" {
			t.Fatalf("remove de novo: %d %q", code, stdout)
		}
	})

	t.Run("set sem decisor configurado", func(t *testing.T) {
		isolatedVerifier(t)
		gitRepo(t)
		code, _, stderr := runCLI(t, "decider", "set")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		want := "✗ não há decisor configurado: informe --decider <provedor:modelo>\n"
		if stderr != want {
			t.Fatalf("stderr = %q, quer %q", stderr, want)
		}
	})
}
