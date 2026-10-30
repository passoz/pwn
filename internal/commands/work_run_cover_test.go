package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/queue"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/work"
)

// approvedWork deixa o Work com aceitação aprovada: o script de check cria a
// implementação que o teste congelado exige, e o verificador usa o bwrap de teste.
func approvedWork(e *env, workID, checkScript string) {
	e.t.Helper()
	e.scaffold(workID)
	e.write("tests/check.sh", checkScript)
	e.commit("script de check")
	e.configureVerifier(fakeBwrap(e.t))
	e.freezeAndApprove(workID)
}

const implementScript = "echo implementado\n"

func TestWorkRunHandler(t *testing.T) {
	t.Run("aceitação aprovada conclui a task", func(t *testing.T) {
		e := newEnv(t)
		approvedWork(e, "0001", implementScript)
		// A implementação chega depois da aprovação: o baseline não a contém.
		e.write("src/add-widget.ts", "export const widget = 1\n")

		result := e.work("run", "--work", "0001", "--task", "1.1", "--timeout-seconds", "60", "--", "sh", "tests/check.sh")
		result.expect(t, 0, []string{
			"=== [pwn work run] Executando Work via Pipeline ===\n",
			"✓ GATE-DISC-REQ: pass\n",
			"✓ GATE-PLAN-CONTRACT: pass\n",
			"✓ Todos os gates determinísticos aprovados — Work elegível para execução.\n",
			"implementado\n",
			"✓ Aceitação independente: PASS (recibo ",
		}, nil)
		e.verify("status", "--work", "0001", "--task", "1.1").expect(t, 0, []string{"ACCEPTED 0001/1.1 — recibo "}, nil)
		if _, err := os.Stat(filepath.Join(e.dir, ".pwn", "metrics.jsonl")); err != nil {
			t.Fatalf("a execução não registrou métricas: %v", err)
		}
	})

	t.Run("comando que falha devolve o status dele", func(t *testing.T) {
		e := newEnv(t)
		approvedWork(e, "0001", "echo falhou >&2\nexit 3\n")
		result := e.work("run", "--work", "0001", "--task", "1.1", "--", "sh", "tests/check.sh")
		result.expect(t, 3, nil, []string{
			"[RUN FAILED] Execução terminou com status 3 para a task 1.1 (work 0001).\n",
		})
		if strings.Contains(result.stdout, "Aceitação independente") {
			t.Fatalf("a aceitação não roda depois de uma falha:\n%s", result.stdout)
		}
	})

	t.Run("escrita fora do escopo é violação de diff", func(t *testing.T) {
		e := newEnv(t)
		approvedWork(e, "0001", "echo fora > outside.txt\n")
		e.work("run", "--work", "0001", "--task", "1.1", "--", "sh", "tests/check.sh").expect(t, 1, nil, []string{
			"\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:\n",
			"  - outside.txt: Arquivo outside.txt não consta na allowlist de escrita: [src/**, tests/**]\n",
			"[RUN FAILED] Execução terminou com status 1 para a task 1.1 (work 0001).\n",
		})
		if e.exists("outside.txt") {
			t.Fatal("a escrita fora do escopo vazou para o repositório")
		}
	})

	t.Run("sem aprovação a execução não conclui", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		result := e.work("run", "--work", "0001", "--task", "1.1", "--", "sh", "tests/check.sh")
		if result.code != 0 {
			t.Fatalf("código = %d, quer 0\n%s\n%s", result.code, result.stdout, result.stderr)
		}
		if !strings.Contains(result.stdout+result.stderr, "sem aprovação de aceitação independente para 0001/1.1; a execução não produz conclusão") {
			t.Fatalf("sem o aviso de aprovação ausente:\nstdout: %s\nstderr: %s", result.stdout, result.stderr)
		}
	})

	t.Run("sem --task a aceitação independente fica para o verify", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("run", "--work", "0001", "--", "sh", "tests/check.sh").expect(t, 0, []string{
			"· Aceitação independente exige --task (ou use: pwn verify run --work NNNN --task T).\n",
		}, nil)
	})

	t.Run("gate bloqueado interrompe a cadeia", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		breakRequirements(e, "0001")
		e.work("run", "--work", "0001", "--", "sh", "tests/check.sh").expect(t, 1,
			[]string{"✓ GATE-DISC-REQ: pass\n", "\"result\": \"blocked\""},
			[]string{"\n[GATE BLOCKED] GATE-REQ-PRD bloqueou o Work 0001. Resolva os findings ou use --no-gate somente se o risco for aceito por humano.\n"})
	})

	t.Run("markdown divergente do plan.json bloqueia", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		original := e.read(".todo/0001-tasks.md")
		e.write(".todo/0001-tasks.md", strings.Replace(original, "### [ ] [1.1] Add widget", "### [ ] [1.1] Widget editado à mão", 1))
		e.work("run", "--work", "0001", "--", "sh", "tests/check.sh").expect(t, 1, nil, []string{
			"\n[DRIFT BLOCKED] .todo/0001-tasks.md diverge de plan.json. Regenere com 'pwn work plan --work 0001 --force' ou resolva a divergência.\n",
		})
	})

	t.Run("--no-gate e --no-isolation rodam no diretório de trabalho", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.write("tests/check.sh", "mkdir -p src\necho direto > src/direto.ts\n")
		e.commit("check escreve em src")
		result := e.work("run", "--work", "0001", "--no-gate", "--no-isolation", "--no-sync", "--", "sh", "tests/check.sh")
		result.expect(t, 0,
			[]string{"· Manifest .work/0001.json não sincronizado (--no-sync).\n"},
			[]string{
				"⚠  Gates bypassados (--no-gate): execução sem validação da cadeia determinística.\n",
				"⚠  Sandbox desabilitado (--no-isolation): execução no diretório de trabalho, sem diff guard.\n",
			})
		if strings.Contains(result.stdout, "GATE-") {
			t.Fatalf("--no-gate não pode avaliar gates:\n%s", result.stdout)
		}
		if got := e.read("src/direto.ts"); got != "direto\n" {
			t.Fatalf("src/direto.ts = %q: sem isolamento o comando escreve direto na árvore", got)
		}
	})

	t.Run("sincroniza o manifest ao fim", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		if _, err := work.ReserveWork(e.dir, work.ReserveWorkOptions{WorkID: "0001", OriginType: "manual"}); err != nil {
			t.Fatalf("reservar Work: %v", err)
		}
		e.work("run", "--work", "0001", "--no-gate", "--", "sh", "tests/check.sh").expect(t, 0,
			[]string{"✓ Manifest .work/0001.json → state: planned\n"}, nil)
	})

	t.Run("manifest ilegível interrompe a sincronização", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.write(".work/0001.json", "{não é json")
		e.work("run", "--work", "0001", "--no-gate", "--", "sh", "tests/check.sh").expect(t, 1, nil, []string{"✗ "})
	})

	t.Run("task L4 fica suspensa até a aprovação da fila", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.mutateJSON(".pwn/work/0001/CTR-001.json", func(document map[string]any) {
			document["risk"].(map[string]any)["level"] = "L4"
		})
		e.commit("risco L4")

		suspended := e.work("run", "--work", "0001", "--task", "1.1", "--no-gate", "--", "sh", "tests/check.sh")
		if suspended.code != run.ExitSuspended {
			t.Fatalf("código = %d, quer %d\nstderr: %s", suspended.code, run.ExitSuspended, suspended.stderr)
		}
		match := regexp.MustCompile(`Use 'pwn queue approve (RUN-[A-Za-z0-9_-]+)' para destravar \(exit code (\d+)\)\.`).FindStringSubmatch(suspended.stderr)
		if match == nil {
			t.Fatalf("stderr sem a instrução da fila:\n%s", suspended.stderr)
		}
		if !strings.Contains(suspended.stderr, "[SUSPENDED] A task 1.1 do Work 0001 não foi executada: aguarda decisão humana na fila AFK.\n") {
			t.Fatalf("stderr sem o aviso de suspensão:\n%s", suspended.stderr)
		}
		if strings.Contains(suspended.stdout, "Manifest") {
			t.Fatalf("suspensão não sincroniza o manifest:\n%s", suspended.stdout)
		}

		e.queue("list").expect(t, 0, []string{"[PENDING_REVIEW] Run: " + match[1] + " | Work: 0001 | Task: 1.1\n"}, nil)
		e.queue("approve", match[1]).mustOK(t, "queue approve")
		items, err := queue.List(e.dir)
		if err != nil || len(items) != 1 || items[0].Status != queue.StatusApproved {
			t.Fatalf("fila = %+v (erro %v), quer o item aprovado", items, err)
		}

		e.work("run", "--work", "0001", "--task", "1.1", "--no-gate", "--", "sh", "tests/check.sh").expect(t, 0,
			[]string{"checado\n"}, nil)
	})
}

func TestWorkRunDryRunHandler(t *testing.T) {
	t.Run("Work elegível", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("run", "--dry-run", "--work", "0001", "--", "sh", "tests/check.sh").expect(t, 0, []string{
			"=== [pwn work run] Simulação (--dry-run) do Work 0001 — nada será executado ===\n",
			"GATE-PLAN-CONTRACT: pass (0 findings)\n",
			"✓ 1.1 — CTR-001 | risco L2 | 2 write_allow | 3 comando(s)\n",
			"\n── Impedimentos ──\n(nenhum) — Work elegível para execução.\n",
		}, nil)
		if e.exists(".pwn/metrics.jsonl") {
			t.Fatal("dry-run não pode executar nada")
		}
	})

	t.Run("gate bloqueado vira impedimento com o finding", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		breakRequirements(e, "0001")
		e.work("run", "--dry-run", "--work", "0001").expect(t, 1,
			[]string{"GATE-REQ-PRD: blocked (1 findings)\n"},
			[]string{"  - GATE-REQ-PRD: blocked — FIND-PRD-XREF-FR-001\n", "\n[DRY-RUN]: 1 impedimento(s). A execução ficaria bloqueada.\n"})
	})

	t.Run("contrato incompleto lista cada problema", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.mutateJSON(".pwn/work/0001/CTR-001.json", func(document map[string]any) {
			document["scope_contract"].(map[string]any)["write_allow"] = []any{}
			document["acceptance_contract"].(map[string]any)["commands"] = []any{}
		})
		e.work("run", "--dry-run", "--work", "0001").expect(t, 1, nil, []string{
			"✗ 1.1 — scope_contract.write_allow vazio; acceptance_contract.commands vazio\n",
			"  - Task 1.1 (CTR-001): scope_contract.write_allow vazio\n",
			"  - Task 1.1 (CTR-001): acceptance_contract.commands vazio\n",
			"[DRY-RUN]:",
		})
	})

	t.Run("contrato ausente", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		if err := os.Remove(filepath.Join(e.dir, ".pwn", "work", "0001", "CTR-001.json")); err != nil {
			t.Fatalf("remover contrato: %v", err)
		}
		e.work("run", "--dry-run", "--work", "0001").expect(t, 1, nil, []string{"✗ 1.1 — ", "  - Task 1.1: ", "[DRY-RUN]:"})
	})
}

// fakePwn grava um executável de teste que imita `pwn work run --work ID ...`:
// ecoa os argumentos, cita um RUN-<id> e sai com o código do Work informado.
func fakePwn(t *testing.T, exitCodes map[string]string) {
	t.Helper()
	var cases strings.Builder
	for workID, code := range exitCodes {
		cases.WriteString("  " + workID + ") exit " + code + ";;\n")
	}
	script := "#!/bin/sh\nid=$4\necho \"args: $*\"\necho \"RUN-fake$id\"\necho \"aviso $id\" >&2\ncase $id in\n" +
		cases.String() + "esac\nexit 0\n"
	path := filepath.Join(t.TempDir(), "pwn-fake")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("escrever executável de teste: %v", err)
	}
	t.Setenv(selfExecutableEnv, path)
}

func TestWorkRunAllHandler(t *testing.T) {
	t.Run("sucesso em todos os Works", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.scaffold("0002")
		fakePwn(t, nil)
		result := e.work("run-all", "--jobs", "2", "--timeout-seconds", "30", "--no-gate", "--", "sh", "tests/check.sh")
		result.expect(t, 0, []string{
			"=== [pwn work run-all] Executando Works em paralelo (um subprocesso por Work) ===\n",
			"· 2 Work(s): 0001, 0002 | jobs=2\n",
			"[0001] args: work run --work 0001 --no-gate --timeout-seconds 30 -- sh tests/check.sh\n",
			"[0002] args: work run --work 0002 --no-gate --timeout-seconds 30 -- sh tests/check.sh\n",
			"\n── Resumo run-all ──\n",
			"[RUN-ALL]: 2 Work(s) concluído(s) com sucesso.\n",
		}, []string{"[0001] aviso 0001\n", "[0002] aviso 0002\n"})
		for _, workID := range []string{"0001", "0002"} {
			summary := regexp.MustCompile(`✓ Work ` + workID + `: exit 0 \| \d+\.\ds \| RUN-fake` + workID + `\n`)
			if !summary.MatchString(result.stdout) {
				t.Fatalf("resumo do Work %s ausente:\n%s", workID, result.stdout)
			}
		}
	})

	t.Run("falha agrega o maior código e avisa de escopos sobrepostos", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.scaffold("0002")
		for _, workID := range []string{"0001", "0002"} {
			e.mutateJSON(".pwn/work/"+workID+"/CTR-001.json", func(document map[string]any) {
				document["scope_contract"].(map[string]any)["write_allow"] = []any{"src/**", "lib/**", "docs/**", "cmd/**"}
			})
		}
		fakePwn(t, map[string]string{"0002": "3"})
		result := e.work("run-all", "--works", "0001,0002", "--jobs", "1", "--", "sh", "tests/check.sh")
		result.expect(t, 3, []string{
			"· 2 Work(s): 0001, 0002 | jobs=1\n",
			"[0001] args: work run --work 0001 --timeout-seconds 600 -- sh tests/check.sh\n",
			"✗ Work 0002: exit 3",
			"[RUN-ALL]: 1/2 Work(s) falharam (exit 3).\n",
		}, []string{
			"⚠  Possível conflito de merge entre Works 0001 e 0002: write_allow sobreposto (src/** ↔ src/**; lib/** ↔ lib/**; docs/** ↔ docs/**; …). Cada um roda em worktree isolado.\n",
		})
		if !regexp.MustCompile(`✗ Work 0002: exit 3 \| \d+\.\ds \| RUN-fake0002\n`).MatchString(result.stdout) {
			t.Fatalf("resumo do Work 0002 ausente:\n%s", result.stdout)
		}
	})

	t.Run("descobre os Works com plano", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0004")
		fakePwn(t, nil)
		e.work("run-all", "--", "sh", "tests/check.sh").expect(t, 0, []string{
			"· 1 Work(s): 0004 | jobs=1\n",
			"[RUN-ALL]: 1 Work(s) concluído(s) com sucesso.\n",
		}, nil)
	})

	t.Run("contratos não carregados viram aviso", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		fakePwn(t, nil)
		e.work("run-all", "--works", "0001,0009", "--", "sh", "tests/check.sh").expect(t, 0, nil, []string{
			"⚠  Work 0009: contratos não carregados para a checagem de escopo (plan.json não encontrado para o Work 0009).\n",
		})
	})

	t.Run("argumentos inválidos", func(t *testing.T) {
		e := newEnv(t)
		e.work("run-all", "--timeout-seconds", "0", "--", "x").expect(t, 1, nil, []string{
			"✗ --timeout-seconds inválido: '0' (esperado número > 0)\n",
			"Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando de aceitação>\n",
		})
	})
}
