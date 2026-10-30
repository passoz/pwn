package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/queue"
)

func TestQueueHandler(t *testing.T) {
	t.Run("fila vazia", func(t *testing.T) {
		e := newEnv(t)
		e.queue("list").expect(t, 0,
			[]string{"=== [pwn queue list] Fila de Revisão Humana (AFK) ===\n\n", "Nenhuma tarefa pendente na fila de revisão queue/review/.\n"}, nil)
	})

	t.Run("lista, aprova e rejeita", func(t *testing.T) {
		e := newEnv(t)
		for _, item := range []queue.Item{
			{RunID: "RUN-a", WorkID: "0001", TaskID: "1.1", Title: "Primeira", PausedAtStep: "spawn", Reason: "L4", RiskLevel: "L4"},
			{RunID: "RUN-b", WorkID: "0001", TaskID: "1.2", Title: "Segunda", PausedAtStep: "spawn", Reason: "L4", RiskLevel: "L4"},
		} {
			if _, err := queue.Enqueue(item, e.dir, ""); err != nil {
				t.Fatalf("enfileirar %s: %v", item.RunID, err)
			}
		}

		listed := e.queue("list")
		listed.expect(t, 0, []string{
			"[PENDING_REVIEW] Run: RUN-a | Work: 0001 | Task: 1.1\n",
			"  Título: Primeira\n",
			"  Motivo: L4 (Risco: L4)\n",
			"  Pausado em: spawn | Criado em: ",
			"[PENDING_REVIEW] Run: RUN-b | Work: 0001 | Task: 1.2\n",
		}, nil)

		e.queue("approve", "RUN-a").expect(t, 0,
			[]string{"✓ Run RUN-a aprovada com sucesso! O pipeline pode ser retomado.\n"}, nil)
		e.queue("reject", "RUN-b").expect(t, 0,
			[]string{"✗ Run RUN-b rejeitada. A execução foi cancelada.\n"}, nil)

		after := e.queue("list")
		for _, want := range []string{"[APPROVED] Run: RUN-a", "[REJECTED] Run: RUN-b"} {
			if !strings.Contains(after.stdout, want) {
				t.Fatalf("stdout sem %q:\n%s", want, after.stdout)
			}
		}
	})

	t.Run("approve e reject exigem o run", func(t *testing.T) {
		e := newEnv(t)
		e.queue("approve").expect(t, 1, nil, []string{"Uso: pwn queue approve <run-id>\n"})
		e.queue("reject").expect(t, 1, nil, []string{"Uso: pwn queue reject <run-id>\n"})
	})

	t.Run("run inexistente", func(t *testing.T) {
		e := newEnv(t)
		e.queue("approve", "RUN-x").expect(t, 1, nil, []string{"Run RUN-x não encontrada na fila de revisão.\n"})
	})

	t.Run("item corrompido não atualiza", func(t *testing.T) {
		e := newEnv(t)
		e.write("queue/review/RUN-z.json", "{não é json")
		e.queue("approve", "RUN-z").expect(t, 1, nil, []string{"✗ queue: decodificar "})
	})

	t.Run("fila impossível de criar", func(t *testing.T) {
		e := newEnv(t)
		e.write("queue", "arquivo no lugar do diretório")
		e.queue("list").expect(t, 1, []string{"=== [pwn queue list]"}, []string{"✗ queue: criar "})
		e.queue("approve", "RUN-x").expect(t, 1, nil, []string{"✗ queue: criar "})
	})

	t.Run("subcomando desconhecido", func(t *testing.T) {
		e := newEnv(t)
		e.queue("nada").expect(t, 1,
			[]string{"\nUso:\n", "  pwn queue list      Lista itens", "  pwn queue reject    Rejeita"},
			[]string{"Subcomando desconhecido para 'pwn queue': nada\n"})
	})
}

func TestMetricsHandler(t *testing.T) {
	t.Run("sem métricas", func(t *testing.T) {
		e := newEnv(t)
		e.metrics("list").expect(t, 0, []string{"Nenhuma métrica registrada em .pwn/metrics.jsonl ainda.\n"}, nil)
		e.metrics("optimize").expect(t, 0, []string{
			"Sem histórico de métricas suficiente para recomendar otimização de routing.\n",
			"Rode tarefas com \"pwn work run\" primeiro;",
		}, nil)
	})

	t.Run("lista totais e sugere otimização", func(t *testing.T) {
		e := newEnv(t)
		entries := []metrics.Entry{
			{RunID: "RUN-1", WorkID: "0001", TaskID: "1.1", AgentRole: metrics.RoleStrong, Model: "m-forte",
				TokensInput: 100, TokensOutput: 50, CostUSD: 0.25, DurationMs: 1200,
				Status: metrics.StatusSuccess, Attempts: 1, Isolated: true},
			{RunID: "RUN-2", WorkID: "0001", TaskID: "1.2", AgentRole: metrics.RoleCheap, Model: "m-barato",
				TokensInput: 10, TokensOutput: 5, CostUSD: 0.0125, DurationMs: 300,
				Status: metrics.StatusFailed, Attempts: 2},
		}
		for _, entry := range entries {
			if err := metrics.Record(entry, e.dir); err != nil {
				t.Fatalf("registrar métrica: %v", err)
			}
		}

		listed := e.metrics("list")
		listed.expect(t, 0, []string{
			"[SUCCESS] Run: RUN-1 | Task: 1.1 | Role: strong (m-forte)\n",
			"  Tokens: 150 | Custo: $0.2500 | Duração: 1200ms | Tentativas: 1 | Sandbox: sim\n",
			"[FAILED] Run: RUN-2 | Task: 1.2 | Role: cheap (m-barato)\n",
			"  Tokens: 15 | Custo: $0.0125 | Duração: 300ms | Tentativas: 2 | Sandbox: NÃO (--no-isolation)\n",
			"Total de Execuções: 2\n",
			"Consumo Total de Tokens: 165\n",
			"Custo Total Estimado: $0.2625 USD\n",
		}, nil)

		e.metrics("optimize").expect(t, 0, []string{
			"[Sugestão #1] Papel Atual: strong (m-forte) -> Recomendado: cheap\n",
			"1 execuções com papel 'strong' tiveram sucesso no 1º turno.",
			"  Economia Estimada: 65%\n",
			"NOTA: Nenhuma alteração de arquivo é feita automaticamente.",
		}, nil)
	})

	t.Run("métricas sem papel strong não geram sugestão", func(t *testing.T) {
		e := newEnv(t)
		entry := metrics.Entry{RunID: "RUN-1", AgentRole: metrics.RoleCheap, Model: "m", Status: metrics.StatusSuccess, Attempts: 1}
		if err := metrics.Record(entry, e.dir); err != nil {
			t.Fatalf("registrar métrica: %v", err)
		}
		e.metrics("optimize").expect(t, 0, []string{"Sem histórico de métricas suficiente"}, nil)
	})

	t.Run(".pwn impossível de criar", func(t *testing.T) {
		e := newEnv(t)
		e.write(".pwn", "arquivo no lugar do diretório")
		e.metrics("list").expect(t, 1, nil, []string{"✗ metrics: criar "})
		e.metrics("optimize").expect(t, 1, nil, []string{"✗ metrics: criar "})
	})

	t.Run("subcomando desconhecido", func(t *testing.T) {
		e := newEnv(t)
		e.metrics("nada").expect(t, 1,
			[]string{"  pwn metrics list       Exibe", "  pwn metrics optimize   Gera"},
			[]string{"Subcomando desconhecido para 'pwn metrics': nada\n"})
	})
}

func TestTargetHandler(t *testing.T) {
	t.Run("list descreve todos os runtimes", func(t *testing.T) {
		e := newEnv(t)
		e.target("list").expect(t, 0, []string{
			"=== [pwn target list] Runtimes e Matriz de Capacidades ===\n\n",
			"• Target: PI (",
			"• Target: OMP (",
			"  Contratos V4:        ",
			"  Formato Principal:   ",
		}, nil)
	})

	t.Run("subcomando desconhecido", func(t *testing.T) {
		e := newEnv(t)
		e.target("nada").expect(t, 1,
			[]string{"  pwn target materialize --target <target>"},
			[]string{"Subcomando desconhecido para 'pwn target': nada\n"})
	})

	t.Run("materialize usa pi e o diretório padrão", func(t *testing.T) {
		e := newEnv(t)
		outDir := filepath.Join(e.dir, ".pwn", "targets", "pi")
		result := e.target("materialize")
		result.expect(t, 0, []string{
			"=== [pwn target materialize] Materializando artefatos para PI ===\n",
			"✓ Materialização concluída com sucesso em: " + outDir + "\n",
			"Arquivos Gerados:\n",
		}, nil)
		entries, err := os.ReadDir(outDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("nada foi gerado em %s: %v", outDir, err)
		}
	})

	t.Run("materialize omp com --out e escopo do Work", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		outDir := filepath.Join(t.TempDir(), "saida")
		result := e.target("materialize", "--target", "omp", "--work", "0001", "--out", outDir)
		result.expect(t, 0, []string{
			"=== [pwn target materialize] Materializando artefatos para OMP ===\n",
			"✓ Escopo derivado de 1 contrato(s) do Work 0001 (risco L2).\n",
			"✓ Materialização concluída com sucesso em: " + outDir + "\n",
		}, nil)
		if _, err := os.Stat(outDir); err != nil {
			t.Fatalf("diretório de saída ausente: %v", err)
		}
	})

	t.Run("Work sem plano", func(t *testing.T) {
		e := newEnv(t)
		e.target("materialize", "--work", "0009").expect(t, 1, nil, []string{
			"✗ Não foi possível carregar contratos do Work 0009: plan.json não encontrado para o Work 0009\n",
		})
	})

	t.Run("target desconhecido", func(t *testing.T) {
		e := newEnv(t)
		e.target("materialize", "--target", "nada").expect(t, 1, nil, []string{
			"Target desconhecido ou não suportado para materialização automática: nada\n",
		})
	})

	t.Run("falha ao gravar a saída", func(t *testing.T) {
		e := newEnv(t)
		blocked := filepath.Join(e.dir, "bloqueado")
		e.write("bloqueado", "arquivo")
		e.target("materialize", "--target", "opencode", "--out", filepath.Join(blocked, "dentro")).
			expect(t, 1, nil, []string{"✗ Materialização falhou: "})
	})
}

func TestRunnerZeroValueUsesWorkingDirectory(t *testing.T) {
	e := newEnv(t)
	if _, err := queue.Enqueue(queue.Item{RunID: "RUN-w", WorkID: "0001", TaskID: "1.1"}, e.dir, ""); err != nil {
		t.Fatalf("enfileirar: %v", err)
	}
	// Sem Stdout, Stderr nem RootDir: a saída é descartada e a raiz é o cwd.
	runner := &Runner{}
	if code := runner.Queue("approve", []string{"RUN-w"}); code != 0 {
		t.Fatalf("código = %d, quer 0", code)
	}
	if code := runner.Queue("approve", []string{"RUN-inexistente"}); code != 1 {
		t.Fatalf("código = %d, quer 1", code)
	}
	items, err := queue.List(e.dir)
	if err != nil || len(items) != 1 || items[0].Status != queue.StatusApproved {
		t.Fatalf("itens = %+v (erro %v), quer RUN-w aprovado", items, err)
	}
}

func TestSupportHelpers(t *testing.T) {
	t.Run("flagListAfter", func(t *testing.T) {
		args := []string{"--task", "1.1", "--freeze-tests", "a.ts", "b.ts", "--work", "0001"}
		got := flagListAfter(args, "--freeze-tests")
		if strings.Join(got, ",") != "a.ts,b.ts" {
			t.Fatalf("lista = %v, quer [a.ts b.ts]", got)
		}
		if got := flagListAfter(args, "--work"); strings.Join(got, ",") != "0001" {
			t.Fatalf("lista final = %v, quer [0001]", got)
		}
		if got := flagListAfter(args, "--ausente"); got == nil || len(got) != 0 {
			t.Fatalf("flag ausente = %#v, quer lista vazia não nula", got)
		}
	})

	t.Run("resolvedDir", func(t *testing.T) {
		e := newEnv(t)
		runner := &Runner{RootDir: e.dir}
		if got := runner.resolvedDir(nil); got != e.dir {
			t.Fatalf("sem --dir = %q, quer %q", got, e.dir)
		}
		if got := runner.resolvedDir([]string{"--dir", "sub"}); got != filepath.Join(e.dir, "sub") {
			t.Fatalf("--dir relativo = %q, quer %q", got, filepath.Join(e.dir, "sub"))
		}
		if got := runner.resolvedDir([]string{"--dir", "/abs/dir"}); got != "/abs/dir" {
			t.Fatalf("--dir absoluto = %q", got)
		}
	})

	t.Run("timeoutSecondsValue", func(t *testing.T) {
		tests := []struct {
			raw  string
			want int
		}{
			{"", 600},
			{"30", 30},
			{"1.2", 2},
			{"0.2", 1},
			{"0", 600},
			{"-5", 600},
			{"abc", 600},
			{"NaN", 600},
			{"Inf", 600},
		}
		for _, test := range tests {
			args := []string{"--timeout-seconds", test.raw}
			if test.raw == "" {
				args = nil
			}
			if got := timeoutSecondsValue(args); got != test.want {
				t.Errorf("timeoutSecondsValue(%q) = %d, quer %d", test.raw, got, test.want)
			}
		}
	})

	t.Run("printJSON preserva a ordem declarada", func(t *testing.T) {
		var out strings.Builder
		runner := &Runner{Stdout: &out}
		runner.printJSON(struct {
			Zeta  int    `json:"zeta"`
			Alfa  string `json:"alfa"`
			Lista []int  `json:"lista"`
		}{Zeta: 1, Alfa: "a", Lista: []int{1, 2}})
		want := "{\n  \"zeta\": 1,\n  \"alfa\": \"a\",\n  \"lista\": [\n    1,\n    2\n  ]\n}\n"
		if out.String() != want {
			t.Fatalf("JSON = %q, quer %q", out.String(), want)
		}
	})

	t.Run("printJSON com valor inválido escreve o erro", func(t *testing.T) {
		var out, errOut strings.Builder
		runner := &Runner{Stdout: &out, Stderr: &errOut}
		runner.printJSON(make(chan int))
		if out.Len() != 0 || !strings.HasPrefix(errOut.String(), "✗ ") {
			t.Fatalf("stdout = %q, stderr = %q", out.String(), errOut.String())
		}
	})
}
