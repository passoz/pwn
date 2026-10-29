package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/queue"
)

// inTempDir troca o diretório de trabalho para um diretório temporário.
func inTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("criar diretório de %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("escrever %s: %v", path, err)
	}
}

func targetBlock(t *testing.T, label, name string, flags ...bool) string {
	t.Helper()
	checks := func(value bool) string {
		if value {
			return "✓"
		}
		return "✗"
	}
	formats := map[string]string{
		"PI":       "AGENTS.md",
		"OPENCODE": "AGENTS.md",
		"OMP":      "AGENTS.md",
		"RAW":      "prompt.txt",
	}
	var builder strings.Builder
	builder.WriteString("• Target: " + label + " (" + name + ")\n")
	builder.WriteString("  System Prompt:       " + checks(flags[0]) + "\n")
	builder.WriteString("  Subagents:           " + checks(flags[1]) + "\n")
	builder.WriteString("  Skills:              " + checks(flags[2]) + "\n")
	builder.WriteString("  Tool Calling:        " + checks(flags[3]) + "\n")
	builder.WriteString("  Contratos V4:        " + checks(flags[4]) + "\n")
	builder.WriteString("  Worktree Sandbox:    " + checks(flags[5]) + "\n")
	builder.WriteString("  Formato Principal:   " + formats[label] + "\n\n")
	return builder.String()
}

func TestTargetList(t *testing.T) {
	inTempDir(t)

	code, stdout, stderr := runCLI(t, "target", "list")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	want := "=== [pwn target list] Runtimes e Matriz de Capacidades ===\n\n" +
		targetBlock(t, "PI", "Pi Agent Harness", true, true, true, true, true, true) +
		targetBlock(t, "OPENCODE", "OpenCode Interpreter", true, true, true, true, true, true) +
		targetBlock(t, "OMP", "omp (oh my pi) Coding Agent", true, true, true, true, true, true) +
		targetBlock(t, "RAW", "Raw Model API / LLM Prompt", true, false, false, false, false, false)
	if stdout != want {
		t.Fatalf("stdout divergente\n--- got ---\n%q\n--- want ---\n%q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, quer vazio", stderr)
	}
}

func TestTargetMaterializePi(t *testing.T) {
	root := inTempDir(t)

	code, stdout, stderr := runCLI(t, "target", "materialize", "--target", "pi", "--out", "out")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	for _, fragment := range []string{
		"=== [pwn target materialize] Materializando artefatos para PI ===\n",
		"✓ Materialização concluída com sucesso em: out\n",
		"Arquivos Gerados:\n  + out/AGENTS.md\n",
		"\nNotas de Adaptação:\n  ! Gerado AGENTS.md para Pi\n",
	} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("stdout sem %q:\n%s", fragment, stdout)
		}
	}
	if strings.Contains(stdout, "Capacidades Não Suportadas") {
		t.Fatalf("stdout não deve listar capacidades para pi:\n%s", stdout)
	}
	generated, err := os.ReadFile(filepath.Join(root, "out", "AGENTS.md"))
	if err != nil {
		t.Fatalf("ler AGENTS.md: %v", err)
	}
	if !strings.Contains(string(generated), "## Protocolo de aceitação") {
		t.Fatalf("AGENTS.md sem o protocolo de aceitação:\n%s", generated)
	}
}

func TestTargetMaterializeWithContractContext(t *testing.T) {
	root := inTempDir(t)

	taskContract, err := contract.CreateDefaultContractV4("1.1", "0001", "Task de referência", contract.RiskL2, nil)
	if err != nil {
		t.Fatalf("criar contrato: %v", err)
	}
	contractJSON, err := json.Marshal(taskContract)
	if err != nil {
		t.Fatalf("serializar contrato: %v", err)
	}
	writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "ctr-1.1.json"), string(contractJSON))
	writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "plan.json"), `{
  "work_id": "0001",
  "title": "Work de referência",
  "components": [],
  "global_gates": [],
  "tasks": [
    {
      "id": "1.1",
      "title": "Task de referência",
      "requirement_id": "FR-1",
      "depends_on": [],
      "behavior": "b",
      "components": [],
      "files": [],
      "implementation_files": [],
      "test_files": [],
      "red": {"command": "bun test", "description": "falha"},
      "implementation_steps": [],
      "acceptance_criteria": [],
      "spec_reference": "SPEC-1",
      "contract_id": "ctr-1.1",
      "complexity": "low"
    }
  ]
}`)

	code, stdout, stderr := runCLI(t, "target", "materialize", "--target", "opencode", "--work", "0001", "--out", "out")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stdout, "✓ Escopo derivado de 1 contrato(s) do Work 0001 (risco L2).\n") {
		t.Fatalf("stdout sem o escopo derivado:\n%s", stdout)
	}
	generated, err := os.ReadFile(filepath.Join(root, "out", "AGENTS.md"))
	if err != nil {
		t.Fatalf("ler AGENTS.md: %v", err)
	}
	if !strings.Contains(string(generated), "## Escopo do contrato (V4 congelado)") {
		t.Fatalf("AGENTS.md sem a seção de escopo:\n%s", generated)
	}
	if !strings.Contains(string(generated), "RISK LEVEL: L2") {
		t.Fatalf("AGENTS.md sem o risco do contrato:\n%s", generated)
	}
}

func TestTargetMaterializeErrors(t *testing.T) {
	root := inTempDir(t)

	t.Run("target desconhecido", func(t *testing.T) {
		code, _, stderr := runCLI(t, "target", "materialize", "--target", "raw")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "Target desconhecido ou não suportado para materialização automática: raw") {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("work sem contrato", func(t *testing.T) {
		writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "notes.txt"), "nota")
		code, stdout, stderr := runCLI(t, "target", "materialize", "--target", "pi", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stdout, "=== [pwn target materialize] Materializando artefatos para PI ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.Contains(stderr, "✗ Não foi possível carregar contratos do Work 0001: plan.json não encontrado para o Work 0001") {
			t.Fatalf("stderr = %q", stderr)
		}
	})
}

func TestValidateWork(t *testing.T) {
	root := inTempDir(t)

	t.Run("work sem documento com schema", func(t *testing.T) {
		writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "notes.txt"), "nota")
		code, stdout, stderr := runCLI(t, "validate", "--work", "0001")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn validate] Validador de Documentos do Work 0001 ===\n\n" +
			"Nenhum documento com schema encontrado em .pwn/work/0001/.\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	t.Run("work com documento inválido", func(t *testing.T) {
		writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "prd.json"), `{"$schema":"../../schemas/prd.schema.json"}`)
		code, stdout, stderr := runCLI(t, "validate", "--work", "0001")
		if code != 1 {
			t.Fatalf("código = %d, quer 1 (stderr: %q)", code, stderr)
		}
		if !strings.Contains(stdout, "✗ .pwn/work/0001/prd.json — ERRO:") {
			t.Fatalf("stdout = %q", stdout)
		}
		if !strings.Contains(stdout, "\n=== RESUMO: 0/1 arquivos válidos, 1 erros ===\n") {
			t.Fatalf("stdout = %q", stdout)
		}
	})
}

func TestValidateWithoutWorkFallsBackToCore(t *testing.T) {
	inTempDir(t)

	code, stdout, stderr := runCLI(t, "validate")
	if code != 1 {
		t.Fatalf("código = %d, quer 1 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stdout, "=== [pwn validate] Validador de Documentos Normativos JSON ===\n\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "File not found: .specs/system.json") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "\n=== RESUMO: 0/4 arquivos válidos, 4 erros ===\n") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestValidateAllWorks(t *testing.T) {
	root := inTempDir(t)
	writeFile(t, filepath.Join(root, ".pwn", "work", "0001", "prd.json"), `{"$schema":"../../schemas/prd.schema.json"}`)

	code, stdout, stderr := runCLI(t, "validate")
	if code != 1 {
		t.Fatalf("código = %d, quer 1 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stdout, "=== [pwn validate] Validador de Documentos dos Works do projeto ===\n\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "\n=== RESUMO: 0/1 arquivos válidos, 1 erros ===\n") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestSelfCheckWithoutMutate(t *testing.T) {
	inTempDir(t)

	code, stdout, stderr := runCLI(t, "self-check")
	if code != 1 {
		t.Fatalf("código = %d, quer 1 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stdout, "=== [pwn self-check] Validador dos documentos normativos do framework ===\n\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "\n=== RESUMO: 0/4 arquivos válidos, 4 erros ===\n") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestSelfCheckMutateUsesLatestWork(t *testing.T) {
	root := inTempDir(t)
	writeFile(t, filepath.Join(root, ".pwn", "work", "0007", "notes.txt"), "nota")

	code, stdout, stderr := runCLI(t, "self-check", "--mutate")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stdout, "=== [pwn self-check --mutate] Mutation testing dos gates do harness ===\n\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "Baseline: baseline canônica (Work 0007") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "=== RESUMO: 4/5 mutações detectadas ===\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "Gates decorativos (mutação aceita como advisory): GATE-PRD-SPEC\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, quer vazio", stderr)
	}
}

func TestSelfCheckMutateExplicitMissingWork(t *testing.T) {
	inTempDir(t)

	code, stdout, stderr := runCLI(t, "self-check", "--mutate", "--work", "0099")
	if code != 1 {
		t.Fatalf("código = %d, quer 1", code)
	}
	if !strings.Contains(stdout, "=== [pwn self-check --mutate] Mutation testing dos gates do harness ===\n\n") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "Work 0099 não encontrado em .pwn/work/.\n") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestQueueLifecycle(t *testing.T) {
	root := inTempDir(t)

	t.Run("lista vazia", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "queue", "list")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn queue list] Fila de Revisão Humana (AFK) ===\n\n" +
			"Nenhuma tarefa pendente na fila de revisão queue/review/.\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	writeFile(t, filepath.Join(root, "queue", "review", "run-1.json"), `{
  "runId": "run-1",
  "workId": "0001",
  "taskId": "1.1",
  "title": "Task suspensa",
  "pausedAtStep": "audit green",
  "reason": "risco L4",
  "riskLevel": "L4",
  "createdAt": "2026-01-02T03:04:05.000Z",
  "status": "pending_review"
}`)

	t.Run("lista item pendente", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "queue", "list")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn queue list] Fila de Revisão Humana (AFK) ===\n\n" +
			"[PENDING_REVIEW] Run: run-1 | Work: 0001 | Task: 1.1\n" +
			"  Título: Task suspensa\n" +
			"  Motivo: risco L4 (Risco: L4)\n" +
			"  Pausado em: audit green | Criado em: 2026-01-02T03:04:05.000Z\n\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	t.Run("aprova item", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "queue", "approve", "run-1")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if stdout != "✓ Run run-1 aprovada com sucesso! O pipeline pode ser retomado.\n" {
			t.Fatalf("stdout = %q", stdout)
		}
		data, err := os.ReadFile(filepath.Join(root, "queue", "review", "run-1.json"))
		if err != nil {
			t.Fatalf("ler item: %v", err)
		}
		var item queue.Item
		if err := json.Unmarshal(data, &item); err != nil {
			t.Fatalf("decodificar item: %v", err)
		}
		if item.Status != queue.StatusApproved {
			t.Fatalf("status = %q, quer %q", item.Status, queue.StatusApproved)
		}
	})

	t.Run("run inexistente", func(t *testing.T) {
		code, _, stderr := runCLI(t, "queue", "reject", "run-2")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stderr != "Run run-2 não encontrada na fila de revisão.\n" {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("sem run-id", func(t *testing.T) {
		code, _, stderr := runCLI(t, "queue", "approve")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if stderr != "Uso: pwn queue approve <run-id>\n" {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("rejeita item", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "queue", "reject", "run-1")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if stdout != "✗ Run run-1 rejeitada. A execução foi cancelada.\n" {
			t.Fatalf("stdout = %q", stdout)
		}
	})
}

func TestMetricsList(t *testing.T) {
	root := inTempDir(t)

	t.Run("sem métricas", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "metrics", "list")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn metrics list] Telemetria e Consumo de Métricas ===\n\n" +
			"Nenhuma métrica registrada em .pwn/metrics.jsonl ainda.\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	writeFile(t, filepath.Join(root, ".pwn", "metrics.jsonl"),
		`{"timestamp":"2026-01-02T03:04:05.000Z","runId":"run-1","workId":"0001","taskId":"1.1","agentRole":"strong","model":"model-x","tokensInput":100,"tokensOutput":50,"costUSD":0.0123,"durationMs":45,"status":"success","attempts":1,"isolated":true}`+"\n")

	t.Run("lista métricas", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "metrics", "list")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn metrics list] Telemetria e Consumo de Métricas ===\n\n" +
			"[SUCCESS] Run: run-1 | Task: 1.1 | Role: strong (model-x)\n" +
			"  Tokens: 150 | Custo: $0.0123 | Duração: 45ms | Tentativas: 1 | Sandbox: sim\n\n" +
			"--------------------------------------------------------------------------------\n" +
			"Total de Execuções: 1\n" +
			"Consumo Total de Tokens: 150\n" +
			"Custo Total Estimado: $0.0123 USD\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})

	t.Run("otimização", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "metrics", "optimize")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		want := "=== [pwn metrics optimize] Sugestões Declarativas de Otimização de Routing ===\n\n" +
			"[Sugestão #1] Papel Atual: strong (model-x) -> Recomendado: cheap\n" +
			"  Motivo: 1 execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para papel 'cheap' com economia.\n" +
			"  Economia Estimada: 65%\n\n" +
			"NOTA: Nenhuma alteração de arquivo é feita automaticamente. As recomendações são apenas consultivas.\n"
		if stdout != want {
			t.Fatalf("stdout = %q, quer %q", stdout, want)
		}
	})
}

func TestMetricsOptimizeWithoutHistory(t *testing.T) {
	inTempDir(t)

	code, stdout, stderr := runCLI(t, "metrics", "optimize")
	if code != 0 {
		t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
	}
	want := "=== [pwn metrics optimize] Sugestões Declarativas de Otimização de Routing ===\n\n" +
		"Sem histórico de métricas suficiente para recomendar otimização de routing.\n" +
		"Rode tarefas com \"pwn work run\" primeiro; as sugestões aparecem quando houver execuções registradas.\n"
	if stdout != want {
		t.Fatalf("stdout = %q, quer %q", stdout, want)
	}
}
