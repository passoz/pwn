package run

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/queue"
)

// writeWorkDoc grava um arquivo em .pwn/work/0001/ sem validar o conteúdo.
func writeWorkDoc(t *testing.T, root, name, content string) {
	t.Helper()
	writeFile(t, root, filepath.Join(".pwn", "work", "0001", name), content)
}

// requireNotRoot pula o teste quando permissões de arquivo não são aplicadas.
func requireNotRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignora permissões de arquivo")
	}
}

func assertContractError(t *testing.T, result Result, want string) {
	t.Helper()
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1 (stderr=%q)", result.Status, result.Stderr)
	}
	if !strings.HasPrefix(result.Stderr, "[CONTRACT ERROR] ") || !strings.Contains(result.Stderr, want) {
		t.Fatalf("stderr = %q, esperava [CONTRACT ERROR] com %q", result.Stderr, want)
	}
	if result.RunID == "" {
		t.Fatal("run sem id")
	}
	if result.DiffViolations == nil || len(result.DiffViolations) != 0 {
		t.Fatalf("diffViolations = %#v, esperava lista vazia não nula", result.DiffViolations)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	root := t.TempDir()
	result := Run(context.Background(), Options{WorkID: "0001", TaskID: "1.1", RootDir: root, Log: &bytes.Buffer{}})
	assertContractError(t, result, "comando de aceitação vazio")
}

func TestRunContractLoadingErrors(t *testing.T) {
	const planOne = `{"tasks":[{"id":"1.1","contract_id":"CTR-001"}]}`
	tests := []struct {
		name string
		plan string // vazio = sem plan.json
		ctr  string // vazio = sem contrato
		want string
		// workOnly pula o modo por task: o erro só existe no carregamento do Work.
		workOnly bool
		// taskOnly pula o modo por Work.
		taskOnly bool
	}{
		{name: "sem plan.json", want: "plan.json não encontrado"},
		{name: "plan.json não é JSON", plan: "{", want: "plan.json não encontrado"},
		{name: "plan.json sem lista de tasks", plan: `{"title":"t"}`, want: "plan.json não encontrado"},
		{
			name: "task fora do plano", plan: `{"tasks":[{"id":"9.9","contract_id":"CTR-001"}]}`,
			want: "Task 1.1 não encontrada no plano do Work 0001", taskOnly: true,
		},
		{
			name: "task sem contract_id", plan: `{"tasks":[{"id":"1.1"}]}`,
			want: "Task 1.1 não vincula contract_id",
		},
		{name: "contrato ausente", plan: planOne, want: "Contrato CTR-001 não encontrado em"},
		{name: "contrato não é JSON", plan: planOne, ctr: "{", want: "Erro ao ler o contrato CTR-001"},
		{name: "contrato com tipo errado", plan: planOne, ctr: "[1]", want: "Erro ao ler o contrato CTR-001"},
		{name: "contrato sem versão", plan: planOne, ctr: "{}", want: "contract_version: ausente"},
		{
			name: "contrato em outra versão", plan: planOne, ctr: `{"contract_version":"V3"}`,
			want: "não é V4 (contract_version: V3)",
		},
	}
	for _, test := range tests {
		modes := []struct {
			name   string
			taskID string
			skip   bool
		}{
			{name: "por task", taskID: "1.1", skip: test.workOnly},
			{name: "por work", taskID: "", skip: test.taskOnly},
		}
		for _, mode := range modes {
			if mode.skip {
				continue
			}
			t.Run(test.name+"/"+mode.name, func(t *testing.T) {
				root := t.TempDir()
				if test.plan != "" {
					writeWorkDoc(t, root, "plan.json", test.plan)
				}
				if test.ctr != "" {
					writeWorkDoc(t, root, "CTR-001.json", test.ctr)
				}
				options := baseOptions(root, "echo", "hi")
				options.TaskID = mode.taskID
				options.Log = &bytes.Buffer{}
				assertContractError(t, Run(context.Background(), options), test.want)
			})
		}
	}
}

func TestLoadWorkContractsPropagatesBrokenTaskContract(t *testing.T) {
	root := t.TempDir()
	writeWorkDoc(t, root, "plan.json", `{"tasks":[{"id":"1.1","contract_id":"CTR-001"},{"id":"1.2","contract_id":"CTR-002"}]}`)
	good := testContract(t, contract.RiskL1, []string{"src/**"}, nil)
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	writeWorkDoc(t, root, "CTR-001.json", string(data))
	writeWorkDoc(t, root, "CTR-002.json", "{")

	contracts, documents, err := loadWorkContractsWithDocuments("0001", root)
	if err == nil || !strings.Contains(err.Error(), "Erro ao ler o contrato CTR-002") {
		t.Fatalf("erro = %v, esperava falha do segundo contrato", err)
	}
	if contracts != nil || documents != nil {
		t.Fatalf("falha parcial devolveu dados: %v %v", contracts, documents)
	}

	writeWorkDoc(t, root, "CTR-002.json", string(data))
	contracts, documents, err = loadWorkContractsWithDocuments("0001", root)
	if err != nil || len(contracts) != 2 || len(documents) != 2 {
		t.Fatalf("carregamento do Work = %d contratos, %d documentos, err=%v", len(contracts), len(documents), err)
	}
}

func TestContractBindingFailsOnUnserializableDocument(t *testing.T) {
	_, err := contractBinding([]any{make(chan int)}, []string{"sh", "x.sh"})
	if err == nil || !strings.Contains(err.Error(), "vínculo L4") {
		t.Fatalf("erro = %v, esperava falha de serialização do vínculo", err)
	}
}

func TestRunDefaultsRootDirLogTaskAndContext(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "ok.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh ok.sh", contract.RiskL2, []string{"allowed.txt"}, []string{})
	t.Chdir(root)

	var ctx context.Context // nil: Run deve tratar como Background
	result := Run(ctx, Options{WorkID: "0001", Command: []string{"sh", "ok.sh"}, Timeout: 10 * time.Second})
	if result.Status != 0 {
		t.Fatalf("status = %d, stderr=%s", result.Status, result.Stderr)
	}
	if len(result.DiffViolations) != 0 {
		t.Fatalf("violações inesperadas: %v", result.DiffViolations)
	}
	entries, err := metrics.Read(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("métricas = %+v (%v)", entries, err)
	}
	if entries[0].TaskID != "WORK" || entries[0].Status != metrics.StatusSuccess || entries[0].RunID != result.RunID {
		t.Fatalf("métrica inesperada: %+v", entries[0])
	}
	assertSandboxesEmpty(t, root)
}

func TestRunL4GatekeeperFailureAndEscalation(t *testing.T) {
	t.Run("erro do decisor interrompe a run sem enfileirar", func(t *testing.T) {
		root := t.TempDir()
		writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})
		gate := &captureGatekeeper{decision: GateDecision{Err: os.ErrInvalid, Log: []string{"não deve aparecer"}}}
		var log bytes.Buffer
		options := baseOptions(root, "sh", "write.sh")
		options.Gatekeeper = gate
		options.Log = &log

		result := Run(context.Background(), options)
		if result.Status != 1 || result.Stderr != os.ErrInvalid.Error() || result.Suspended {
			t.Fatalf("resultado = %+v", result)
		}
		if strings.Contains(log.String(), "não deve aparecer") {
			t.Fatalf("log do decisor escrito apesar do erro: %q", log.String())
		}
		items, err := queue.List(root)
		if err != nil || len(items) != 0 {
			t.Fatalf("fila = %+v (%v), esperava vazia", items, err)
		}
	})

	t.Run("escalação suspende com motivos, decisão e log", func(t *testing.T) {
		root := t.TempDir()
		writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})
		gate := &captureGatekeeper{decision: GateDecision{
			Outcome:    GateEscalate,
			Reasons:    []string{"risco alto", "comando novo"},
			DecisionID: "DEC-9",
			Log:        []string{"decisor: escalando", "decisor: confiança 0.4"},
		}}
		var log bytes.Buffer
		options := baseOptions(root, "sh", "write.sh")
		options.Gatekeeper = gate
		options.Log = &log

		result := Run(context.Background(), options)
		if !result.Suspended || result.Status != ExitSuspended {
			t.Fatalf("resultado = %+v, esperava suspensão", result)
		}
		for _, want := range []string{"decisor: escalando\n", "decisor: confiança 0.4\n", "suspensa", "pwn queue approve " + result.RunID} {
			if !strings.Contains(log.String(), want) {
				t.Fatalf("log sem %q: %q", want, log.String())
			}
		}
		items, err := queue.List(root)
		if err != nil || len(items) != 1 {
			t.Fatalf("fila = %+v (%v)", items, err)
		}
		item := items[0]
		if item.Status != queue.StatusPendingReview || item.RunID != result.RunID {
			t.Fatalf("item inesperado: %+v", item)
		}
		if item.Reason != "Tarefa de risco L4: risco alto; comando novo" {
			t.Fatalf("motivo = %q", item.Reason)
		}
		if item.Payload["decision_id"] != "DEC-9" {
			t.Fatalf("decision_id = %v", item.Payload["decision_id"])
		}
		if got, _ := item.Payload["command"].([]any); len(got) != 2 || got[0] != "sh" || got[1] != "write.sh" {
			t.Fatalf("comando no payload = %v", item.Payload["command"])
		}
	})

	t.Run("decisor sem motivos usa o motivo padrão e decision_id nulo", func(t *testing.T) {
		root := t.TempDir()
		writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})
		options := baseOptions(root, "sh", "write.sh")
		options.Gatekeeper = &captureGatekeeper{decision: GateDecision{Outcome: GateEscalate}}
		options.Log = &bytes.Buffer{}

		result := Run(context.Background(), options)
		if !result.Suspended {
			t.Fatalf("resultado = %+v", result)
		}
		items, err := queue.List(root)
		if err != nil || len(items) != 1 {
			t.Fatalf("fila = %+v (%v)", items, err)
		}
		if items[0].Reason != "Tarefa de risco L4 exige aprovação humana na fila AFK" {
			t.Fatalf("motivo = %q", items[0].Reason)
		}
		if value, present := items[0].Payload["decision_id"]; !present || value != nil {
			t.Fatalf("decision_id = %v (presente=%t), esperava null", value, present)
		}
	})
}

func TestRunL4QueueFailureIsReported(t *testing.T) {
	tests := []struct {
		name string
		gate Gatekeeper
	}{
		{name: "sem decisor", gate: nil},
		{name: "decisor aprova", gate: &captureGatekeeper{decision: GateDecision{Outcome: GateApprove}}},
		{name: "decisor rejeita", gate: &captureGatekeeper{decision: GateDecision{Outcome: GateReject, Reasons: []string{"não"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})
			// "queue" como arquivo regular impede criar queue/review.
			writeFile(t, root, "queue", "bloqueio")
			var log bytes.Buffer
			options := baseOptions(root, "sh", "write.sh")
			options.Gatekeeper = test.gate
			options.Log = &log

			result := Run(context.Background(), options)
			if result.Status != 1 || !strings.HasPrefix(result.Stderr, "[QUEUE ERROR]") || result.Suspended {
				t.Fatalf("resultado = %+v", result)
			}
			if !strings.Contains(log.String(), "[QUEUE ERROR]") {
				t.Fatalf("falha da consulta à fila não foi registrada no log: %q", log.String())
			}
			if _, err := os.Stat(filepath.Join(root, ".pwn", "sandboxes")); !os.IsNotExist(err) {
				t.Fatal("falha de fila não pode criar sandbox")
			}
		})
	}
}

func TestRunUsesPolicyFileInsteadOfAcceptanceAllowlist(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL2, []string{"allowed.txt"}, []string{})
	writeFile(t, root, ".pwn/policy.json", `{"shell":{"allowed_commands":[{"command":"echo"}],"denied_commands":[],"allow_all_shell":false}}`)

	// O comando de aceitação do contrato deixa de ser permitido: a política
	// declarada substitui a derivada do contrato.
	denied := Run(context.Background(), baseOptions(root, "sh", "write.sh"))
	if denied.Status != 1 || !strings.Contains(strings.ToLower(denied.Stderr), "allowlist") {
		t.Fatalf("política declarada não negou sh: %+v", denied)
	}

	allowed := Run(context.Background(), baseOptions(root, "echo", "hi"))
	if allowed.Status != 0 || strings.TrimSpace(allowed.Stdout) != "hi" {
		t.Fatalf("política declarada não permitiu echo: %+v", allowed)
	}
	assertSandboxesEmpty(t, root)
}

func TestRunWithoutIsolationTimeoutAndExitStatus(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "slow.sh", "sleep 5\n")
	writeFile(t, root, "fail.sh", "echo erro >&2\nexit 7\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh slow.sh", contract.RiskL2, []string{}, []string{})
	// A política declarada libera qualquer argumento de sh para os dois comandos.
	writeFile(t, root, ".pwn/policy.json", `{"shell":{"allowed_commands":[{"command":"sh"}],"denied_commands":[],"allow_all_shell":false}}`)

	slow := baseOptions(root, "sh", "slow.sh")
	slow.Isolated = new(false)
	slow.Timeout = 200 * time.Millisecond
	started := time.Now()
	timedOut := Run(context.Background(), slow)
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("timeout demorou %s", elapsed)
	}
	if timedOut.Status != 1 {
		t.Fatalf("status do timeout = %d, esperava 1", timedOut.Status)
	}

	failing := baseOptions(root, "sh", "fail.sh")
	failing.Isolated = new(false)
	failed := Run(context.Background(), failing)
	if failed.Status != 7 || !strings.Contains(failed.Stderr, "erro") {
		t.Fatalf("resultado = %+v, esperava status 7 com stderr", failed)
	}

	entries, err := metrics.Read(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("métricas = %+v (%v)", entries, err)
	}
	for _, entry := range entries {
		if entry.Isolated || entry.Status != metrics.StatusFailed {
			t.Fatalf("métrica inesperada: %+v", entry)
		}
	}
}

func TestRunSandboxPreparationFailureAbortsAndCleansUp(t *testing.T) {
	requireNotRoot(t)
	root := newRepo(t)
	writeFile(t, root, "seed.sh", "exit 0\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh seed.sh", contract.RiskL2, []string{}, []string{})
	// bunfig.toml ilegível: PrepareSandbox não consegue copiá-lo.
	writeFile(t, root, "bunfig.toml", "[test]\n")
	if err := os.Chmod(filepath.Join(root, "bunfig.toml"), 0); err != nil {
		t.Fatal(err)
	}

	result := Run(context.Background(), baseOptions(root, "sh", "seed.sh"))
	if result.Status != 1 || !strings.Contains(result.Stderr, "[SANDBOX ABORT]") || !strings.Contains(result.Stderr, "bunfig.toml") {
		t.Fatalf("resultado = %+v", result)
	}
	assertSandboxesEmpty(t, root)
	entries, err := metrics.Read(root)
	if err != nil || len(entries) != 1 || entries[0].Status != metrics.StatusFailed {
		t.Fatalf("métricas = %+v (%v)", entries, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", result.RunID+".jsonl")); err != nil {
		t.Fatalf("eventos da run abortada não foram gravados: %v", err)
	}
}

func TestRunOverlayFailureAbortsAndCleansUp(t *testing.T) {
	requireNotRoot(t)
	root := newRepo(t)
	writeFile(t, root, "seed.sh", "exit 0\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh seed.sh", contract.RiskL2, []string{}, []string{})
	// Arquivo novo ilegível: o overlay da working tree não consegue copiá-lo.
	writeFile(t, root, "novo-ilegivel.txt", "x")
	if err := os.Chmod(filepath.Join(root, "novo-ilegivel.txt"), 0); err != nil {
		t.Fatal(err)
	}

	result := Run(context.Background(), baseOptions(root, "sh", "seed.sh"))
	if result.Status != 1 || !strings.Contains(result.Stderr, "[SANDBOX ABORT]") || !strings.Contains(result.Stderr, "novo-ilegivel.txt") {
		t.Fatalf("resultado = %+v", result)
	}
	assertSandboxesEmpty(t, root)
}

func TestBuildShellPolicyParsesAcceptanceCommands(t *testing.T) {
	shell := buildShellPolicy([]string{
		"go test ./...",
		"  sh 'script com espaço.sh'  ",
		"sh 'aspas abertas",
		"   ",
	})
	if shell.AllowAllShell {
		t.Fatal("política derivada não pode liberar todo o shell")
	}
	if len(shell.DeniedCommands) == 0 {
		t.Fatal("política derivada perdeu a denylist default")
	}
	type rule struct {
		command string
		args    []string
	}
	var got []rule
	for _, allowed := range shell.AllowedCommands {
		got = append(got, rule{allowed.Command, allowed.Args})
	}
	want := []rule{
		{"go", []string{"test", "./..."}},
		{"sh", []string{"script com espaço.sh"}},
		// Aspas desbalanceadas caem para a divisão por espaços.
		{"sh", []string{"'aspas", "abertas"}},
	}
	if len(got) != len(want) {
		t.Fatalf("regras = %+v, esperava %+v", got, want)
	}
	for index := range want {
		if got[index].command != want[index].command || !slices.Equal(got[index].args, want[index].args) {
			t.Fatalf("regra %d = %+v, esperava %+v", index, got[index], want[index])
		}
	}
}

func TestRecordMetricsAndEventsFailuresAreLoggedNotFatal(t *testing.T) {
	root := t.TempDir()
	// ".pwn" como arquivo impede métricas e eventos.
	writeFile(t, root, ".pwn", "bloqueio")

	var log bytes.Buffer
	recordMetrics(metrics.Entry{RunID: "RUN-x", Status: metrics.StatusFailed}, root, &log)
	if !strings.Contains(log.String(), "[METRICS ERROR]") {
		t.Fatalf("falha de métricas não registrada: %q", log.String())
	}

	log.Reset()
	saveEventsQuietly(&RunContext{RunID: "RUN-x"}, root, &log)
	if !strings.Contains(log.String(), "[EVENTS ERROR]") {
		t.Fatalf("falha de eventos não registrada: %q", log.String())
	}

	// Sem writer de log a falha é silenciosa e não derruba a run.
	recordMetrics(metrics.Entry{RunID: "RUN-y", Status: metrics.StatusFailed}, root, nil)
	saveEventsQuietly(&RunContext{RunID: "RUN-y"}, root, nil)
}

func TestNewRunIDIsUniqueAndPrefixed(t *testing.T) {
	seen := make(map[string]struct{})
	for range 50 {
		id := newRunID()
		if !strings.HasPrefix(id, "RUN-") || strings.Count(id, "-") != 2 {
			t.Fatalf("id fora do formato RUN-<tempo>-<hex>: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("id repetido: %q", id)
		}
		seen[id] = struct{}{}
	}
}
