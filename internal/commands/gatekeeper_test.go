package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/batch"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/decider"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
)

// fakeJev responde ao ponto `queue`: nada destrutivo e task compatível.
func fakeJev(t *testing.T, destructive float64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Questions map[string]struct{ Type string } `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("corpo inválido: %v", err)
		}
		answers := map[string]any{}
		for id := range body.Questions {
			value := 0.97
			if id == "destructive" {
				value = destructive
			}
			answers[id] = map[string]any{"type": "noul", "noul": value}
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "fake-1.0",
			"answers": answers,
			"usage":   map[string]int{"input_tokens": 1, "output_tokens": 1},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func gatekeeperProject(t *testing.T, endpoint string) string {
	t.Helper()
	repo := t.TempDir()
	if output, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v (%s)", err, output)
	}
	root := filepath.Join(t.TempDir(), "verifier")
	t.Setenv(verify.HomeEnv, root)
	if _, err := verify.InitializeVerifierHome(root); err != nil {
		t.Fatalf("verifier home: %v", err)
	}
	if endpoint != "" {
		t.Setenv("PWN_TEST_DECIDER_KEY", "segredo")
		if _, err := decider.WriteConfig(repo, &decider.Input{
			Decider: "jev:fake", KeyEnv: "PWN_TEST_DECIDER_KEY", MaxRisk: "L4", Endpoint: &endpoint,
		}, root); err != nil {
			t.Fatalf("decider config: %v", err)
		}
	}
	return repo
}

// A fila L4 da run precisa chegar ao decisor do projeto: sem a ligação, toda task
// L4 vai para a fila humana mesmo com decisor configurado.
func TestGatekeeperConsultsProjectDecider(t *testing.T) {
	tests := []struct {
		name        string
		destructive float64
		want        run.GateOutcome
	}{
		{name: "aprova quando nada é destrutivo", destructive: 0.03, want: run.GateApprove},
		{name: "escala quando há efeito destrutivo", destructive: 0.97, want: run.GateEscalate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := fakeJev(t, test.destructive)
			repo := gatekeeperProject(t, server.URL)

			gate := deciderGatekeeper{}.Decide(run.GateRequest{
				RootDir:   repo,
				WorkID:    "0001",
				TaskID:    "WORK",
				Risk:      contract.RiskL4,
				Contracts: []contract.TaskContractV4{{}},
				Command:   []string{"go", "test", "./..."},
			})
			if gate.Err != nil {
				t.Fatalf("erro: %v", gate.Err)
			}
			if gate.Outcome != test.want {
				t.Fatalf("desfecho = %q, quer %q (log: %v)", gate.Outcome, test.want, gate.Log)
			}
			if gate.DecisionID == "" || len(gate.Log) == 0 || !strings.HasPrefix(gate.Log[0], "[DECISOR] ") {
				t.Fatalf("sem registro assinado: id=%q log=%v", gate.DecisionID, gate.Log)
			}
		})
	}
}

func TestGatekeeperWithoutDeciderLeavesDecisionToOperator(t *testing.T) {
	repo := gatekeeperProject(t, "")
	gate := deciderGatekeeper{}.Decide(run.GateRequest{
		RootDir: repo, WorkID: "0001", TaskID: "WORK", Risk: contract.RiskL4,
		Contracts: []contract.TaskContractV4{{}}, Command: []string{"go", "test"},
	})
	if gate.Err != nil || gate.Outcome != run.GateEscalate || gate.DecisionID != "" {
		t.Fatalf("sem decisor a task deve ir para o operador sem registro: %+v", gate)
	}
}

// O rebase automático só roda com decisor no projeto e só para retenção por base
// desatualizada ou colisão, depois que ao menos uma task foi integrada.
func TestAutoRebaseRequiresDeciderAndRebasableHold(t *testing.T) {
	held := []batch.HeldTask{
		{ID: "1.2", Kind: batch.HoldStaleBase, Reasons: []string{"base antiga"}},
		{ID: "1.3", Kind: batch.HoldRegression, Reasons: []string{"falhou"}},
	}
	integrated := []batch.IntegratedTask{{ID: "1.1"}}

	t.Run("sem decisor não faz nada", func(t *testing.T) {
		repo := gatekeeperProject(t, "")
		t.Chdir(repo)
		var stdout, stderr bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stderr: &stderr}
		runner.autoRebase(context.Background(), batch.IntegrationResult{WorkID: "0001", Integrated: integrated, Failed: held})
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("saída inesperada: %q %q", stdout.String(), stderr.String())
		}
	})

	t.Run("com decisor tenta só a task refazível", func(t *testing.T) {
		server := fakeJev(t, 0.03)
		repo := gatekeeperProject(t, server.URL)
		t.Chdir(repo)
		var stdout, stderr bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stderr: &stderr}
		runner.autoRebase(context.Background(), batch.IntegrationResult{WorkID: "0001", Integrated: integrated, Failed: held})
		if !strings.Contains(stdout.String(), "[DECISOR] tasks retidas só por base desatualizada") {
			t.Fatalf("stdout = %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "rebase automático de 1.2 falhou") || strings.Contains(stderr.String(), "1.3") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("sem task integrada não refaz", func(t *testing.T) {
		server := fakeJev(t, 0.03)
		repo := gatekeeperProject(t, server.URL)
		t.Chdir(repo)
		var stdout, stderr bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stderr: &stderr}
		runner.autoRebase(context.Background(), batch.IntegrationResult{WorkID: "0001", Failed: held})
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("saída inesperada: %q %q", stdout.String(), stderr.String())
		}
	})
}
