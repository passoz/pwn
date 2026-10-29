package decider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
)

func noul(value float64) Answer { return Answer{Type: QuestionNoul, Noul: &value} }
func choice(value string, confidence float64) Answer {
	return Answer{Type: QuestionChoice, Choice: value, Confidence: &confidence, Probabilities: map[string]float64{value: confidence}}
}
func score(value float64) Answer {
	return Answer{Type: QuestionScore, Score: &value, Confidence: new(0.9), Probabilities: map[string]float64{"2": 1}}
}

func approvalAnswers(overrides map[string]Answer) map[string]Answer {
	answers := map[string]Answer{
		"covers_behavior":            noul(0.95),
		"passes_without_requirement": noul(0.05),
		"specificity":                score(2.6),
		"scope":                      choice("adequate", 0.85),
	}
	for id, answer := range overrides {
		answers[id] = answer
	}
	return answers
}

func TestTaskApprovalPolicy(t *testing.T) {
	tests := []struct {
		name     string
		answers  map[string]Answer
		want     Outcome
		contains string
	}{
		{name: "todos os limiares", answers: approvalAnswers(nil), want: OutcomeApprove},
		{name: "cobertura exatamente no mínimo escala", answers: approvalAnswers(map[string]Answer{"covers_behavior": noul(0.8)}), want: OutcomeEscalate, contains: "cobertura do comportamento"},
		{name: "cobertura acima do mínimo aprova", answers: approvalAnswers(map[string]Answer{"covers_behavior": noul(0.81)}), want: OutcomeApprove},
		{name: "especificidade baixa escala", answers: approvalAnswers(map[string]Answer{"specificity": score(1.9)}), want: OutcomeEscalate, contains: "especificidade"},
		{name: "escopo com confiança baixa escala", answers: approvalAnswers(map[string]Answer{"scope": choice("adequate", 0.6)}), want: OutcomeEscalate, contains: "escopo adequate"},
		{name: "escopo amplo escala", answers: approvalAnswers(map[string]Answer{"scope": choice("too_broad", 0.95)}), want: OutcomeEscalate, contains: "escopo too_broad"},
		{name: "teste que passa sem requisito rejeita", answers: approvalAnswers(map[string]Answer{"passes_without_requirement": noul(0.9)}), want: OutcomeReject, contains: "ignora o requisito"},
		{name: "cobertura muito baixa rejeita", answers: approvalAnswers(map[string]Answer{"covers_behavior": noul(0.1)}), want: OutcomeReject, contains: "não verificam o comportamento"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			judgment := TaskApprovalPolicy.Judge(test.answers)
			if judgment.Outcome != test.want {
				t.Fatalf("outcome = %s, quer %s (motivos: %v)", judgment.Outcome, test.want, judgment.Reasons)
			}
			if test.contains != "" && !strings.Contains(strings.Join(judgment.Reasons, " "), test.contains) {
				t.Fatalf("motivos = %v, quer conter %q", judgment.Reasons, test.contains)
			}
		})
	}
}

func TestQueuePolicy(t *testing.T) {
	tests := []struct {
		name        string
		destructive float64
		matches     float64
		want        Outcome
		contains    string
	}{
		{name: "comando não corresponde rejeita", destructive: 0.01, matches: 0.1, want: OutcomeReject, contains: "não corresponde"},
		{name: "efeito destrutivo escala", destructive: 0.5, matches: 0.99, want: OutcomeEscalate, contains: "efeito destrutivo possível"},
		{name: "incerto escala", destructive: 0.05, matches: 0.8, want: OutcomeEscalate, contains: "incerto"},
		{name: "seguro aprova", destructive: 0.05, matches: 0.9, want: OutcomeApprove},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			judgment := QueuePolicy.Judge(map[string]Answer{"destructive": noul(test.destructive), "matches_task": noul(test.matches)})
			if judgment.Outcome != test.want {
				t.Fatalf("outcome = %s, quer %s (%v)", judgment.Outcome, test.want, judgment.Reasons)
			}
			if test.contains != "" && !strings.Contains(strings.Join(judgment.Reasons, " "), test.contains) {
				t.Fatalf("motivos = %v, quer conter %q", judgment.Reasons, test.contains)
			}
		})
	}
}

func TestRiskRaises(t *testing.T) {
	tasks := []RiskTask{
		{ID: "1.1", Deterministic: contract.RiskL2},
		{ID: "1.2", Deterministic: contract.RiskL3},
		{ID: "1.3", Deterministic: contract.RiskL1},
		{ID: "1.4", Deterministic: contract.RiskL1},
	}
	raises := RiskRaises(map[string]Answer{
		"risk:1.1": choice("L3", 0.9),
		"risk:1.2": choice("L1", 0.99),
		"risk:1.3": choice("L3", 0.5),
		"risk:1.4": choice("L4", 0.99),
	}, tasks)
	if len(raises) != 1 {
		t.Fatalf("elevações = %+v", raises)
	}
	want := RiskRaise{TaskID: "1.1", From: contract.RiskL2, To: contract.RiskL3, Confidence: 0.9}
	if raises[0] != want {
		t.Fatalf("elevação = %+v, quer %+v", raises[0], want)
	}

	judgment := RiskPolicy(tasks).Judge(map[string]Answer{"risk:1.1": choice("L3", 0.9)})
	if judgment.Outcome != OutcomeApprove || judgment.Action == nil || *judgment.Action != "1.1:L2→L3" {
		t.Fatalf("decisão de risco = %+v", judgment)
	}
	none := RiskPolicy(tasks).Judge(map[string]Answer{})
	if none.Action != nil || len(none.Reasons) != 1 || none.Reasons[0] != "nenhuma elevação: risco determinístico mantido" {
		t.Fatalf("decisão sem elevação = %+v", none)
	}
}

func TestRiskRequestProjectsDeterministicOut(t *testing.T) {
	request := RiskRequest([]RiskTask{{ID: "1.1", Title: "t", Description: "d", Files: []string{"a.go"}, Deterministic: contract.RiskL2}})
	tasks, ok := request.State["tasks"].([]map[string]any)
	if !ok || len(tasks) != 1 {
		t.Fatalf("estado = %#v", request.State["tasks"])
	}
	if _, present := tasks[0]["deterministic"]; present {
		t.Fatal("risco determinístico vazou para o estado")
	}
	if _, present := request.Questions["risk:1.1"]; !present {
		t.Fatalf("perguntas = %v", request.Questions)
	}
}

// approvalFixture cria um Work com plano, contrato V4 e teste congelado.
func approvalFixture(t *testing.T) (string, *plan.Plan, *contract.TaskContractV4) {
	t.Helper()
	repo := t.TempDir()
	workDir := filepath.Join(repo, ".pwn", "work", "0001")
	testDir := filepath.Join(repo, "tests")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	task := plan.PlanTask{
		ID:                  "1.1",
		Title:               "Entrega a",
		RequirementID:       "FR-001",
		Behavior:            "a passa a valer 2.",
		ImplementationFiles: []string{"src/a.js"},
		AcceptanceCriteria:  []plan.PlanAC{{Command: "go test", Description: "a vale 2"}},
		ContractID:          "CTR-001",
	}
	workPlan := &plan.Plan{WorkID: "0001", Title: "Decisor", Tasks: []plan.PlanTask{task}}
	data, err := json.Marshal(workPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "plan.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	const acceptance = "test('a vale 2', () => expect(a).toBe(2));\n"
	if err := os.WriteFile(filepath.Join(testDir, "a.acceptance.test.js"), []byte(acceptance), 0o644); err != nil {
		t.Fatal(err)
	}
	taskContract, err := contract.CreateDefaultContractV4("1.1", "0001", "Entrega a", contract.RiskL3, nil)
	if err != nil {
		t.Fatal(err)
	}
	taskContract.ScopeContract.WriteAllow = []string{"src/a.js", "tests/a.test.js"}
	taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{Path: "tests/a.acceptance.test.js", SHA256: "x"}}
	encoded, err := json.Marshal(taskContract)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "CTR-001.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return repo, workPlan, &taskContract
}

func TestTaskApprovalRequest(t *testing.T) {
	repo, _, _ := approvalFixture(t)
	request, err := TaskApprovalRequest(repo, "0001", "1.1")
	if err != nil {
		t.Fatalf("TaskApprovalRequest: %v", err)
	}
	if request.State["requirement_id"] != "FR-001" {
		t.Fatalf("requirement_id = %v", request.State["requirement_id"])
	}
	frozen, ok := request.State["frozen_tests"].([]map[string]any)
	if !ok || len(frozen) != 1 || !strings.Contains(frozen[0]["content"].(string), "a vale 2") {
		t.Fatalf("frozen_tests = %#v", request.State["frozen_tests"])
	}
	if request.State["write_allow"] == nil || request.State["write_deny"] == nil {
		t.Fatalf("escopo ausente: %#v", request.State)
	}
	for _, id := range []string{"covers_behavior", "passes_without_requirement", "specificity", "scope"} {
		if _, present := request.Questions[id]; !present {
			t.Fatalf("pergunta %s ausente", id)
		}
	}

	// As respostas da política atravessam a validação do contrato.
	answers := approvalAnswers(nil)
	body := map[string]any{"model": "jev-test-1", "answers": answers}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ValidateResponse(request, encoded)
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if judgment := TaskApprovalPolicy.Judge(response.Answers); judgment.Outcome != OutcomeApprove {
		t.Fatalf("outcome = %s (%v)", judgment.Outcome, judgment.Reasons)
	}
}

func TestTaskApprovalRequestRejectsMissingFrozenTests(t *testing.T) {
	repo, _, _ := approvalFixture(t)
	path := filepath.Join(repo, ".pwn", "work", "0001", "CTR-001.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var taskContract contract.TaskContractV4
	if err := json.Unmarshal(data, &taskContract); err != nil {
		t.Fatal(err)
	}
	taskContract.AcceptanceContract.FrozenTests = nil
	data, err = json.Marshal(taskContract)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskApprovalRequest(repo, "0001", "1.1"); err == nil || !strings.Contains(err.Error(), "testes de aceitação congelados") {
		t.Fatalf("erro = %v", err)
	}
	if _, err := TaskApprovalRequest(repo, "0001", "9.9"); err == nil || !strings.Contains(err.Error(), "não encontrada") {
		t.Fatalf("erro para task ausente = %v", err)
	}
}

func TestGlobalApprovalRequest(t *testing.T) {
	repo := t.TempDir()
	markdown := "## Global gates\n\n- [ ] `go test ./...` — todos os testes passam\n- [ ] `go vet ./...` — sem avisos\n"
	if err := os.MkdirAll(filepath.Join(repo, ".todo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".todo", "0001-tasks.md"), []byte(markdown), 0o644); err != nil {
		t.Fatal(err)
	}
	request, err := GlobalApprovalRequest(repo, "0001", "G-2")
	if err != nil {
		t.Fatalf("GlobalApprovalRequest: %v", err)
	}
	gate, ok := request.State["gate"].(map[string]any)
	if !ok || gate["id"] != "G-2" || gate["command"] != "go vet ./..." || !strings.Contains(gate["text"].(string), "sem avisos") {
		t.Fatalf("gate = %#v", request.State["gate"])
	}
	if _, err := GlobalApprovalRequest(repo, "0001", "G-9"); err == nil {
		t.Fatal("gate inexistente aceito")
	}
	if judgment := GlobalApprovalPolicy.Judge(map[string]Answer{"verifies_gate": noul(0.1)}); judgment.Outcome != OutcomeReject {
		t.Fatalf("outcome = %s", judgment.Outcome)
	}
	if judgment := GlobalApprovalPolicy.Judge(map[string]Answer{"verifies_gate": noul(0.9)}); judgment.Outcome != OutcomeApprove {
		t.Fatalf("outcome = %s", judgment.Outcome)
	}
	if judgment := GlobalApprovalPolicy.Judge(map[string]Answer{"verifies_gate": noul(0.5)}); judgment.Outcome != OutcomeEscalate {
		t.Fatalf("outcome = %s", judgment.Outcome)
	}
}
