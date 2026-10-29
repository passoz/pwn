package decider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/gitx"
)

const engineKeyEnv = "PWN_TEST_DECIDER_KEY"

type jevBody struct {
	Model string `json:"model"`
	State struct {
		Notice    string         `json:"notice"`
		Artifacts map[string]any `json:"artifacts"`
	} `json:"state"`
	Questions map[string]Question `json:"questions"`
}

func testPolicy() Policy {
	return Policy{
		Point:      PointApprove,
		Thresholds: map[string]any{"min": 0.8},
		Judge: func(answers map[string]Answer) Judgment {
			if noulValue(answers, "ok") > 0.8 {
				return Judgment{Outcome: OutcomeApprove, Reasons: []string{"ok"}}
			}
			return Judgment{Outcome: OutcomeReject, Reasons: []string{"não"}}
		},
	}
}

func testRequest() (Request, error) {
	return Request{
		State:     map[string]any{"artifact": "valor do repositório"},
		Questions: map[string]Question{"ok": {Type: QuestionNoul, Instructions: "está ok?", Criteria: NoulCriteria{True: "sim", False: "não"}}},
	}, nil
}

func TestDecideApprovesAndRecords(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "secret-value")
	var body jevBody
	var authorization string
	var questions int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("corpo inválido: %v", err)
		}
		questions++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"jev-test-1","answers":{"ok":{"type":"noul","noul":0.9}},"usage":{"input_tokens":7,"output_tokens":3}}`))
	}))
	defer server.Close()
	writeEnabled(t, repo, verifier, server.URL, engineKeyEnv, contract.RiskL3)

	result, err := Decide(DecideOptions{
		RootDir:      repo,
		WorkID:       "0001",
		TaskID:       "1.1",
		Policy:       testPolicy(),
		Request:      testRequest,
		VerifierRoot: verifier,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if result.Kind != ResultDecided || result.Record == nil {
		t.Fatalf("resultado = %+v", result)
	}
	record := result.Record
	if record.Outcome != OutcomeApprove || record.Model == nil || *record.Model != "jev-test-1" || record.Point != PointApprove {
		t.Fatalf("registro = %+v", record)
	}
	if record.StateSHA == nil || len(*record.StateSHA) != 64 {
		t.Fatalf("state_sha256 = %v", record.StateSHA)
	}
	if record.Usage == nil || record.Usage.InputTokens != 7 || record.Usage.OutputTokens != 3 {
		t.Fatalf("usage = %+v", record.Usage)
	}
	if !DecisionSignatureValid(*record, verifier) {
		t.Fatal("assinatura inválida")
	}
	if _, err := os.Stat(DecisionRepoCopy(repo, "0001", record.DecisionID)); err != nil {
		t.Fatalf("cópia no repositório: %v", err)
	}
	if got := DecisionReference(*record); got != "decider:jev-test-1#"+record.DecisionID {
		t.Fatalf("referência = %q", got)
	}

	if authorization != "Bearer secret-value" {
		t.Fatalf("authorization = %q", authorization)
	}
	if questions != 1 {
		t.Fatalf("chamadas = %d, quer 1", questions)
	}
	if body.Model != "jev-latest" {
		t.Fatalf("modelo enviado = %q", body.Model)
	}
	if !strings.Contains(body.State.Notice, "não instruções") {
		t.Fatalf("aviso de estado = %q", body.State.Notice)
	}
	if body.State.Artifacts["artifact"] != "valor do repositório" {
		t.Fatalf("artefatos = %#v", body.State.Artifacts)
	}
	if body.Questions["ok"].Type != QuestionNoul {
		t.Fatalf("perguntas enviadas = %#v", body.Questions)
	}
}

func TestDecideFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		status    int
		body      string
		contains  string
		buildCall bool
	}{
		{name: "sem chave", key: "", status: 200, body: `{"model":"m","answers":{"ok":{"type":"noul","noul":0.9}}}`, contains: "$" + engineKeyEnv + " não está definida"},
		{name: "HTTP de erro", key: "k", status: 500, body: `{"error":"boom"}`, contains: "Jev respondeu HTTP 500", buildCall: true},
		{name: "resposta fora do contrato", key: "k", status: 200, body: `{"model":"m","answers":{"ok":{"type":"noul","noul":1.5}}}`, contains: "noul fora de [0,1]", buildCall: true},
		{name: "resposta sem a pergunta", key: "k", status: 200, body: `{"model":"m","answers":{}}`, contains: "resposta sem 'ok'", buildCall: true},
		{name: "corpo que não é JSON", key: "k", status: 200, body: `not json`, contains: "corpo que não é JSON", buildCall: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			verifier := initVerifier(t)
			t.Setenv(OperatorEnv, "")
			t.Setenv(engineKeyEnv, test.key)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			writeEnabled(t, repo, verifier, server.URL, engineKeyEnv, contract.RiskL3)
			called := false
			result, err := Decide(DecideOptions{
				RootDir:      repo,
				WorkID:       "0001",
				TaskID:       "1.1",
				Policy:       testPolicy(),
				VerifierRoot: verifier,
				Request: func() (Request, error) {
					called = true
					return testRequest()
				},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if result.Kind != ResultDecided || result.Record == nil {
				t.Fatalf("resultado = %+v", result)
			}
			record := result.Record
			if record.Outcome != OutcomeEscalate || record.Model != nil {
				t.Fatalf("registro = %+v", record)
			}
			if len(record.Reasons) == 0 || !strings.Contains(record.Reasons[0], "decisor indisponível") || !strings.Contains(record.Reasons[0], test.contains) {
				t.Fatalf("motivos = %v, quer conter %q", record.Reasons, test.contains)
			}
			if !DecisionSignatureValid(*record, verifier) {
				t.Fatal("assinatura inválida")
			}
			if called != test.buildCall {
				t.Fatalf("request montado = %v, quer %v", called, test.buildCall)
			}
		})
	}
}

func TestDecideFailsClosedWithoutNetwork(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := server.URL
	server.Close()
	writeEnabled(t, repo, verifier, endpoint, engineKeyEnv, contract.RiskL3)
	result, err := Decide(DecideOptions{
		RootDir:      repo,
		WorkID:       "0001",
		TaskID:       "1.1",
		Policy:       testPolicy(),
		Request:      testRequest,
		VerifierRoot: verifier,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if result.Record == nil || result.Record.Outcome != OutcomeEscalate {
		t.Fatalf("resultado = %+v", result)
	}
	if !strings.Contains(strings.Join(result.Record.Reasons, " "), "chamada ao Jev falhou") {
		t.Fatalf("motivos = %v", result.Record.Reasons)
	}
}

func TestGovernanceHumanScopeAndRisk(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	writeEnabled(t, repo, verifier, "http://127.0.0.1:9/x", engineKeyEnv, contract.RiskL2)

	governed, err := Govern(repo, PointApprove, nil, verifier)
	if err != nil || governed.Config == nil {
		t.Fatalf("Govern = %+v, %v", governed, err)
	}
	risky := contract.RiskL3
	governed, err = Govern(repo, PointApprove, &risky, verifier)
	if err != nil {
		t.Fatalf("Govern: %v", err)
	}
	if governed.Config != nil || governed.Reason == nil || !strings.Contains(*governed.Reason, "acima do teto do decisor (L2)") {
		t.Fatalf("Govern risco = %+v", governed)
	}

	// Ponto fora do escopo gravado no projeto.
	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatal(err)
	}
	encoded["scope"] = []any{"queue"}
	data, err = json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	governed, err = Govern(repo, PointApprove, nil, verifier)
	if err != nil {
		t.Fatalf("Govern escopo: %v", err)
	}
	if governed.Config != nil || governed.Reason == nil || !strings.Contains(*governed.Reason, "fora do escopo") {
		t.Fatalf("Govern escopo = %+v", governed)
	}

	t.Setenv(OperatorEnv, string(OperatorHuman))
	governed, err = Govern(repo, PointApprove, nil, verifier)
	if err != nil || governed.Config != nil || governed.Reason != nil {
		t.Fatalf("Govern humano = %+v, %v", governed, err)
	}
	t.Setenv(OperatorEnv, "invalido")
	if _, err := Govern(repo, PointApprove, nil, verifier); err == nil || !strings.Contains(err.Error(), "PWN_OPERATOR inválido") {
		t.Fatalf("erro = %v", err)
	}
}

func TestOperatorHumanSkipsModel(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	t.Setenv(OperatorEnv, string(OperatorHuman))
	t.Setenv(engineKeyEnv, "k")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"model":"m","answers":{"ok":{"type":"noul","noul":1}}}`))
	}))
	defer server.Close()
	writeEnabled(t, repo, verifier, server.URL, engineKeyEnv, contract.RiskL3)
	requested := false
	result, err := Decide(DecideOptions{
		RootDir:      repo,
		WorkID:       "0001",
		TaskID:       "1.1",
		Policy:       testPolicy(),
		VerifierRoot: verifier,
		Request: func() (Request, error) {
			requested = true
			return testRequest()
		},
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if result.Kind != ResultHuman || result.Reason != nil {
		t.Fatalf("resultado = %+v", result)
	}
	if calls.Load() != 0 || requested {
		t.Fatalf("decisor chamado com operador humano (http=%d request=%v)", calls.Load(), requested)
	}
}

func TestOperatorDeciderWithoutConfigFails(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	t.Setenv(OperatorEnv, string(OperatorDecider))
	_, err := Govern(repo, PointApprove, nil, verifier)
	if err == nil || !strings.Contains(err.Error(), "não tem decisor configurado") {
		t.Fatalf("erro = %v", err)
	}
}

func TestProjectRootFindsRepository(t *testing.T) {
	repo := t.TempDir()
	runner := gitx.New(repo)
	if result, err := runner.Run(context.Background(), []string{"init", "-q"}, gitx.Options{}); err != nil || !result.OK() {
		t.Fatalf("git init: %v (%+v)", err, result)
	}
	nested := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectRoot(nested); got != repo {
		t.Fatalf("ProjectRoot = %q, quer %q", got, repo)
	}
	// Sem repositório Git o fallback preserva o diretório informado.
	isolated := t.TempDir()
	if got := ProjectRoot(isolated); got != isolated {
		t.Fatalf("ProjectRoot sem repositório = %q", got)
	}
}
