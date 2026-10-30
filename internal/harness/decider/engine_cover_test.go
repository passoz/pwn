package decider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/verify"
)

const fakeProvider = "fake"

// enableWithProvider grava uma configuração habilitada e troca o decisor para
// provider:model, direto no arquivo (ValidateInput só aceita provedores reais).
func enableWithProvider(t *testing.T, repo, verifier, provider string) {
	t.Helper()
	writeEnabled(t, repo, verifier, "http://127.0.0.1:9/x", engineKeyEnv, contract.RiskL3)
	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(data), "jev:jev-latest", provider+":m", 1)
	if patched == string(data) {
		t.Fatal("decisor não substituído na configuração")
	}
	if err := os.WriteFile(file, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
}

func registerAdapter(t *testing.T, adapter Adapter) {
	t.Helper()
	Adapters[fakeProvider] = adapter
	t.Cleanup(func() { delete(Adapters, fakeProvider) })
}

func decideOptions(repo, verifier string, request func() (Request, error)) DecideOptions {
	return DecideOptions{
		RootDir:      repo,
		WorkID:       "0001",
		TaskID:       "1.1",
		Policy:       testPolicy(),
		Request:      request,
		VerifierRoot: verifier,
	}
}

func approvingAdapter(t *testing.T) Adapter {
	t.Helper()
	return func(_ context.Context, connection Connection, _ Request) (Response, error) {
		if connection.Model != "m" || connection.Key != "k" {
			t.Errorf("conexão = %+v", connection)
		}
		return Response{Model: "fake-1", Answers: map[string]Answer{"ok": {Type: QuestionNoul, Noul: new(0.95)}}}, nil
	}
}

func badStateRequest() (Request, error) {
	return Request{State: map[string]any{"canal": make(chan int)}, Questions: map[string]Question{}}, nil
}

func blockDecisions(t *testing.T, verifier string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(verifier, "decisions"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDecideUsesRegisteredAdapter(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	registerAdapter(t, approvingAdapter(t))
	enableWithProvider(t, repo, verifier, fakeProvider)
	result, err := Decide(decideOptions(repo, verifier, testRequest))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	record := result.Record
	if record == nil || record.Outcome != OutcomeApprove || *record.Model != "fake-1" {
		t.Fatalf("registro = %+v", record)
	}
	lines := DescribeDecision(*record)
	if len(lines) != 2 || !strings.Contains(lines[0], "APROVADO — fake-1") || lines[1] != "  · ok" {
		t.Fatalf("linhas = %q", lines)
	}
}

func TestDecideUnknownProviderEscalates(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	enableWithProvider(t, repo, verifier, "ghost")
	called := false
	result, err := Decide(decideOptions(repo, verifier, func() (Request, error) { called = true; return testRequest() }))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if called {
		t.Error("request não deve ser montado sem adaptador")
	}
	if result.Record == nil || result.Record.Outcome != OutcomeEscalate ||
		!strings.Contains(result.Record.Reasons[0], "provedor sem adaptador: ghost:m") {
		t.Fatalf("registro = %+v", result.Record)
	}
}

func TestDecidePropagatesRequestAndAdapterErrors(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	enableWithProvider(t, repo, verifier, fakeProvider)

	registerAdapter(t, approvingAdapter(t))
	boom := errors.New("falha ao montar")
	if _, err := Decide(decideOptions(repo, verifier, func() (Request, error) { return Request{}, boom })); !errors.Is(err, boom) {
		t.Errorf("erro do Request deve propagar: %v", err)
	}

	hard := errors.New("erro fatal do adaptador")
	registerAdapter(t, func(context.Context, Connection, Request) (Response, error) { return Response{}, hard })
	result, err := Decide(decideOptions(repo, verifier, testRequest))
	if !errors.Is(err, hard) || result.Record != nil {
		t.Errorf("erro não-indisponibilidade deve propagar sem registro: %v %+v", err, result)
	}

	registerAdapter(t, func(context.Context, Connection, Request) (Response, error) {
		return Response{}, unavailablef("fora do ar")
	})
	result, err = Decide(decideOptions(repo, verifier, testRequest))
	if err != nil || result.Record == nil || result.Record.Outcome != OutcomeEscalate ||
		result.Record.Reasons[0] != "decisor indisponível: fora do ar" {
		t.Errorf("indisponibilidade: %v %+v", err, result.Record)
	}
}

func TestDecideStateDigestErrors(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	enableWithProvider(t, repo, verifier, fakeProvider)

	registerAdapter(t, approvingAdapter(t))
	if _, err := Decide(decideOptions(repo, verifier, badStateRequest)); err == nil || !strings.Contains(err.Error(), "serializar o estado") {
		t.Errorf("resposta válida com estado inválido: %v", err)
	}
	registerAdapter(t, func(context.Context, Connection, Request) (Response, error) {
		return Response{}, unavailablef("fora do ar")
	})
	if _, err := Decide(decideOptions(repo, verifier, badStateRequest)); err == nil || !strings.Contains(err.Error(), "serializar o estado") {
		t.Errorf("escalonamento com estado inválido: %v", err)
	}
}

func TestDecideRecordFailures(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	t.Setenv(engineKeyEnv, "k")
	enableWithProvider(t, repo, verifier, fakeProvider)
	blockDecisions(t, verifier)

	registerAdapter(t, approvingAdapter(t))
	if result, err := Decide(decideOptions(repo, verifier, testRequest)); err == nil || result.Record != nil {
		t.Errorf("decisão aprovada sem poder gravar deve falhar: %v %+v", err, result)
	}
	registerAdapter(t, func(context.Context, Connection, Request) (Response, error) {
		return Response{}, unavailablef("fora do ar")
	})
	if result, err := Decide(decideOptions(repo, verifier, testRequest)); err == nil || result.Record != nil {
		t.Errorf("escalonamento sem poder gravar deve falhar: %v %+v", err, result)
	}
	// Sem chave: o escalonamento também é gravado e falha de forma explícita.
	t.Setenv(engineKeyEnv, "")
	if _, err := Decide(decideOptions(repo, verifier, testRequest)); err == nil {
		t.Error("escalonamento por chave ausente sem poder gravar deve falhar")
	}
}

func TestGovernAndDecideRootErrors(t *testing.T) {
	t.Setenv(OperatorEnv, "")
	t.Setenv(verify.HomeEnv, "")
	t.Setenv("HOME", "")
	repo := t.TempDir()
	if _, err := Govern(repo, PointApprove, nil, ""); err == nil {
		t.Error("Govern sem raiz resolvível deve falhar")
	}
	if _, err := Decide(decideOptions(repo, "", testRequest)); err == nil {
		t.Error("Decide sem raiz resolvível deve falhar")
	}
}

func TestGovernReadConfigErrorAndNoConfig(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	t.Setenv(OperatorEnv, "")
	governed, err := Govern(repo, PointApprove, nil, verifier)
	if err != nil || governed.Config != nil || governed.Reason != nil {
		t.Fatalf("sem configuração deve ser silencioso: %+v %v", governed, err)
	}
	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Govern(repo, PointApprove, nil, verifier); err == nil {
		t.Error("configuração corrompida deve falhar")
	}
	if _, err := Decide(decideOptions(repo, verifier, testRequest)); err == nil {
		t.Error("Decide com configuração corrompida deve falhar")
	}
}

func TestGovernDisabledConfigWithOperatorDecider(t *testing.T) {
	repo, verifier := t.TempDir(), initVerifier(t)
	if _, err := WriteConfig(repo, nil, verifier); err != nil {
		t.Fatal(err)
	}
	t.Setenv(OperatorEnv, string(OperatorDecider))
	if _, err := Govern(repo, PointApprove, nil, verifier); err == nil || !strings.Contains(err.Error(), "não tem decisor configurado") {
		t.Errorf("erro = %v", err)
	}
	t.Setenv(OperatorEnv, "")
	governed, err := Govern(repo, PointApprove, nil, verifier)
	if err != nil || governed.Config != nil || governed.Reason != nil {
		t.Errorf("config desabilitada deve ser silenciosa: %+v %v", governed, err)
	}
}

func TestRecordRuleDecisionFailsForMissingRepository(t *testing.T) {
	verifier := initVerifier(t)
	_, err := RecordRuleDecision(RuleDecisionOptions{RootDir: filepath.Join(t.TempDir(), "x"), WorkID: "0001", Point: PointApprove}, verifier)
	if err == nil {
		t.Fatal("esperava erro")
	}
}

func TestDescribeDecisionLabelsAndReference(t *testing.T) {
	action := "merge"
	model := "m-1"
	tests := []struct {
		name   string
		record DecisionRecord
		want   string
		ref    string
	}{
		{
			name:   "rejeitado com ação e modelo",
			record: DecisionRecord{DecisionSubject: DecisionSubject{DecisionID: "id1", DecisionContent: DecisionContent{Outcome: OutcomeReject, Action: &action, Model: &model, Decider: "jev:x"}}},
			want:   "[DECISOR] REJEITADO (merge) — m-1, registro id1",
			ref:    "decider:m-1#id1",
		},
		{
			name:   "escalado sem modelo usa o decisor",
			record: DecisionRecord{DecisionSubject: DecisionSubject{DecisionID: "id2", DecisionContent: DecisionContent{Outcome: OutcomeEscalate, Decider: "rule"}}},
			want:   "[DECISOR] PARA O OPERADOR — rule, registro id2",
			ref:    "decider:rule#id2",
		},
		{
			name:   "desfecho desconhecido mantém o texto",
			record: DecisionRecord{DecisionSubject: DecisionSubject{DecisionID: "id3", DecisionContent: DecisionContent{Outcome: Outcome("talvez"), Decider: "rule"}}},
			want:   "[DECISOR] talvez — rule, registro id3",
			ref:    "decider:rule#id3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lines := DescribeDecision(test.record)
			if len(lines) != 1 || lines[0] != test.want {
				t.Errorf("linhas = %q, quer %q", lines, test.want)
			}
			if got := DecisionReference(test.record); got != test.ref {
				t.Errorf("referência = %q, quer %q", got, test.ref)
			}
		})
	}
}
