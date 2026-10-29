package commands

import (
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/proc"
)

func approvalOf(workID, taskID string) verify.Approval {
	return verify.Approval{
		ApprovalID:      "ap-" + workID + "-" + taskID,
		ApprovalContent: verify.ApprovalContent{WorkID: workID, TaskID: taskID, Kind: "task"},
	}
}

func TestBuildVerifyJobs(t *testing.T) {
	approvals := []verify.Approval{
		approvalOf("0001", "1.1"),
		approvalOf("0002", "1.1"),
		approvalOf("0001", "G-1"),
		approvalOf("0001", "1.1"),
		approvalOf("0001", "1.2"),
	}
	jobs := buildVerifyJobs(approvals, "0001", "/bin/pwn", 30, func(taskID string) bool { return taskID != "1.2" })
	if len(jobs) != 2 || jobs[0].ID != "1.1" || jobs[1].ID != "G-1" {
		t.Fatalf("jobs = %+v", jobs)
	}
	want := "/bin/pwn verify run --work 0001 --task 1.1 --timeout-seconds 30"
	if got := strings.Join(jobs[0].Command, " "); got != want {
		t.Fatalf("command = %q, quer %q", got, want)
	}
	if got := strings.Join(jobs[1].Command, " "); got != "/bin/pwn verify run --work 0001 --global G-1 --timeout-seconds 30" {
		t.Fatalf("command global = %q", got)
	}

	if jobs := buildVerifyJobs(approvals, "0001", "/bin/pwn", 30, nil); len(jobs) != 3 {
		t.Fatalf("sem filtro: jobs = %+v", jobs)
	}
}

func TestVerdictOf(t *testing.T) {
	tests := []struct {
		name   string
		result proc.Result
		want   verifyVerdict
	}{
		{name: "aceito", result: proc.Result{Status: 0}, want: verdictAccepted},
		{name: "timeout não é aceito", result: proc.Result{Status: 0, TimedOut: true}, want: verdictNotAccepted},
		{name: "bloqueado", result: proc.Result{Status: 2}, want: verdictBlocked},
		{name: "falhou", result: proc.Result{Status: 1}, want: verdictNotAccepted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := verdictOf(test.result); got != test.want {
				t.Fatalf("verdictOf = %q, quer %q", got, test.want)
			}
		})
	}
}

func TestAggregateVerifyExit(t *testing.T) {
	tests := []struct {
		name    string
		results []proc.Result
		want    int
	}{
		{name: "todas passam", results: []proc.Result{{Status: 0}, {Status: 0}}, want: 0},
		{name: "alguma falha", results: []proc.Result{{Status: 0}, {Status: 1}}, want: 1},
		{name: "timeout conta como falha", results: []proc.Result{{Status: 0, TimedOut: true}}, want: 1},
		{name: "bloqueado vence", results: []proc.Result{{Status: 1}, {Status: 2}, {Status: 0}}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := aggregateVerifyExit(test.results); got != test.want {
				t.Fatalf("aggregateVerifyExit = %d, quer %d", got, test.want)
			}
		})
	}
}

func TestDescribeApproval(t *testing.T) {
	contractID := "CTR-0001-1.1"
	expect := "pass"
	approval := verify.Approval{
		ApprovalID: "0123456789abcdef-resto",
		ApprovalContent: verify.ApprovalContent{
			Kind:           "task",
			WorkID:         "0001",
			TaskID:         "1.1",
			ApprovedBy:     "operador",
			CreatedAt:      "2026-01-01T00:00:00Z",
			BaselineCommit: "0123456789abcdef",
			PlanSHA256:     "abcdef0123456789aaaa",
			ContractID:     &contractID,
			ApprovedFiles:  []verify.ApprovedFile{{Path: "tests/a.test.ts"}},
			Checks: []verify.ApprovedCheck{
				{ID: "AC-1", Command: []string{"bun", "test"}, ExpectOutput: &expect, RequireBaselineFailure: true},
				{ID: "REGRESSION", Command: []string{"bun", "run", "check"}},
			},
		},
	}
	want := strings.Join([]string{
		"Aprovação 0123456789abcdef… (task)",
		"  Work/task:    0001/1.1",
		"  Aprovada por: operador em 2026-01-01T00:00:00Z",
		"  Baseline:     0123456789ab",
		"  Plano sha256: abcdef0123456789…",
		"  Contrato:     CTR-0001-1.1",
		"  Arquivos de aceitação aprovados: 1",
		"    = tests/a.test.ts",
		"  Checks:",
		"    AC-1          bun test  [exige falha no baseline]",
		"    REGRESSION    bun run check",
	}, "\n") + "\n"
	if got := describeApproval(approval); got != want {
		t.Fatalf("describeApproval =\n%s\nquer\n%s", got, want)
	}
}

func TestVerifyTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr string
	}{
		{name: "padrão", args: nil, want: 600},
		{name: "valor", args: []string{"--timeout-seconds", "15"}, want: 15},
		{name: "inválido", args: []string{"--timeout-seconds", "abc"}, wantErr: "--timeout-seconds inválido"},
		{name: "não positivo", args: []string{"--timeout-seconds", "0"}, wantErr: "--timeout-seconds inválido"},
		{name: "sem valor usa o padrão", args: []string{"--timeout-seconds", "--jobs", "2"}, want: 600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := verifyTimeoutSeconds(test.args)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("erro = %v, quer %q", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("verifyTimeoutSeconds = %d, %v, quer %d", got, err, test.want)
			}
		})
	}
}

func TestParsePositiveInt(t *testing.T) {
	tests := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{raw: "1", want: 1},
		{raw: "2.0", want: 2},
		{raw: "0", wantErr: true},
		{raw: "-1", wantErr: true},
		{raw: "1.5", wantErr: true},
		{raw: "abc", wantErr: true},
	}
	for _, test := range tests {
		got, err := parsePositiveInt(test.raw)
		if test.wantErr {
			if err == nil {
				t.Fatalf("parsePositiveInt(%q) = %d, quer erro", test.raw, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("parsePositiveInt(%q) = %d, %v, quer %d", test.raw, got, err, test.want)
		}
	}
}

// A duração da rede de segurança do run-all é o dobro de timeout+60s.
func TestVerifyRunAllPoolTimeout(t *testing.T) {
	want := 2 * time.Minute
	if got := secondsToDuration(float64(0+60)) * 2; got != want {
		t.Fatalf("timeout = %v, quer %v", got, want)
	}
}
