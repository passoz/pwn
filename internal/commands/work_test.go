package commands

import (
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/proc"
)

func scopedContract(writeAllow ...string) contract.TaskContractV4 {
	return contract.TaskContractV4{ScopeContract: contract.ScopeContract{WriteAllow: writeAllow}}
}

func TestParseRunAllArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    runAllOptions
		wantErr string
	}{
		{
			name: "padrões",
			args: []string{"--", "x"},
			want: runAllOptions{timeoutSeconds: 600, command: []string{"x"}},
		},
		{
			name: "works deduplicados e aparados",
			args: []string{"--works", "0001, 0002,0001", "--", "x"},
			want: runAllOptions{works: []string{"0001", "0002"}, timeoutSeconds: 600, command: []string{"x"}},
		},
		{
			name: "flags válidas",
			args: []string{"--works", "0007", "--jobs", "2", "--timeout-seconds", "30", "--no-gate", "--", "bun", "test"},
			want: runAllOptions{
				works:          []string{"0007"},
				jobs:           2,
				timeoutSeconds: 30,
				noGate:         true,
				command:        []string{"bun", "test"},
			},
		},
		{
			name:    "jobs zero",
			args:    []string{"--jobs", "0", "--", "x"},
			wantErr: "--jobs inválido: '0' (esperado inteiro >= 1)",
		},
		{
			name:    "jobs sem valor",
			args:    []string{"--jobs", "--", "x"},
			wantErr: "--jobs exige um inteiro positivo",
		},
		{
			name:    "timeout não numérico",
			args:    []string{"--timeout-seconds", "abc", "--", "x"},
			wantErr: "--timeout-seconds inválido: 'abc' (esperado número > 0)",
		},
		{
			name:    "timeout sem valor",
			args:    []string{"--timeout-seconds", "--", "x"},
			wantErr: "--timeout-seconds exige um número positivo",
		},
		{
			name:    "works sem valor",
			args:    []string{"--works", "--", "x"},
			wantErr: "--works exige uma lista separada por vírgula (ex.: --works 0001,0002)",
		},
		{
			name:    "works vazio",
			args:    []string{"--works", " , ", "--", "x"},
			wantErr: "--works está vazio",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseRunAllArgs(test.args)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("erro = %v, quer %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("erro = %v, quer nil", err)
			}
			if got.jobs != test.want.jobs || got.timeoutSeconds != test.want.timeoutSeconds || got.noGate != test.want.noGate {
				t.Fatalf("opções = %+v, quer %+v", got, test.want)
			}
			if strings.Join(got.works, ",") != strings.Join(test.want.works, ",") {
				t.Fatalf("works = %v, quer %v", got.works, test.want.works)
			}
			if strings.Join(got.command, " ") != strings.Join(test.want.command, " ") {
				t.Fatalf("command = %v, quer %v", got.command, test.want.command)
			}
		})
	}
}

func TestBuildRunAllJobs(t *testing.T) {
	t.Run("um job por Work com flags e -- preservados", func(t *testing.T) {
		jobs, err := buildRunAllJobs(
			[]string{"--works", "0001,0002", "--jobs", "2", "--timeout-seconds", "30", "--no-gate", "--", "bun", "test", "--bail"},
			[]string{"0001", "0002"},
			"/bin/pwn",
		)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if len(jobs) != 2 || jobs[0].ID != "0001" || jobs[1].ID != "0002" {
			t.Fatalf("jobs = %+v", jobs)
		}
		want := "/bin/pwn work run --work 0001 --no-gate --timeout-seconds 30 -- bun test --bail"
		if got := strings.Join(jobs[0].Command, " "); got != want {
			t.Fatalf("command = %q, quer %q", got, want)
		}
	})

	t.Run("sem --no-gate e timeout padrão", func(t *testing.T) {
		jobs, err := buildRunAllJobs([]string{"--jobs", "4", "--", "bun", "test"}, []string{"0007"}, "/bin/pwn")
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		want := "/bin/pwn work run --work 0007 --timeout-seconds 600 -- bun test"
		if got := strings.Join(jobs[0].Command, " "); got != want {
			t.Fatalf("command = %q, quer %q", got, want)
		}
	})

	t.Run("não confunde flags do comando com as do run-all", func(t *testing.T) {
		jobs, err := buildRunAllJobs([]string{"--", "bun", "test", "--no-gate", "--jobs", "9"}, []string{"0001"}, "/bin/pwn")
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		separator := -1
		for i, arg := range jobs[0].Command {
			if arg == "--" {
				separator = i
				break
			}
		}
		if separator == -1 {
			t.Fatalf("comando sem separador: %v", jobs[0].Command)
		}
		for _, arg := range jobs[0].Command[:separator] {
			if arg == "--no-gate" || arg == "--jobs" || arg == "9" {
				t.Fatalf("flag do comando vazou para o run-all: %v", jobs[0].Command)
			}
		}
		want := "bun test --no-gate --jobs 9"
		if got := strings.Join(jobs[0].Command[separator+1:], " "); got != want {
			t.Fatalf("comando = %q, quer %q", got, want)
		}
	})
}

func TestFindScopeOverlaps(t *testing.T) {
	t.Run("globs sobrepostos entre Works", func(t *testing.T) {
		overlaps := findScopeOverlaps([]string{"0001", "0002"}, map[string][]contract.TaskContractV4{
			"0001": {scopedContract("src/**", "tests/**")},
			"0002": {scopedContract("src/auth/**")},
		})
		if len(overlaps) != 1 {
			t.Fatalf("overlaps = %+v", overlaps)
		}
		if overlaps[0].works != [2]string{"0001", "0002"} {
			t.Fatalf("works = %v", overlaps[0].works)
		}
		if len(overlaps[0].patterns) != 1 || overlaps[0].patterns[0] != [2]string{"src/**", "src/auth/**"} {
			t.Fatalf("patterns = %v", overlaps[0].patterns)
		}
	})

	t.Run("caminho literal coberto por glob e glob idêntico", func(t *testing.T) {
		cases := []map[string][]contract.TaskContractV4{
			{"a": {scopedContract("src/a/x.ts")}, "b": {scopedContract("src/**")}},
			{"a": {scopedContract("docs/**")}, "b": {scopedContract("docs/**")}},
			{"a": {scopedContract("src/a/x.ts")}, "b": {scopedContract("src/a/x.ts")}},
		}
		for _, contracts := range cases {
			if got := findScopeOverlaps([]string{"a", "b"}, contracts); len(got) != 1 {
				t.Fatalf("contratos %v: overlaps = %+v", contracts, got)
			}
		}
	})

	t.Run("globs disjuntos", func(t *testing.T) {
		overlaps := findScopeOverlaps([]string{"0001", "0002", "0003"}, map[string][]contract.TaskContractV4{
			"0001": {scopedContract("src/a/**", "docs/a.md")},
			"0002": {scopedContract("src/b/**", "docs/b.md")},
			"0003": {scopedContract("lib/**"), scopedContract("scripts/*.sh")},
		})
		if len(overlaps) != 0 {
			t.Fatalf("overlaps = %+v", overlaps)
		}
	})

	t.Run("une os write_allow de todos os contratos do Work e cobre pares", func(t *testing.T) {
		overlaps := findScopeOverlaps([]string{"0001", "0002", "0003"}, map[string][]contract.TaskContractV4{
			"0001": {scopedContract("src/a/**"), scopedContract("docs/**")},
			"0002": {scopedContract("src/b/**")},
			"0003": {scopedContract("docs/guide.md")},
		})
		if len(overlaps) != 1 || overlaps[0].works != [2]string{"0001", "0003"} {
			t.Fatalf("overlaps = %+v", overlaps)
		}
	})
}

func TestAggregateExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		results []proc.Result
		want    int
	}{
		{name: "vazio", results: nil, want: 0},
		{name: "todos zero", results: []proc.Result{{Status: 0}, {Status: 0}}, want: 0},
		{name: "maior código não-zero", results: []proc.Result{{Status: 0}, {Status: 3}, {Status: 1}}, want: 3},
		{name: "timeout vale 124", results: []proc.Result{{Status: 137, TimedOut: true}, {Status: 1}}, want: 124},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := aggregateExitCodes(test.results); got != test.want {
				t.Fatalf("aggregateExitCodes = %d, quer %d", got, test.want)
			}
		})
	}
}

func TestPrefixLines(t *testing.T) {
	got := prefixLines("0001", "linha a\nlinha b\n\n")
	want := []string{"[0001] linha a", "[0001] linha b"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("prefixLines = %v, quer %v", got, want)
	}

	if got := prefixLines("0002", ""); len(got) != 1 || got[0] != "[0002] " {
		t.Fatalf("prefixLines vazio = %v", got)
	}
}

func TestParseRunID(t *testing.T) {
	tests := []struct {
		name   string
		result proc.Result
		want   string
	}{
		{name: "stdout", result: proc.Result{Stdout: "✓ RUN-20261029-abc_1 concluído"}, want: "RUN-20261029-abc_1"},
		{name: "stderr", result: proc.Result{Stderr: "[RUN-xyz] falhou"}, want: "RUN-xyz"},
		{name: "ausente", result: proc.Result{Stdout: "nada"}, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseRunID(test.result); got != test.want {
				t.Fatalf("parseRunID = %q, quer %q", got, test.want)
			}
		})
	}
}

func TestWorkAuditArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "sem argumentos", args: nil, want: []string{"verify"}},
		{name: "ação explícita", args: []string{"baseline", "--work", "0001"}, want: []string{"baseline", "--work", "0001"}},
		{name: "compatibilidade", args: []string{"--work", "0001"}, want: []string{"verify", "--work", "0001"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := strings.Join(workAuditArgs(test.args), " "); got != strings.Join(test.want, " ") {
				t.Fatalf("workAuditArgs = %v, quer %v", got, test.want)
			}
		})
	}
}

func TestValidateFrozenContract(t *testing.T) {
	if err := validateFrozenContract(&contract.TaskContractV4{}); err == nil || !strings.Contains(err.Error(), "risk.level ausente") {
		t.Fatalf("contrato vazio: erro = %v", err)
	}
	noScope := contract.TaskContractV4{Risk: contract.RiskContract{Level: contract.RiskL2}}
	if err := validateFrozenContract(&noScope); err == nil || !strings.Contains(err.Error(), "write_allow vazio") {
		t.Fatalf("sem escopo: erro = %v", err)
	}
	noAcceptance := noScope
	noAcceptance.ScopeContract.WriteAllow = []string{"src/**"}
	if err := validateFrozenContract(&noAcceptance); err == nil || !strings.Contains(err.Error(), "commands vazio") {
		t.Fatalf("sem aceitação: erro = %v", err)
	}
	valid := noAcceptance
	valid.AcceptanceContract.Commands = []string{"bun test"}
	if err := validateFrozenContract(&valid); err != nil {
		t.Fatalf("contrato válido: erro = %v", err)
	}
}

func TestTimeoutSecondsValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "padrão", args: nil, want: 600},
		{name: "valor", args: []string{"--timeout-seconds", "30"}, want: 30},
		{name: "fração arredonda para cima", args: []string{"--timeout-seconds", "0.5"}, want: 1},
		{name: "inválido usa o padrão", args: []string{"--timeout-seconds", "abc"}, want: 600},
		{name: "zero usa o padrão", args: []string{"--timeout-seconds", "0"}, want: 600},
		{name: "sem valor usa o padrão", args: []string{"--timeout-seconds", "--work", "0001"}, want: 600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := timeoutSecondsValue(test.args); got != test.want {
				t.Fatalf("timeoutSecondsValue = %d, quer %d", got, test.want)
			}
		})
	}
}

func TestPadEndAndTruncate(t *testing.T) {
	if got := padEnd("critérios", 12); len([]rune(got)) != 12 {
		t.Fatalf("padEnd = %q", got)
	}
	if got := padEnd("abcdefghij", 4); got != "abcdefghij" {
		t.Fatalf("padEnd não deve cortar: %q", got)
	}
	if got := truncate("0123456789abcdef", 12); got != "0123456789ab" {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncate("curto", 12); got != "curto" {
		t.Fatalf("truncate curto = %q", got)
	}
}

func TestSecondsText(t *testing.T) {
	if got := secondsText(1500 * time.Millisecond); got != "1.5" {
		t.Fatalf("secondsText = %q, quer 1.5", got)
	}
	if got := secondsText(0); got != "0.0" {
		t.Fatalf("secondsText = %q, quer 0.0", got)
	}
}
