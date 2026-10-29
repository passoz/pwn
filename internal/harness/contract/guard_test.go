package contract_test

import (
	"errors"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/glob"
)

func TestCheckFileAgainstScope(t *testing.T) {
	allow := []string{"src/**", "tests/**"}
	deny := []string{".git/**", "package.json"}

	tests := []struct {
		name      string
		path      string
		allowed   bool
		file      string
		violation contract.ViolationType
	}{
		{"arquivo na allowlist", "src/cli.ts", true, "src/cli.ts", ""},
		{"prefixo ponto barra", "./src/cli.ts", true, "src/cli.ts", ""},
		{"barra dupla e ponto", "src//nested/../cli.ts", true, "src/cli.ts", ""},
		{"subida que sai da allowlist", "src/../secret.txt", false, "secret.txt", contract.ViolationNotInWriteAllow},
		{"subida dupla", "src/foo/../../secret.txt", false, "secret.txt", contract.ViolationNotInWriteAllow},
		{"teste na allowlist", "tests/core/a_test.go", true, "tests/core/a_test.go", ""},
		{"deny literal", "package.json", false, "package.json", contract.ViolationWriteDeny},
		{"deny normalizado", "./package.json", false, "package.json", contract.ViolationWriteDeny},
		{"deny de diretorio", ".git/config", false, ".git/config", contract.ViolationWriteDeny},
		{"fora da allowlist", "secret.env", false, "secret.env", contract.ViolationNotInWriteAllow},
		{"caminho absoluto perde a raiz", "/etc/passwd", false, "etc/passwd", contract.ViolationNotInWriteAllow},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := contract.CheckFileAgainstScope(test.path, allow, deny)
			if err != nil {
				t.Fatalf("CheckFileAgainstScope(%q): %v", test.path, err)
			}
			if result.Allowed != test.allowed {
				t.Fatalf("allowed = %v, quer %v", result.Allowed, test.allowed)
			}
			if result.File != test.file {
				t.Fatalf("file = %q, quer %q", result.File, test.file)
			}
			if result.ViolationType != test.violation {
				t.Fatalf("violationType = %q, quer %q", result.ViolationType, test.violation)
			}
		})
	}
}

func TestCheckFileAgainstScopeReasons(t *testing.T) {
	denied, err := contract.CheckFileAgainstScope("package.json", []string{"src/**"}, []string{"package.json"})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if got, want := denied.Reason, "Arquivo package.json está explicitamente na lista write_deny: package.json"; got != want {
		t.Fatalf("reason = %q, quer %q", got, want)
	}

	outside, err := contract.CheckFileAgainstScope("secret.env", []string{"src/**", "tests/**"}, nil)
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if got, want := outside.Reason, "Arquivo secret.env não consta na allowlist de escrita: [src/**, tests/**]"; got != want {
		t.Fatalf("reason = %q, quer %q", got, want)
	}
}

func TestCheckFileAgainstScopeDenyOverridesAllow(t *testing.T) {
	result, err := contract.CheckFileAgainstScope("secrets/a", []string{"**"}, []string{"secrets/{a,b}"})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if result.Allowed || result.ViolationType != contract.ViolationWriteDeny {
		t.Fatalf("resultado = %+v, quer write_deny", result)
	}

	other, err := contract.CheckFileAgainstScope("secrets/c", []string{"**"}, []string{"secrets/{a,b}"})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if !other.Allowed {
		t.Fatalf("resultado = %+v, quer allowed", other)
	}

	extension, err := contract.CheckFileAgainstScope("secrets/a.key", []string{"**"}, []string{"**/*.{key,pem}"})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if extension.Allowed || extension.ViolationType != contract.ViolationWriteDeny {
		t.Fatalf("resultado = %+v, quer write_deny", extension)
	}
}

func TestCheckFileAgainstScopeInvalidPattern(t *testing.T) {
	_, err := contract.CheckFileAgainstScope("src/a.ts", []string{"src/**"}, []string{"secrets/{a"})
	if !errors.Is(err, glob.ErrInvalidPattern) {
		t.Fatalf("erro = %v, quer ErrInvalidPattern", err)
	}
}

func TestInvalidScopePattern(t *testing.T) {
	tests := []struct {
		name        string
		allow       []string
		deny        []string
		want        string
		wantInvalid bool
	}{
		{"todos validos", []string{"src/**", "tests/**"}, []string{"secrets/{a,b}"}, "", false},
		{"deny invalido", []string{"src/**"}, []string{"secrets/{a"}, "secrets/{a", true},
		{"allow invalido vem antes", []string{"src/{a"}, []string{"secrets/{b"}, "src/{a", true},
		{"classe invertida", []string{"src/**"}, []string{"[z-a]"}, "[z-a]", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pattern, invalid := contract.InvalidScopePattern(test.allow, test.deny)
			if invalid != test.wantInvalid {
				t.Fatalf("invalid = %v, quer %v", invalid, test.wantInvalid)
			}
			if pattern != test.want {
				t.Fatalf("pattern = %q, quer %q", pattern, test.want)
			}
		})
	}
}

func TestCheckDiffAgainstContract(t *testing.T) {
	report, err := contract.CheckDiffAgainstContract(
		[]string{"src/allowed.ts", "package.json", "../outside.txt"},
		[]string{"src/**", "tests/**"},
		[]string{".git/**", "package.json"},
	)
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if report.Passed {
		t.Fatal("report.passed = true")
	}
	if report.TotalFiles != 3 {
		t.Fatalf("totalFiles = %d, quer 3", report.TotalFiles)
	}
	if len(report.Violations) != 2 {
		t.Fatalf("violations = %+v, quer 2", report.Violations)
	}
	if report.Violations[0].File != "package.json" || report.Violations[0].ViolationType != contract.ViolationWriteDeny {
		t.Fatalf("primeira violação = %+v", report.Violations[0])
	}
	if report.Violations[1].File != "outside.txt" || report.Violations[1].ViolationType != contract.ViolationNotInWriteAllow {
		t.Fatalf("segunda violação = %+v", report.Violations[1])
	}
}

func TestCheckDiffAgainstContractPasses(t *testing.T) {
	report, err := contract.CheckDiffAgainstContract(
		[]string{"src/a.ts", "./tests/b_test.go"},
		[]string{"src/**", "tests/**"},
		nil,
	)
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if !report.Passed || report.TotalFiles != 2 || len(report.Violations) != 0 {
		t.Fatalf("report = %+v, quer passe limpo", report)
	}
	if report.Violations == nil {
		t.Fatal("violations deveria ser slice vazio, não nil")
	}
}

func TestCheckDiffAgainstContractInvalidPattern(t *testing.T) {
	_, err := contract.CheckDiffAgainstContract([]string{"src/a.ts"}, []string{"src/**"}, []string{"{"})
	if !errors.Is(err, glob.ErrInvalidPattern) {
		t.Fatalf("erro = %v, quer ErrInvalidPattern", err)
	}
}
