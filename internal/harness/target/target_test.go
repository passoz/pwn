package target_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/target"
)

// scopedContext replica a fixture de tests/targets.test.ts.
func scopedContext() target.ContractContext {
	return target.ContractContext{
		WriteAllow:         []string{"src/**"},
		WriteDeny:          []string{"schemas/**"},
		AcceptanceCommands: []string{"bun test"},
		RiskLevel:          contract.RiskL2,
		TaskCount:          1,
	}
}

// contractFixture monta o mínimo de um contrato V4 usado pelo coletor.
func contractFixture(risk contract.RiskLevel, allow, deny, commands []string) contract.TaskContractV4 {
	return contract.TaskContractV4{
		ContractVersion:    contract.ContractVersionV4,
		Risk:               contract.RiskContract{Level: risk},
		ScopeContract:      contract.ScopeContract{WriteAllow: allow, WriteDeny: deny},
		AcceptanceContract: contract.AcceptanceContract{Commands: commands},
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler %s: %v", path, err)
	}
	return string(content)
}

func containsAny(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func TestCapabilityMatrix(t *testing.T) {
	tests := []struct {
		name string
		want target.Capabilities
	}{
		{
			name: "pi",
			want: target.Capabilities{
				Target:                  target.RuntimePi,
				Name:                    "Pi Agent Harness",
				SupportsSystemPrompt:    true,
				SupportsSubagents:       true,
				SupportsSkills:          true,
				SupportsToolCalling:     true,
				SupportsContractV4:      true,
				SupportsWorktreeSandbox: true,
				PromptFileFormat:        "AGENTS.md",
			},
		},
		{
			name: "opencode",
			want: target.Capabilities{
				Target:                  target.RuntimeOpenCode,
				Name:                    "OpenCode Interpreter",
				SupportsSystemPrompt:    true,
				SupportsSubagents:       true,
				SupportsSkills:          true,
				SupportsToolCalling:     true,
				SupportsContractV4:      true,
				SupportsWorktreeSandbox: true,
				PromptFileFormat:        "AGENTS.md",
			},
		},
		{
			name: "omp",
			want: target.Capabilities{
				Target:                  target.RuntimeOmp,
				Name:                    "omp (oh my pi) Coding Agent",
				SupportsSystemPrompt:    true,
				SupportsSubagents:       true,
				SupportsSkills:          true,
				SupportsToolCalling:     true,
				SupportsContractV4:      true,
				SupportsWorktreeSandbox: true,
				PromptFileFormat:        "AGENTS.md",
			},
		},
		{
			name: "raw",
			want: target.Capabilities{
				Target:                  target.RuntimeRaw,
				Name:                    "Raw Model API / LLM Prompt",
				SupportsSystemPrompt:    true,
				SupportsSubagents:       false,
				SupportsSkills:          false,
				SupportsToolCalling:     false,
				SupportsContractV4:      false,
				SupportsWorktreeSandbox: false,
				PromptFileFormat:        "prompt.txt",
			},
		},
	}

	if got, want := len(target.CapabilityMatrix), len(tests); got != want {
		t.Fatalf("matriz tem %d runtimes, quer %d", got, want)
	}
	for _, test := range tests {
		runtime := target.Runtime(test.name)
		got, ok := target.CapabilityMatrix[runtime]
		if !ok {
			t.Fatalf("matriz não declara %q", test.name)
		}
		if got != test.want {
			t.Fatalf("CapabilityMatrix[%q] = %+v, quer %+v", test.name, got, test.want)
		}
	}

	wantOrder := []target.Runtime{target.RuntimePi, target.RuntimeOpenCode, target.RuntimeOmp, target.RuntimeRaw}
	if got := target.Runtimes(); !slices.Equal(got, wantOrder) {
		t.Fatalf("Runtimes() = %v, quer %v", got, wantOrder)
	}
}

func TestDeriveUnsupportedCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		runtime target.Runtime
		want    []string
	}{
		{name: "pi suporta tudo", runtime: target.RuntimePi, want: []string{}},
		{name: "opencode suporta tudo", runtime: target.RuntimeOpenCode, want: []string{}},
		{name: "omp suporta tudo", runtime: target.RuntimeOmp, want: []string{}},
		{
			name:    "raw degrada sem array hard-coded",
			runtime: target.RuntimeRaw,
			want: []string{
				"supportsSubagents",
				"supportsSkills",
				"supportsToolCalling",
				"supportsContractV4",
				"supportsWorktreeSandbox",
			},
		},
		{name: "runtime desconhecido não degrada", runtime: target.Runtime("nope"), want: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := target.DeriveUnsupportedCapabilities(test.runtime)
			if !slices.Equal(got, test.want) {
				t.Fatalf("DeriveUnsupportedCapabilities(%q) = %v, quer %v", test.runtime, got, test.want)
			}
		})
	}
}

func TestValidateTargetSupport(t *testing.T) {
	tests := []struct {
		name     string
		runtime  target.Runtime
		required []target.CapabilityFlag
		want     target.SupportCheck
	}{
		{
			name:     "pi atende contrato V4 e tool calling",
			runtime:  target.RuntimePi,
			required: []target.CapabilityFlag{target.CapSupportsContractV4, target.CapSupportsToolCalling},
			want:     target.SupportCheck{Valid: true, Missing: []string{}},
		},
		{
			name:     "omp atende contrato V4 e tool calling",
			runtime:  target.RuntimeOmp,
			required: []target.CapabilityFlag{target.CapSupportsContractV4, target.CapSupportsToolCalling},
			want:     target.SupportCheck{Valid: true, Missing: []string{}},
		},
		{
			name:     "raw falta contrato V4 e tool calling",
			runtime:  target.RuntimeRaw,
			required: []target.CapabilityFlag{target.CapSupportsContractV4, target.CapSupportsToolCalling},
			want:     target.SupportCheck{Valid: false, Missing: []string{"supportsContractV4", "supportsToolCalling"}},
		},
		{
			name:     "capacidade desconhecida nunca é suportada",
			runtime:  target.RuntimePi,
			required: []target.CapabilityFlag{"supportsTelepathy"},
			want:     target.SupportCheck{Valid: false, Missing: []string{"supportsTelepathy"}},
		},
		{
			name:     "runtime desconhecido informa o nome",
			runtime:  target.Runtime("nope"),
			required: []target.CapabilityFlag{target.CapSupportsContractV4},
			want:     target.SupportCheck{Valid: false, Missing: []string{"Target desconhecido: nope"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := target.ValidateTargetSupport(test.runtime, test.required)
			if got.Valid != test.want.Valid {
				t.Fatalf("Valid = %v, quer %v", got.Valid, test.want.Valid)
			}
			if !slices.Equal(got.Missing, test.want.Missing) {
				t.Fatalf("Missing = %v, quer %v", got.Missing, test.want.Missing)
			}
		})
	}
}

func TestCollectContractContext(t *testing.T) {
	tests := []struct {
		name      string
		contracts []contract.TaskContractV4
		want      target.ContractContext
	}{
		{
			name:      "work sem contrato",
			contracts: nil,
			want: target.ContractContext{
				WriteAllow:         []string{},
				WriteDeny:          []string{},
				AcceptanceCommands: []string{},
				RiskLevel:          contract.RiskL0,
				TaskCount:          0,
			},
		},
		{
			name: "um contrato",
			contracts: []contract.TaskContractV4{
				contractFixture(contract.RiskL2, []string{"src/**"}, []string{"schemas/**"}, []string{"bun test"}),
			},
			want: target.ContractContext{
				WriteAllow:         []string{"src/**"},
				WriteDeny:          []string{"schemas/**"},
				AcceptanceCommands: []string{"bun test"},
				RiskLevel:          contract.RiskL2,
				TaskCount:          1,
			},
		},
		{
			name: "risco mais alto vence e listas deduplicam na ordem",
			contracts: []contract.TaskContractV4{
				contractFixture(contract.RiskL1, []string{"docs/**", "src/**"}, []string{"schemas/**"}, []string{"bun test"}),
				contractFixture(contract.RiskL2, []string{"src/**", "tests/**"}, []string{"schemas/**", "infra/**"}, []string{"bun lint", "bun test"}),
			},
			want: target.ContractContext{
				WriteAllow:         []string{"docs/**", "src/**", "tests/**"},
				WriteDeny:          []string{"schemas/**", "infra/**"},
				AcceptanceCommands: []string{"bun test", "bun lint"},
				RiskLevel:          contract.RiskL2,
				TaskCount:          2,
			},
		},
		{
			name: "L4 é o risco máximo",
			contracts: []contract.TaskContractV4{
				contractFixture(contract.RiskL3, nil, nil, nil),
				contractFixture(contract.RiskL4, nil, nil, nil),
				contractFixture(contract.RiskL2, nil, nil, nil),
			},
			want: target.ContractContext{
				WriteAllow:         []string{},
				WriteDeny:          []string{},
				AcceptanceCommands: []string{},
				RiskLevel:          contract.RiskL4,
				TaskCount:          3,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := target.CollectContractContext(test.contracts)
			if !slices.Equal(got.WriteAllow, test.want.WriteAllow) {
				t.Fatalf("WriteAllow = %v, quer %v", got.WriteAllow, test.want.WriteAllow)
			}
			if !slices.Equal(got.WriteDeny, test.want.WriteDeny) {
				t.Fatalf("WriteDeny = %v, quer %v", got.WriteDeny, test.want.WriteDeny)
			}
			if !slices.Equal(got.AcceptanceCommands, test.want.AcceptanceCommands) {
				t.Fatalf("AcceptanceCommands = %v, quer %v", got.AcceptanceCommands, test.want.AcceptanceCommands)
			}
			if got.RiskLevel != test.want.RiskLevel {
				t.Fatalf("RiskLevel = %q, quer %q", got.RiskLevel, test.want.RiskLevel)
			}
			if got.TaskCount != test.want.TaskCount {
				t.Fatalf("TaskCount = %d, quer %d", got.TaskCount, test.want.TaskCount)
			}
		})
	}
}

func TestRenderScopeSection(t *testing.T) {
	if got := target.RenderScopeSection(target.ContractContext{TaskCount: 0}); got != "" {
		t.Fatalf("RenderScopeSection sem task = %q, quer vazio", got)
	}

	want := "\n## Escopo do contrato (V4 congelado)\n" +
		"WRITE ALLOW:\n  + src/**\n" +
		"WRITE DENY:\n  - schemas/**\n" +
		"VALIDATION COMMANDS:\n  $ bun test\n" +
		"RISK LEVEL: L2"
	if got := target.RenderScopeSection(scopedContext()); got != want {
		t.Fatalf("RenderScopeSection divergiu:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderAcceptanceProtocol(t *testing.T) {
	protocol := target.RenderAcceptanceProtocol()
	if !strings.HasPrefix(protocol, "\n## Protocolo de aceitação") {
		t.Fatalf("protocolo sem separador inicial: %q", protocol[:40])
	}
	if !strings.HasSuffix(protocol, "implementar fora do que os ACs exigem e chamar de pronto.") {
		t.Fatalf("protocolo termina em %q", protocol[len(protocol)-60:])
	}

	for _, fragment := range []string{
		"`pwn work audit baseline --work <W> --task <T>`",
		"`pwn work audit red --work <W> --task <T> --expect \"<ID da asserção>\" -- <comando RED do plano>`",
		"`pwn work audit green --work <W> --task <T> -- <comando RED do plano>`",
		"`pwn verify run --work <W> --task <T>`",
		"`pwn verify run --work <W> --global G-<n>`",
		"Nunca aprove por conta própria",
	} {
		if !strings.Contains(protocol, fragment) {
			t.Fatalf("protocolo não contém %q", fragment)
		}
	}
}

func TestMaterializeMatchesReference(t *testing.T) {
	materializers := []struct {
		name       string
		runtime    target.Runtime
		run        func(string, *target.ContractContext) (target.MaterializationResult, error)
		files      []string
		promptFile string
		wantNotes  []string
	}{
		{
			name:       "pi",
			runtime:    target.RuntimePi,
			run:        target.MaterializePi,
			files:      []string{"AGENTS.md"},
			promptFile: "AGENTS.md",
			wantNotes: []string{
				"Gerado AGENTS.md para Pi",
				"Instale copiando AGENTS.md para a raiz do projeto (pi descobre AGENTS.md e CLAUDE.md na inicialização)",
			},
		},
		{
			name:       "opencode",
			runtime:    target.RuntimeOpenCode,
			run:        target.MaterializeOpenCode,
			files:      []string{"AGENTS.md", "opencode.jsonc"},
			promptFile: "AGENTS.md",
			wantNotes: []string{
				"Gerado opencode.jsonc e AGENTS.md para OpenCode",
				"Instale copiando AGENTS.md e opencode.jsonc para a raiz do projeto (ou exporte OPENCODE_CONFIG apontando para o opencode.jsonc)",
				"permission explícita: sessões headless não respondem prompts; o gate de escrita é o Diff Guard do PWN (write_allow/write_deny)",
			},
		},
		{
			name:       "omp",
			runtime:    target.RuntimeOmp,
			run:        target.MaterializeOmp,
			files:      []string{"AGENTS.md", filepath.Join(".omp", "config.yml")},
			promptFile: "AGENTS.md",
			wantNotes: []string{
				"Gerado AGENTS.md e .omp/config.yml para omp (oh my pi)",
				"Instale copiando AGENTS.md para a raiz do projeto e .omp/config.yml para <raiz>/.omp/config.yml",
				"tools.approvalMode: yolo no config de projeto sobrepõe a policy global do operador; use --approval-mode write para sessões interativas",
			},
		},
	}

	modes := []struct {
		name    string
		context *target.ContractContext
	}{
		{name: "plain", context: nil},
		{name: "scoped", context: func() *target.ContractContext { ctx := scopedContext(); return &ctx }()},
	}

	for _, materializer := range materializers {
		for _, mode := range modes {
			t.Run(materializer.name+"/"+mode.name, func(t *testing.T) {
				outDir := t.TempDir()
				result, err := materializer.run(outDir, mode.context)
				if err != nil {
					t.Fatalf("materializar: %v", err)
				}
				if !result.Success {
					t.Fatalf("Success = false")
				}
				if result.Target != materializer.runtime {
					t.Fatalf("Target = %q, quer %q", result.Target, materializer.runtime)
				}
				if len(result.UnsupportedCapabilities) != 0 {
					t.Fatalf("UnsupportedCapabilities = %v, quer vazio", result.UnsupportedCapabilities)
				}
				if !containsAny(result.Notes, "Instale") {
					t.Fatalf("notas sem instrução de instalação: %v", result.Notes)
				}
				if !slices.Equal(result.Notes, materializer.wantNotes) {
					t.Fatalf("notas = %q, quer %q", result.Notes, materializer.wantNotes)
				}

				for _, file := range materializer.files {
					got := readFile(t, filepath.Join(outDir, file))
					goldenDir := "plain"
					if mode.context != nil && file == materializer.promptFile {
						goldenDir = "scoped"
					}
					want := readFile(t, filepath.Join("testdata", goldenDir, materializer.name, file))
					if got != want {
						t.Fatalf("%s divergiu da referência TypeScript:\n got: %q\nwant: %q", file, got, want)
					}
				}
			})
		}
	}
}

func TestMaterializeOpenCodeConfigIsValidJSON(t *testing.T) {
	outDir := t.TempDir()
	if _, err := target.MaterializeOpenCode(outDir, nil); err != nil {
		t.Fatalf("materializar: %v", err)
	}

	var config struct {
		Schema     string `json:"$schema"`
		Permission struct {
			Edit string `json:"edit"`
			Bash string `json:"bash"`
		} `json:"permission"`
		Agent   any `json:"agent"`
		Version any `json:"version"`
		Sandbox any `json:"sandbox"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(outDir, "opencode.jsonc"))), &config); err != nil {
		t.Fatalf("opencode.jsonc inválido: %v", err)
	}
	if config.Schema != "https://opencode.ai/config.json" {
		t.Fatalf("$schema = %q", config.Schema)
	}
	if config.Permission.Edit != "allow" || config.Permission.Bash != "allow" {
		t.Fatalf("permission = %+v", config.Permission)
	}
	if config.Agent != nil || config.Version != nil || config.Sandbox != nil {
		t.Fatalf("config carrega chaves não materializadas: agent=%v version=%v sandbox=%v", config.Agent, config.Version, config.Sandbox)
	}
}

func TestMaterializeOmpConfig(t *testing.T) {
	outDir := t.TempDir()
	result, err := target.MaterializeOmp(outDir, nil)
	if err != nil {
		t.Fatalf("materializar: %v", err)
	}
	if !slices.Equal(result.UnsupportedCapabilities, []string{}) {
		t.Fatalf("UnsupportedCapabilities = %v", result.UnsupportedCapabilities)
	}

	config := readFile(t, filepath.Join(outDir, ".omp", "config.yml"))
	if !strings.Contains(config, "tools:\n  approvalMode: yolo") {
		t.Fatalf("config.yml sem approvalMode: %q", config)
	}
	if !strings.HasSuffix(config, "approvalMode: yolo\n") {
		t.Fatalf("config.yml sem newline final: %q", config[len(config)-20:])
	}
	if !containsAny(result.Notes, ".omp/config.yml") {
		t.Fatalf("notas sem .omp/config.yml: %v", result.Notes)
	}
	if !containsAny(result.Notes, "--approval-mode write") {
		t.Fatalf("notas sem instrução de approval-mode: %v", result.Notes)
	}
}

func TestMaterializeRaw(t *testing.T) {
	outDir := t.TempDir()
	result, err := target.MaterializeRaw(outDir, nil)
	if err != nil {
		t.Fatalf("materializar: %v", err)
	}
	if result.Target != target.RuntimeRaw || !result.Success {
		t.Fatalf("resultado = %+v", result)
	}
	wantUnsupported := []string{
		"supportsSubagents",
		"supportsSkills",
		"supportsToolCalling",
		"supportsContractV4",
		"supportsWorktreeSandbox",
	}
	if !slices.Equal(result.UnsupportedCapabilities, wantUnsupported) {
		t.Fatalf("UnsupportedCapabilities = %v, quer %v", result.UnsupportedCapabilities, wantUnsupported)
	}

	content := readFile(t, filepath.Join(outDir, "prompt.txt"))
	if !strings.HasPrefix(content, "# PWN Raw Model Prompt\n\n") {
		t.Fatalf("prompt.txt sem cabeçalho: %q", content[:30])
	}
	if !strings.Contains(content, "## Protocolo de aceitação") {
		t.Fatalf("prompt.txt sem protocolo de aceitação")
	}
	if !strings.HasSuffix(content, "pronto.\n\n") {
		t.Fatalf("prompt.txt termina em %q", content[len(content)-30:])
	}
}

func TestScopeInjectionParity(t *testing.T) {
	materializers := []struct {
		name       string
		run        func(string, *target.ContractContext) (target.MaterializationResult, error)
		promptFile string
	}{
		{name: "pi", run: target.MaterializePi, promptFile: "AGENTS.md"},
		{name: "opencode", run: target.MaterializeOpenCode, promptFile: "AGENTS.md"},
		{name: "omp", run: target.MaterializeOmp, promptFile: "AGENTS.md"},
		{name: "raw", run: target.MaterializeRaw, promptFile: "prompt.txt"},
	}

	ctx := scopedContext()
	for _, materializer := range materializers {
		t.Run(materializer.name, func(t *testing.T) {
			outDir := t.TempDir()
			if _, err := materializer.run(outDir, &ctx); err != nil {
				t.Fatalf("materializar: %v", err)
			}
			content := readFile(t, filepath.Join(outDir, materializer.promptFile))
			for _, fragment := range []string{
				"WRITE ALLOW", "src/**",
				"WRITE DENY", "schemas/**",
				"VALIDATION COMMANDS", "bun test",
				"RISK LEVEL: L2",
			} {
				if !strings.Contains(content, fragment) {
					t.Fatalf("%s sem %q", materializer.promptFile, fragment)
				}
			}
		})
	}
}

func TestMaterializeDispatchesByRuntime(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "pi", file: "AGENTS.md"},
		{name: "opencode", file: "opencode.jsonc"},
		{name: "omp", file: filepath.Join(".omp", "config.yml")},
		{name: "raw", file: "prompt.txt"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outDir := t.TempDir()
			result, err := target.Materialize(target.Runtime(test.name), outDir, nil)
			if err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			if result.Target != target.Runtime(test.name) {
				t.Fatalf("Target = %q", result.Target)
			}
			if _, err := os.Stat(filepath.Join(outDir, test.file)); err != nil {
				t.Fatalf("arquivo %s ausente: %v", test.file, err)
			}
		})
	}

	if _, err := target.Materialize(target.Runtime("nope"), t.TempDir(), nil); err == nil {
		t.Fatalf("runtime desconhecido devolveu erro nil")
	}
}
