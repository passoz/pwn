package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, root, content string) {
	t.Helper()
	filePath := PolicyFilePath(root)
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(filePath), err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", filePath, err)
	}
}

func TestPolicyFilePath(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, ".pwn", "policy.json")
	if got := PolicyFilePath(root); got != want {
		t.Fatalf("PolicyFilePath(%q) = %q, want %q", root, got, want)
	}
	if got := PolicyFilePath(""); got != filepath.Join(".pwn", "policy.json") {
		t.Fatalf("PolicyFilePath(\"\") = %q", got)
	}
}

func TestResolvePolicyDefaults(t *testing.T) {
	resolved, warnings := ResolvePolicy(t.TempDir())

	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if resolved.Source != SourceDefaults {
		t.Fatalf("source = %q, want %q", resolved.Source, SourceDefaults)
	}
	if !slices.Contains(resolved.RiskKeywords.L3, "auth") || !slices.Contains(resolved.RiskKeywords.L3, "webhook") {
		t.Fatalf("L3 keywords = %v, want auth and webhook", resolved.RiskKeywords.L3)
	}
	if !slices.Contains(resolved.RiskKeywords.L1, "readme") {
		t.Fatalf("L1 keywords = %v, want readme", resolved.RiskKeywords.L1)
	}
	if want := DefaultShellPolicy(); !reflect.DeepEqual(resolved.Shell, want) {
		t.Fatalf("shell = %#v, want %#v", resolved.Shell, want)
	}
	if want := DefaultNetworkPolicy(); !reflect.DeepEqual(resolved.Network, want) {
		t.Fatalf("network = %#v, want %#v", resolved.Network, want)
	}
	if want := DefaultGateThresholds(); resolved.GateThresholds != want {
		t.Fatalf("thresholds = %#v, want %#v", resolved.GateThresholds, want)
	}
}

func TestResolvePolicyDoesNotShareStateWithDefaults(t *testing.T) {
	root := t.TempDir()

	first, _ := ResolvePolicy(root)
	first.Shell.DeniedCommands = append(first.Shell.DeniedCommands, CommandRule{Command: "mutado"})
	first.Network.AllowedDomains = append(first.Network.AllowedDomains, "mutado.example")
	first.RiskKeywords.L3 = append(first.RiskKeywords.L3, "mutado")

	second, _ := ResolvePolicy(root)
	if want := DefaultShellPolicy(); !reflect.DeepEqual(second.Shell, want) {
		t.Fatalf("second shell = %#v, want %#v", second.Shell, want)
	}
	if want := DefaultNetworkPolicy(); !reflect.DeepEqual(second.Network, want) {
		t.Fatalf("second network = %#v, want %#v", second.Network, want)
	}
	if slices.Contains(second.RiskKeywords.L3, "mutado") {
		t.Fatalf("second L3 keywords = %v, want no mutation", second.RiskKeywords.L3)
	}
}

func TestResolvePolicyValidFile(t *testing.T) {
	root := t.TempDir()
	writePolicyFile(t, root, `{
  "risk_keywords": { "l3": ["checkout", "pix"], "l1": ["docs"] },
  "gate_thresholds": { "max_findings_before_block": 2, "max_acs_per_task": 5 },
  "shell": {
    "allowed_commands": [{ "command": "bun", "args": ["test"] }, { "command": "git", "args": ["status"] }],
    "denied_commands": [{ "command": "curl" }],
    "allow_all_shell": false
  },
  "network": {
    "allowed_domains": ["registry.npmjs.org"],
    "denied_domains": ["evil.example"],
    "allow_all_network": false
  }
}`)

	resolved, warnings := ResolvePolicy(root)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if resolved.Source != SourceFile {
		t.Fatalf("source = %q, want %q", resolved.Source, SourceFile)
	}
	if want := (RiskKeywords{L3: []string{"checkout", "pix"}, L1: []string{"docs"}}); !reflect.DeepEqual(resolved.RiskKeywords, want) {
		t.Fatalf("risk keywords = %#v, want %#v", resolved.RiskKeywords, want)
	}
	if want := (GateThresholds{MaxFindingsBeforeBlock: 2, MaxACsPerTask: 5}); resolved.GateThresholds != want {
		t.Fatalf("thresholds = %#v, want %#v", resolved.GateThresholds, want)
	}
	wantShell := ShellPolicy{
		AllowedCommands: []CommandRule{
			{Command: "bun", Args: []string{"test"}},
			{Command: "git", Args: []string{"status"}},
		},
		DeniedCommands: []CommandRule{{Command: "curl"}},
	}
	if !reflect.DeepEqual(resolved.Shell, wantShell) {
		t.Fatalf("shell = %#v, want %#v", resolved.Shell, wantShell)
	}
	wantNetwork := NetworkPolicy{
		AllowedDomains: []string{"registry.npmjs.org"},
		DeniedDomains:  []string{"evil.example"},
	}
	if !reflect.DeepEqual(resolved.Network, wantNetwork) {
		t.Fatalf("network = %#v, want %#v", resolved.Network, wantNetwork)
	}

	loaded, warnings := LoadPolicyFile(root)
	if len(warnings) != 0 {
		t.Fatalf("load warnings = %v, want none", warnings)
	}
	if loaded == nil || loaded.Shell == nil || loaded.Shell.AllowAllShell {
		t.Fatalf("loaded shell = %#v, want declared section with AllowAllShell false", loaded)
	}
}

func TestResolvePolicyPartialSectionsPreserveDefaults(t *testing.T) {
	root := t.TempDir()
	writePolicyFile(t, root, `{
  "risk_keywords": { "l1": ["somente-docs"] },
  "shell": { "allow_all_shell": true },
  "gate_thresholds": { "max_acs_per_task": 0 }
}`)

	resolved, warnings := ResolvePolicy(root)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if resolved.Source != SourceFile {
		t.Fatalf("source = %q, want %q", resolved.Source, SourceFile)
	}
	if want := DefaultRiskKeywords().L3; !reflect.DeepEqual(resolved.RiskKeywords.L3, want) {
		t.Fatalf("L3 keywords = %#v, want defaults %#v", resolved.RiskKeywords.L3, want)
	}
	if want := []string{"somente-docs"}; !reflect.DeepEqual(resolved.RiskKeywords.L1, want) {
		t.Fatalf("L1 keywords = %#v, want %#v", resolved.RiskKeywords.L1, want)
	}
	if !resolved.Shell.AllowAllShell {
		t.Fatal("AllowAllShell = false, want true")
	}
	if len(resolved.Shell.AllowedCommands) != 0 {
		t.Fatalf("allowed commands = %#v, want empty", resolved.Shell.AllowedCommands)
	}
	if want := DefaultShellPolicy().DeniedCommands; !reflect.DeepEqual(resolved.Shell.DeniedCommands, want) {
		t.Fatalf("denied commands = %#v, want defaults %#v", resolved.Shell.DeniedCommands, want)
	}
	if want := (GateThresholds{MaxFindingsBeforeBlock: 0, MaxACsPerTask: 0}); resolved.GateThresholds != want {
		t.Fatalf("thresholds = %#v, want %#v", resolved.GateThresholds, want)
	}
}

func TestResolvePolicyDeclaredEmptyListOverridesDefault(t *testing.T) {
	root := t.TempDir()
	writePolicyFile(t, root, `{"shell": {"denied_commands": []}}`)

	resolved, warnings := ResolvePolicy(root)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if resolved.Shell.DeniedCommands == nil {
		t.Fatal("denied commands = nil, want declared empty slice")
	}
	if len(resolved.Shell.DeniedCommands) != 0 {
		t.Fatalf("denied commands = %#v, want empty", resolved.Shell.DeniedCommands)
	}
}

func TestResolvePolicyRejectsInvalidFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "malformed JSON", content: `{"shell": `},
		{name: "wrong section type", content: `{"shell": 42}`},
		{name: "unknown shell key", content: `{"shell": {"allowAllShell": true}}`},
		{name: "unknown root key", content: `{"campo_desconhecido": 1}`},
		{name: "threshold below minimum", content: `{"gate_thresholds": {"max_acs_per_task": -1}}`},
		{name: "threshold not integer", content: `{"gate_thresholds": {"max_acs_per_task": 1.5}}`},
		{name: "empty command", content: `{"shell": {"allowed_commands": [{"command": ""}]}}`},
		{name: "empty domain", content: `{"network": {"allowed_domains": [""]}}`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			writePolicyFile(t, root, testCase.content)

			loaded, loadWarnings := LoadPolicyFile(root)
			if loaded != nil {
				t.Fatalf("loaded = %#v, want nil", loaded)
			}
			if len(loadWarnings) == 0 {
				t.Fatal("load warnings = none, want at least one")
			}

			resolved, warnings := ResolvePolicy(root)
			if resolved.Source != SourceDefaults {
				t.Fatalf("source = %q, want %q", resolved.Source, SourceDefaults)
			}
			if !slices.Contains(resolved.RiskKeywords.L3, "auth") {
				t.Fatalf("L3 keywords = %v, want defaults", resolved.RiskKeywords.L3)
			}
			if len(warnings) == 0 {
				t.Fatal("warnings = none, want at least one")
			}
			for _, warning := range warnings {
				if !strings.Contains(warning, filepath.Join(".pwn", "policy.json")) {
					t.Fatalf("warning %q does not name the policy file", warning)
				}
			}
		})
	}
}

func TestLoadPolicyFileMissing(t *testing.T) {
	loaded, warnings := LoadPolicyFile(t.TempDir())
	if loaded != nil || len(warnings) != 0 {
		t.Fatalf("LoadPolicyFile(missing) = (%#v, %v), want (nil, none)", loaded, warnings)
	}
}
