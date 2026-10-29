package policy

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

func defaultScope() contract.ScopeContract {
	return contract.ScopeContract{
		WriteAllow: []string{"src/**", "tests/**"},
		WriteDeny:  []string{".git/**", "package.json"},
	}
}

func engineWithScope(scope contract.ScopeContract, overrides *Overrides) *Engine {
	return NewEngineForScope(scope, overrides)
}

func engineWith(overrides *Overrides) *Engine {
	return engineWithScope(defaultScope(), overrides)
}

func TestEvaluateFilesystem(t *testing.T) {
	engine := engineWith(nil)

	cases := []struct {
		name          string
		operation     AgentOperation
		wantAllowed   bool
		wantViolation ViolationType
	}{
		{name: "write inside allowlist", operation: AgentOperation{Type: OpWriteFile, Path: "src/cli.go"}, wantAllowed: true},
		{name: "write tests inside allowlist", operation: AgentOperation{Type: OpWriteFile, Path: "tests/policy_test.go"}, wantAllowed: true},
		{
			name:          "write outside allowlist",
			operation:     AgentOperation{Type: OpWriteFile, Path: "secret.env"},
			wantViolation: ViolationNotInWriteAllow,
		},
		{
			name:          "write deny list",
			operation:     AgentOperation{Type: OpWriteFile, Path: "package.json"},
			wantViolation: ViolationWriteDeny,
		},
		{name: "create dir inside allowlist", operation: AgentOperation{Type: OpCreateDir, Path: "src/new"}, wantAllowed: true},
		{
			name:          "create dir outside allowlist",
			operation:     AgentOperation{Type: OpCreateDir, Path: "vendor/new"},
			wantViolation: ViolationNotInWriteAllow,
		},
		{
			name:          "delete deny list",
			operation:     AgentOperation{Type: OpDeleteFile, Path: ".git/config"},
			wantViolation: ViolationWriteDeny,
		},
		{name: "read any file", operation: AgentOperation{Type: OpReadFile, Path: "any-file.txt"}, wantAllowed: true},
		{name: "read absolute file", operation: AgentOperation{Type: OpReadFile, Path: "/etc/hosts"}, wantAllowed: true},
		{
			name:          "traversal to escape allowlist",
			operation:     AgentOperation{Type: OpWriteFile, Path: "src/../secret.env"},
			wantViolation: ViolationPathTraversal,
		},
		{
			name:          "deep traversal",
			operation:     AgentOperation{Type: OpWriteFile, Path: "src/../../etc/passwd"},
			wantViolation: ViolationPathTraversal,
		},
		{
			name:          "traversal with backslash",
			operation:     AgentOperation{Type: OpWriteFile, Path: `src\..\secret.env`},
			wantViolation: ViolationPathTraversal,
		},
		{
			name:          "traversal that stays inside allowlist",
			operation:     AgentOperation{Type: OpWriteFile, Path: "src/sub/../main.go"},
			wantViolation: ViolationPathTraversal,
		},
		{
			name:          "unknown operation",
			operation:     AgentOperation{Type: OperationType("unknown_op")},
			wantViolation: ViolationDeniedByPolicy,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision := engine.Evaluate(testCase.operation)
			if decision.Allowed != testCase.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason: %s)", decision.Allowed, testCase.wantAllowed, decision.Reason)
			}
			if decision.Domain != DomainFilesystem {
				t.Fatalf("domain = %q, want %q", decision.Domain, DomainFilesystem)
			}
			if decision.ViolationType != testCase.wantViolation {
				t.Fatalf("violation = %q, want %q (reason: %s)", decision.ViolationType, testCase.wantViolation, decision.Reason)
			}
			if testCase.wantAllowed && decision.Reason != "" {
				t.Fatalf("allowed decision has reason %q", decision.Reason)
			}
			if !testCase.wantAllowed && decision.Reason == "" {
				t.Fatal("denied decision has no reason")
			}
		})
	}
}

func TestDefaultShellPolicyDenylist(t *testing.T) {
	engine := engineWith(&Overrides{Shell: &ShellPolicy{
		AllowedCommands: []CommandRule{{Command: "git"}},
		DeniedCommands:  DefaultShellPolicy().DeniedCommands,
	}})

	for _, operation := range []AgentOperation{
		{Type: OpShellExec, Command: "rm", Args: []string{"-rf", "/"}},
		{Type: OpShellExec, Command: "mkfs"},
		{Type: OpShellExec, Command: "dd", Args: []string{"if=/dev/zero"}},
		{Type: OpShellExec, Command: ":"},
	} {
		decision := engine.Evaluate(operation)
		if decision.Allowed {
			t.Fatalf("%s allowed, want denied by default denylist", operation.Command)
		}
		if decision.ViolationType != ViolationShellDenied {
			t.Fatalf("%s violation = %q, want %q", operation.Command, decision.ViolationType, ViolationShellDenied)
		}
	}
}

func TestEvaluateShell(t *testing.T) {
	cases := []struct {
		name           string
		shell          ShellPolicy
		operation      AgentOperation
		wantAllowed    bool
		wantViolation  ViolationType
		reasonContains string
	}{
		{
			name:           "empty allowlist denies all",
			shell:          DefaultShellPolicy(),
			operation:      AgentOperation{Type: OpShellExec, Command: "bun", Args: []string{"test"}},
			wantViolation:  ViolationShellDenied,
			reasonContains: "allowlist vazia",
		},
		{
			name:        "allow all shell",
			shell:       ShellPolicy{AllowedCommands: []CommandRule{}, DeniedCommands: []CommandRule{}, AllowAllShell: true},
			operation:   AgentOperation{Type: OpShellExec, Command: "bun", Args: []string{"test"}},
			wantAllowed: true,
		},
		{
			name:        "allowed command with args prefix",
			shell:       ShellPolicy{AllowedCommands: []CommandRule{{Command: "git", Args: []string{"status"}}}},
			operation:   AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"status", "--short"}},
			wantAllowed: true,
		},
		{
			name:          "args prefix mismatch",
			shell:         ShellPolicy{AllowedCommands: []CommandRule{{Command: "git", Args: []string{"status"}}}},
			operation:     AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"push"}},
			wantViolation: ViolationShellDenied,
		},
		{
			name:          "shorter args than rule",
			shell:         ShellPolicy{AllowedCommands: []CommandRule{{Command: "git", Args: []string{"status", "--short"}}}},
			operation:     AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"status"}},
			wantViolation: ViolationShellDenied,
		},
		{
			name:        "rule without args allows any subcommand",
			shell:       ShellPolicy{AllowedCommands: []CommandRule{{Command: "git"}}},
			operation:   AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"push", "origin", "main"}},
			wantAllowed: true,
		},
		{
			name: "deny wins over allow",
			shell: ShellPolicy{
				AllowedCommands: []CommandRule{{Command: "git"}},
				DeniedCommands:  []CommandRule{{Command: "git", Args: []string{"push"}}},
			},
			operation:     AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"push", "origin"}},
			wantViolation: ViolationShellDenied,
		},
		{
			name: "deny wins over allow all",
			shell: ShellPolicy{
				AllowedCommands: []CommandRule{},
				DeniedCommands:  []CommandRule{{Command: "rm", Args: []string{"-rf", "/"}}},
				AllowAllShell:   true,
			},
			operation:     AgentOperation{Type: OpShellExec, Command: "rm", Args: []string{"-rf", "/"}},
			wantViolation: ViolationShellDenied,
		},
		{
			name:          "unknown command",
			shell:         ShellPolicy{AllowedCommands: []CommandRule{{Command: "go"}}},
			operation:     AgentOperation{Type: OpShellExec, Command: "curl", Args: []string{"https://example.com"}},
			wantViolation: ViolationShellDenied,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := engineWith(&Overrides{Shell: &testCase.shell})
			decision := engine.Evaluate(testCase.operation)
			if decision.Allowed != testCase.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason: %s)", decision.Allowed, testCase.wantAllowed, decision.Reason)
			}
			if decision.Domain != DomainShell {
				t.Fatalf("domain = %q, want %q", decision.Domain, DomainShell)
			}
			if decision.ViolationType != testCase.wantViolation {
				t.Fatalf("violation = %q, want %q (reason: %s)", decision.ViolationType, testCase.wantViolation, decision.Reason)
			}
			if testCase.reasonContains != "" && !strings.Contains(decision.Reason, testCase.reasonContains) {
				t.Fatalf("reason = %q, want substring %q", decision.Reason, testCase.reasonContains)
			}
		})
	}
}

func TestEvaluateNetwork(t *testing.T) {
	cases := []struct {
		name           string
		network        NetworkPolicy
		operation      AgentOperation
		wantAllowed    bool
		wantViolation  ViolationType
		reasonContains string
	}{
		{
			name:           "empty allowlist denies all",
			network:        DefaultNetworkPolicy(),
			operation:      AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com"},
			wantViolation:  ViolationNetworkDenied,
			reasonContains: "allowlist vazia",
		},
		{
			name:        "allow all network",
			network:     NetworkPolicy{AllowedDomains: []string{}, DeniedDomains: []string{}, AllowAllNetwork: true},
			operation:   AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com"},
			wantAllowed: true,
		},
		{
			name:        "allowed domain",
			network:     NetworkPolicy{AllowedDomains: []string{"api.github.com"}},
			operation:   AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://api.github.com/repos"},
			wantAllowed: true,
		},
		{
			name:        "allowed apex covers subdomain",
			network:     NetworkPolicy{AllowedDomains: []string{"example.com"}},
			operation:   AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://sub.example.com/path"},
			wantAllowed: true,
		},
		{
			name:          "suffix attack denied",
			network:       NetworkPolicy{AllowedDomains: []string{"example.com"}},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com.evil.com/path"},
			wantViolation: ViolationNetworkDenied,
		},
		{
			name:          "prefix attack denied",
			network:       NetworkPolicy{AllowedDomains: []string{"example.com"}},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://evil-example.com/path"},
			wantViolation: ViolationNetworkDenied,
		},
		{
			name:        "wildcard covers subdomain",
			network:     NetworkPolicy{AllowedDomains: []string{"*.example.com"}},
			operation:   AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://api.example.com/path"},
			wantAllowed: true,
		},
		{
			name:          "wildcard excludes apex",
			network:       NetworkPolicy{AllowedDomains: []string{"*.example.com"}},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com/path"},
			wantViolation: ViolationNetworkDenied,
		},
		{
			name: "deny wins over allow",
			network: NetworkPolicy{
				AllowedDomains: []string{"evil.com"},
				DeniedDomains:  []string{"evil.com"},
			},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "POST", URL: "https://evil.com/data"},
			wantViolation: ViolationNetworkDenied,
		},
		{
			name: "deny wins over allow all",
			network: NetworkPolicy{
				AllowedDomains:  []string{},
				DeniedDomains:   []string{"evil.com"},
				AllowAllNetwork: true,
			},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://evil.com/data"},
			wantViolation: ViolationNetworkDenied,
		},
		{
			name:        "dns lookup uses hostname",
			network:     NetworkPolicy{AllowedDomains: []string{"example.com"}},
			operation:   AgentOperation{Type: OpDNSLookup, Hostname: "api.example.com"},
			wantAllowed: true,
		},
		{
			name:        "url with port",
			network:     NetworkPolicy{AllowedDomains: []string{"example.com"}},
			operation:   AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com:8443/path"},
			wantAllowed: true,
		},
		{
			name:          "domain outside allowlist",
			network:       NetworkPolicy{AllowedDomains: []string{"api.github.com"}},
			operation:     AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com"},
			wantViolation: ViolationNetworkDenied,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := engineWith(&Overrides{Network: &testCase.network})
			decision := engine.Evaluate(testCase.operation)
			if decision.Allowed != testCase.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason: %s)", decision.Allowed, testCase.wantAllowed, decision.Reason)
			}
			if decision.Domain != DomainNetwork {
				t.Fatalf("domain = %q, want %q", decision.Domain, DomainNetwork)
			}
			if decision.ViolationType != testCase.wantViolation {
				t.Fatalf("violation = %q, want %q (reason: %s)", decision.ViolationType, testCase.wantViolation, decision.Reason)
			}
			if testCase.reasonContains != "" && !strings.Contains(decision.Reason, testCase.reasonContains) {
				t.Fatalf("reason = %q, want substring %q", decision.Reason, testCase.reasonContains)
			}
		})
	}
}

func TestEvaluateAll(t *testing.T) {
	engine := engineWith(nil)
	result := engine.EvaluateAll([]AgentOperation{
		{Type: OpWriteFile, Path: "src/cli.go"},
		{Type: OpWriteFile, Path: "package.json"},
		{Type: OpReadFile, Path: "anything.txt"},
	})

	if result.AllAllowed {
		t.Fatal("AllAllowed = true, want false")
	}
	if len(result.Denials) != 1 {
		t.Fatalf("denials = %#v, want exactly one", result.Denials)
	}
	if result.Denials[0].ViolationType != ViolationWriteDeny {
		t.Fatalf("violation = %q, want %q", result.Denials[0].ViolationType, ViolationWriteDeny)
	}

	empty := engine.EvaluateAll(nil)
	if !empty.AllAllowed || len(empty.Denials) != 0 {
		t.Fatalf("empty batch = %#v, want all allowed without denials", empty)
	}
}

func TestNewEngineUsesContractScope(t *testing.T) {
	taskContract, err := contract.CreateDefaultContractV4("T-001", "0001", "Policy Test", contract.RiskL1, &contract.DefaultOptions{
		WriteAllow: []string{"src/**"},
		WriteDeny:  []string{"package.json"},
	})
	if err != nil {
		t.Fatalf("CreateDefaultContractV4: %v", err)
	}

	engine := NewEngine(taskContract, nil)
	if decision := engine.Evaluate(AgentOperation{Type: OpWriteFile, Path: "src/main.go"}); !decision.Allowed {
		t.Fatalf("src/main.go denied: %s", decision.Reason)
	}
	if decision := engine.Evaluate(AgentOperation{Type: OpWriteFile, Path: "package.json"}); decision.Allowed {
		t.Fatal("package.json allowed, want write_deny")
	}
}

func TestEvaluateInvalidScopePatternFailsClosed(t *testing.T) {
	engine := engineWithScope(contract.ScopeContract{WriteAllow: []string{"{"}}, nil)
	decision := engine.Evaluate(AgentOperation{Type: OpWriteFile, Path: "src/main.go"})
	if decision.Allowed {
		t.Fatal("invalid scope pattern allowed write, want fail-closed denial")
	}
	if decision.ViolationType != ViolationDeniedByPolicy {
		t.Fatalf("violation = %q, want %q", decision.ViolationType, ViolationDeniedByPolicy)
	}
}

func TestEvaluateNetworkAcceptsBareHostname(t *testing.T) {
	engine := engineWith(&Overrides{Network: &NetworkPolicy{AllowedDomains: []string{"example.com"}}})
	decision := engine.Evaluate(AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "example.com/path"})
	if !decision.Allowed {
		t.Fatalf("bare hostname denied: %s", decision.Reason)
	}
}

func TestEngineCopiesInputsAndConfig(t *testing.T) {
	shell := ShellPolicy{
		AllowedCommands: []CommandRule{{Command: "git", Args: []string{"status"}}},
		DeniedCommands:  []CommandRule{{Command: "rm"}},
	}
	network := NetworkPolicy{AllowedDomains: []string{"example.com"}}
	scope := defaultScope()

	engine := engineWithScope(scope, &Overrides{Shell: &shell, Network: &network})

	shell.AllowedCommands[0].Args[0] = "mutado"
	shell.DeniedCommands[0].Command = "mutado"
	network.AllowedDomains[0] = "mutado.example"
	scope.WriteAllow[0] = "mutado/**"

	if decision := engine.Evaluate(AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"status"}}); !decision.Allowed {
		t.Fatalf("git status denied after mutating override: %s", decision.Reason)
	}
	if decision := engine.Evaluate(AgentOperation{Type: OpShellExec, Command: "rm"}); decision.Allowed {
		t.Fatal("rm allowed after mutating override denylist")
	}
	if decision := engine.Evaluate(AgentOperation{Type: OpHTTPRequest, Method: "GET", URL: "https://example.com"}); !decision.Allowed {
		t.Fatalf("example.com denied after mutating network override: %s", decision.Reason)
	}
	if decision := engine.Evaluate(AgentOperation{Type: OpWriteFile, Path: "src/main.go"}); !decision.Allowed {
		t.Fatalf("src/main.go denied after mutating scope allowlist: %s", decision.Reason)
	}

	config := engine.Config()
	config.Shell.AllowedCommands[0].Command = "mutado"
	config.Network.AllowedDomains[0] = "mutado.example"
	config.Filesystem.WriteAllow[0] = "mutado/**"

	if decision := engine.Evaluate(AgentOperation{Type: OpShellExec, Command: "git", Args: []string{"status"}}); !decision.Allowed {
		t.Fatalf("git status denied after mutating Config(): %s", decision.Reason)
	}
	if got := engine.NetworkPolicy().AllowedDomains; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("NetworkPolicy() = %v after mutating Config()", got)
	}
}
