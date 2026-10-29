package policy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
)

// OperationDomain é a superfície atingida por uma operação.
type OperationDomain string

const (
	DomainFilesystem OperationDomain = "filesystem"
	DomainShell      OperationDomain = "shell"
	DomainNetwork    OperationDomain = "network"
)

// OperationType identifica a operação avaliada.
type OperationType string

const (
	OpReadFile    OperationType = "read_file"
	OpWriteFile   OperationType = "write_file"
	OpDeleteFile  OperationType = "delete_file"
	OpCreateDir   OperationType = "create_dir"
	OpShellExec   OperationType = "shell_exec"
	OpHTTPRequest OperationType = "http_request"
	OpDNSLookup   OperationType = "dns_lookup"
)

// AgentOperation é uma operação proposta. Os campos usados dependem de Type:
// Path para filesystem, Command e Args para shell, Method e URL ou Hostname
// para rede.
type AgentOperation struct {
	Type     OperationType `json:"type"`
	Path     string        `json:"path,omitempty"`
	Command  string        `json:"command,omitempty"`
	Args     []string      `json:"args,omitempty"`
	Method   string        `json:"method,omitempty"`
	URL      string        `json:"url,omitempty"`
	Hostname string        `json:"hostname,omitempty"`
}

// ViolationType classifica uma negação.
type ViolationType string

const (
	ViolationWriteDeny       ViolationType = "write_deny"
	ViolationNotInWriteAllow ViolationType = "not_in_write_allow"
	ViolationShellDenied     ViolationType = "shell_denied"
	ViolationNetworkDenied   ViolationType = "network_denied"
	ViolationDeniedByPolicy  ViolationType = "denied_by_policy"
	ViolationPathTraversal   ViolationType = "path_traversal"
)

// Decision é o veredicto para uma operação.
type Decision struct {
	Allowed       bool            `json:"allowed"`
	Domain        OperationDomain `json:"domain"`
	Operation     AgentOperation  `json:"operation"`
	Reason        string          `json:"reason,omitempty"`
	ViolationType ViolationType   `json:"violationType,omitempty"`
	ContractRef   string          `json:"contractRef,omitempty"`
}

// BatchDecision agrega o resultado de EvaluateAll.
type BatchDecision struct {
	AllAllowed bool       `json:"allAllowed"`
	Denials    []Decision `json:"denials"`
}

// CommandRule é uma regra estrutural de comando.
//
// A regra casa quando o comando é idêntico e, se Args não está vazio, os
// argumentos da operação começam pelo prefixo declarado. Args vazio ou nil
// casa qualquer argumento do comando.
type CommandRule struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// ShellPolicy declara a allowlist e a denylist de shell.
type ShellPolicy struct {
	// AllowedCommands vazio nega tudo, salvo AllowAllShell.
	AllowedCommands []CommandRule `json:"allowedCommands"`
	// DeniedCommands vence sempre a allowlist.
	DeniedCommands []CommandRule `json:"deniedCommands"`
	// AllowAllShell permite explicitamente todos os comandos.
	AllowAllShell bool `json:"allowAllShell,omitempty"`
}

// NetworkPolicy declara a allowlist e a denylist de rede.
type NetworkPolicy struct {
	// AllowedDomains vazia nega tudo, salvo AllowAllNetwork.
	AllowedDomains []string `json:"allowedDomains"`
	// DeniedDomains vence sempre a allowlist.
	DeniedDomains []string `json:"deniedDomains"`
	// AllowAllNetwork permite explicitamente toda a rede.
	AllowAllNetwork bool `json:"allowAllNetwork,omitempty"`
}

// FilesystemPolicy declara o escopo de escrita.
type FilesystemPolicy struct {
	WriteAllow []string `json:"writeAllow"`
	WriteDeny  []string `json:"writeDeny"`
}

// Config é a política efetiva do motor.
type Config struct {
	Filesystem FilesystemPolicy `json:"filesystem"`
	Shell      ShellPolicy      `json:"shell"`
	Network    NetworkPolicy    `json:"network"`
}

// Overrides substitui seções da política default. Uma seção nil mantém o
// default; uma seção não nil substitui a seção inteira e é copiada.
type Overrides struct {
	Shell   *ShellPolicy
	Network *NetworkPolicy
}

// DefaultShellPolicy devolve uma cópia da denylist default. A allowlist começa
// vazia: o motor nega tudo até a política declarar o contrário.
func DefaultShellPolicy() ShellPolicy {
	return ShellPolicy{
		AllowedCommands: []CommandRule{},
		DeniedCommands: []CommandRule{
			{Command: "rm", Args: []string{"-rf", "/"}},
			{Command: "mkfs"},
			{Command: "dd"},
			{Command: ":"},
		},
	}
}

// DefaultNetworkPolicy devolve a política de rede default. A allowlist vazia
// nega tudo até a política declarar o contrário.
func DefaultNetworkPolicy() NetworkPolicy {
	return NetworkPolicy{
		AllowedDomains:  []string{},
		DeniedDomains:   []string{},
		AllowAllNetwork: false,
	}
}

// Engine aplica a política às operações.
type Engine struct {
	config Config
}

// NewEngine cria o motor a partir do escopo do contrato V4.
func NewEngine(taskContract contract.TaskContractV4, overrides *Overrides) *Engine {
	return NewEngineForScope(taskContract.ScopeContract, overrides)
}

// NewEngineForScope cria o motor a partir de um escopo isolado.
func NewEngineForScope(scope contract.ScopeContract, overrides *Overrides) *Engine {
	shell := DefaultShellPolicy()
	if overrides != nil && overrides.Shell != nil {
		shell = cloneShell(*overrides.Shell)
	}
	network := DefaultNetworkPolicy()
	if overrides != nil && overrides.Network != nil {
		network = cloneNetwork(*overrides.Network)
	}
	return &Engine{config: Config{
		Filesystem: FilesystemPolicy{
			WriteAllow: slices.Clone(scope.WriteAllow),
			WriteDeny:  slices.Clone(scope.WriteDeny),
		},
		Shell:   shell,
		Network: network,
	}}
}

// Config devolve uma cópia da política do motor.
func (e *Engine) Config() Config {
	return Config{
		Filesystem: FilesystemPolicy{
			WriteAllow: slices.Clone(e.config.Filesystem.WriteAllow),
			WriteDeny:  slices.Clone(e.config.Filesystem.WriteDeny),
		},
		Shell:   cloneShell(e.config.Shell),
		Network: cloneNetwork(e.config.Network),
	}
}

// NetworkPolicy devolve uma cópia da política de rede.
func (e *Engine) NetworkPolicy() NetworkPolicy {
	return cloneNetwork(e.config.Network)
}

// Evaluate produz o veredicto de uma operação. Operação desconhecida é negada.
func (e *Engine) Evaluate(operation AgentOperation) Decision {
	switch operation.Type {
	case OpReadFile:
		return e.evaluateFileRead(operation)
	case OpWriteFile, OpDeleteFile, OpCreateDir:
		return e.evaluateFileWrite(operation)
	case OpShellExec:
		return e.evaluateShell(operation)
	case OpHTTPRequest, OpDNSLookup:
		return e.evaluateNetwork(operation)
	default:
		return Decision{
			Allowed:       false,
			Domain:        DomainFilesystem,
			Operation:     operation,
			Reason:        "Operação desconhecida — bloqueada por padrão",
			ViolationType: ViolationDeniedByPolicy,
		}
	}
}

// EvaluateAll avalia todas as operações e devolve todas as negações.
func (e *Engine) EvaluateAll(operations []AgentOperation) BatchDecision {
	denials := make([]Decision, 0)
	for _, operation := range operations {
		decision := e.Evaluate(operation)
		if !decision.Allowed {
			denials = append(denials, decision)
		}
	}
	return BatchDecision{AllAllowed: len(denials) == 0, Denials: denials}
}

func (e *Engine) evaluateFileRead(operation AgentOperation) Decision {
	// A leitura não é restringida pelo escopo de escrita.
	return Decision{Allowed: true, Domain: DomainFilesystem, Operation: operation}
}

func (e *Engine) evaluateFileWrite(operation AgentOperation) Decision {
	if ContainsTraversal(operation.Path) {
		return Decision{
			Allowed:       false,
			Domain:        DomainFilesystem,
			Operation:     operation,
			Reason:        fmt.Sprintf("Caminho %q contém '..' — bloqueado por path traversal", operation.Path),
			ViolationType: ViolationPathTraversal,
		}
	}

	result, err := contract.CheckFileAgainstScope(
		operation.Path,
		e.config.Filesystem.WriteAllow,
		e.config.Filesystem.WriteDeny,
	)
	if err != nil {
		return Decision{
			Allowed:       false,
			Domain:        DomainFilesystem,
			Operation:     operation,
			Reason:        err.Error(),
			ViolationType: ViolationDeniedByPolicy,
		}
	}
	if result.Allowed {
		return Decision{Allowed: true, Domain: DomainFilesystem, Operation: operation}
	}
	return Decision{
		Allowed:       false,
		Domain:        DomainFilesystem,
		Operation:     operation,
		Reason:        result.Reason,
		ViolationType: ViolationType(result.ViolationType),
	}
}

// ContainsTraversal informa se o caminho contém o segmento `..`. Barras
// invertidas são tratadas como separadores, como na compilação de glob.
func ContainsTraversal(filePath string) bool {
	normalized := strings.ReplaceAll(filePath, "\\", "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func (e *Engine) evaluateShell(operation AgentOperation) Decision {
	command := operation.Command
	args := operation.Args

	for _, denied := range e.config.Shell.DeniedCommands {
		if matchesCommandRule(command, args, denied) {
			reason := fmt.Sprintf("Comando bloqueado pela política: %s", denied.Command)
			if len(denied.Args) > 0 {
				reason += " " + strings.Join(denied.Args, " ")
			}
			return Decision{
				Allowed:       false,
				Domain:        DomainShell,
				Operation:     operation,
				Reason:        reason,
				ViolationType: ViolationShellDenied,
			}
		}
	}

	if len(e.config.Shell.AllowedCommands) == 0 {
		if e.config.Shell.AllowAllShell {
			return Decision{Allowed: true, Domain: DomainShell, Operation: operation}
		}
		return Decision{
			Allowed:       false,
			Domain:        DomainShell,
			Operation:     operation,
			Reason:        "Comando shell negado — allowlist vazia (fail-closed). Use AllowAllShell=true para permitir deliberadamente.",
			ViolationType: ViolationShellDenied,
		}
	}

	for _, allowed := range e.config.Shell.AllowedCommands {
		if matchesCommandRule(command, args, allowed) {
			return Decision{Allowed: true, Domain: DomainShell, Operation: operation}
		}
	}

	display := command
	if len(args) > 0 {
		display += " " + strings.Join(args, " ")
	}
	return Decision{
		Allowed:       false,
		Domain:        DomainShell,
		Operation:     operation,
		Reason:        fmt.Sprintf("Comando %s não está na allowlist de shells", display),
		ViolationType: ViolationShellDenied,
	}
}

// matchesCommandRule compara comando e prefixo de argumentos. Args vazio na
// regra casa qualquer argumento do comando.
func matchesCommandRule(command string, args []string, rule CommandRule) bool {
	if command != rule.Command {
		return false
	}
	if len(rule.Args) == 0 {
		return true
	}
	if len(args) < len(rule.Args) {
		return false
	}
	for index := range rule.Args {
		if args[index] != rule.Args[index] {
			return false
		}
	}
	return true
}

func (e *Engine) evaluateNetwork(operation AgentOperation) Decision {
	rawURL := operation.URL
	if operation.Type == OpDNSLookup {
		rawURL = "https://" + operation.Hostname
	}
	hostname := extractHostname(rawURL)

	for _, denied := range e.config.Network.DeniedDomains {
		if domainMatches(hostname, denied) {
			return Decision{
				Allowed:       false,
				Domain:        DomainNetwork,
				Operation:     operation,
				Reason:        fmt.Sprintf("Domínio bloqueado pela política: %s", denied),
				ViolationType: ViolationNetworkDenied,
			}
		}
	}

	if len(e.config.Network.AllowedDomains) == 0 {
		if e.config.Network.AllowAllNetwork {
			return Decision{Allowed: true, Domain: DomainNetwork, Operation: operation}
		}
		return Decision{
			Allowed:       false,
			Domain:        DomainNetwork,
			Operation:     operation,
			Reason:        "Acesso à rede negado — allowlist vazia (fail-closed). Use AllowAllNetwork=true para permitir deliberadamente.",
			ViolationType: ViolationNetworkDenied,
		}
	}

	for _, allowed := range e.config.Network.AllowedDomains {
		if domainMatches(hostname, allowed) {
			return Decision{Allowed: true, Domain: DomainNetwork, Operation: operation}
		}
	}

	return Decision{
		Allowed:       false,
		Domain:        DomainNetwork,
		Operation:     operation,
		Reason:        fmt.Sprintf("Domínio não está na allowlist de rede: %s", hostname),
		ViolationType: ViolationNetworkDenied,
	}
}

// extractHostname devolve o host da URL. Um valor que não é URL válida é
// tratado como hostname puro.
func extractHostname(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if index := strings.IndexAny(trimmed, ":/"); index >= 0 {
		trimmed = trimmed[:index]
	}
	return trimmed
}

// domainMatches compara o host com o padrão de forma estrutural.
//
// `example.com` casa o domínio exato e seus subdomínios, mas não
// `example.com.evil.com` nem `evil-example.com`. `*.example.com` casa qualquer
// subdomínio e não o domínio raiz.
func domainMatches(hostname, pattern string) bool {
	host := strings.ToLower(hostname)
	pat := strings.ToLower(pattern)

	if base, wildcard := strings.CutPrefix(pat, "*."); wildcard {
		return host != base && strings.HasSuffix(host, "."+base)
	}
	return host == pat || strings.HasSuffix(host, "."+pat)
}

func cloneShell(policy ShellPolicy) ShellPolicy {
	return ShellPolicy{
		AllowedCommands: cloneRules(policy.AllowedCommands),
		DeniedCommands:  cloneRules(policy.DeniedCommands),
		AllowAllShell:   policy.AllowAllShell,
	}
}

func cloneNetwork(policy NetworkPolicy) NetworkPolicy {
	return NetworkPolicy{
		AllowedDomains:  slices.Clone(policy.AllowedDomains),
		DeniedDomains:   slices.Clone(policy.DeniedDomains),
		AllowAllNetwork: policy.AllowAllNetwork,
	}
}

func cloneRules(rules []CommandRule) []CommandRule {
	if rules == nil {
		return nil
	}
	out := make([]CommandRule, len(rules))
	for index, rule := range rules {
		out[index] = CommandRule{Command: rule.Command}
		if rule.Args != nil {
			out[index].Args = slices.Clone(rule.Args)
		}
	}
	return out
}
