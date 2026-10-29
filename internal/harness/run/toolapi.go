// Package run porta o orquestrador de execução governada por contrato de
// src/core/run-orchestrator.ts e as peças que ele usa: o contexto de run
// (src/core/runner.ts), o gateway obrigatório de ferramentas
// (src/core/tool-api.ts), o roteamento por risco (src/core/router.ts) e a
// heurística de sobreposição de escopo (src/core/scope-overlap.ts).
//
// O fluxo de uma run isolada é:
//
//	contrato (V4) → política → sandbox (HEAD + working tree) → budget →
//	Tool API → diff guard → limpeza → métricas.
//
// A Tool API é o único caminho pelo qual o agente toca o filesystem, o shell
// ou a rede. Toda operação passa por budget, política e contenção de caminho.
package run

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/policy"
	"github.com/passoz/pwn/internal/platform/proc"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// ToolResult é o resultado observável de uma chamada à Tool API.
type ToolResult struct {
	Success         bool                      `json:"success"`
	Data            any                       `json:"data,omitempty"`
	Error           string                    `json:"error,omitempty"`
	PolicyDecision  *policy.Decision          `json:"policyDecision,omitempty"`
	BudgetViolation *contract.BudgetViolation `json:"budgetViolation,omitempty"`
}

// ExecOutput é o dado devolvido por ToolAPI.Exec.
type ExecOutput struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Status int    `json:"status"`
}

// ToolAPIOptions monta a Tool API. Cwd é o diretório do sandbox e RunCtx é o
// contexto que recebe os eventos da run.
type ToolAPIOptions struct {
	Policy   *policy.Engine
	Budget   *contract.BudgetController
	Cwd      string
	RunCtx   *RunContext
	Isolated *bool
}

// ToolAPI é o gateway obrigatório do agente.
type ToolAPI struct {
	policy   *policy.Engine
	budget   *contract.BudgetController
	runCtx   *RunContext
	cwd      string
	isolated bool
}

// NewToolAPI cria o gateway. Isolated ausente vale true: o envelope de bwrap
// só é aplicado quando o host oferece suporte.
func NewToolAPI(options ToolAPIOptions) *ToolAPI {
	isolated := true
	if options.Isolated != nil {
		isolated = *options.Isolated
	}
	return &ToolAPI{
		policy:   options.Policy,
		budget:   options.Budget,
		runCtx:   options.RunCtx,
		cwd:      options.Cwd,
		isolated: isolated,
	}
}

// Cwd devolve o diretório de trabalho do sandbox.
func (t *ToolAPI) Cwd() string { return t.cwd }

func (t *ToolAPI) preCheck() (ToolResult, bool) {
	violation := t.budget.CheckBudget()
	if violation == nil {
		return ToolResult{}, true
	}
	return ToolResult{
		Success:         false,
		Error:           "BUDGET EXCEEDED: " + violation.Message,
		BudgetViolation: violation,
	}, false
}

func (t *ToolAPI) logEvent(eventType EventType, message string, detail any) {
	if t.runCtx == nil {
		return
	}
	emitEvent(t.runCtx, eventType, message, detail)
}

func denied(decision policy.Decision) ToolResult {
	return ToolResult{Success: false, Error: decision.Reason, PolicyDecision: &decision}
}

// WriteFile grava um arquivo dentro do sandbox depois de budget, política e
// contenção de caminho.
func (t *ToolAPI) WriteFile(filePath, content string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpWriteFile, Path: filePath}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW write_file "+filePath, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY write_file "+filePath, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	fullPath, reason, ok := resolveSandboxPath(t.cwd, filePath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE: "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("criar diretório de %q: %v", filePath, err)}
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("gravar %q: %v", filePath, err)}
	}
	t.budget.RecordToolCall()
	t.budget.RecordTokens((utf16Len(content) + 3) / 4)
	t.logEvent(EventStep, fmt.Sprintf("Wrote %s (%d bytes)", filePath, len(content)), nil)

	return ToolResult{Success: true}
}

// ReadFile lê um arquivo do sandbox.
func (t *ToolAPI) ReadFile(filePath string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpReadFile, Path: filePath}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW read_file "+filePath, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY read_file "+filePath, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	fullPath, reason, ok := resolveSandboxPath(t.cwd, filePath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE: "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("ler %q: %v", filePath, err)}
	}
	t.budget.RecordToolCall()
	t.logEvent(EventStep, fmt.Sprintf("Read %s (%d bytes)", filePath, len(data)), nil)

	return ToolResult{Success: true, Data: string(data)}
}

// DeleteFile remove um arquivo do sandbox.
func (t *ToolAPI) DeleteFile(filePath string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpDeleteFile, Path: filePath}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW delete_file "+filePath, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY delete_file "+filePath, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	fullPath, reason, ok := resolveSandboxPath(t.cwd, filePath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE: "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}
	if err := os.Remove(fullPath); err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("remover %q: %v", filePath, err)}
	}
	t.budget.RecordToolCall()
	t.logEvent(EventStep, "Deleted "+filePath, nil)

	return ToolResult{Success: true}
}

// CreateDir cria um diretório no sandbox.
func (t *ToolAPI) CreateDir(dirPath string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpCreateDir, Path: dirPath}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW create_dir "+dirPath, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY create_dir "+dirPath, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	fullPath, reason, ok := resolveSandboxPath(t.cwd, dirPath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE: "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}
	if err := os.MkdirAll(fullPath, 0o755); err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("criar diretório %q: %v", dirPath, err)}
	}
	t.budget.RecordToolCall()
	t.logEvent(EventStep, "Created dir "+dirPath, nil)

	return ToolResult{Success: true}
}

// RenameFile move um arquivo dentro do sandbox. O destino é avaliado como
// escrita; origem e destino precisam ficar contidos no sandbox.
func (t *ToolAPI) RenameFile(oldPath, newPath string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	destination := policy.AgentOperation{Type: policy.OpWriteFile, Path: newPath}
	decision := t.policy.Evaluate(destination)
	if !decision.Allowed {
		t.logEvent(EventPolicyCheck, "DENY rename dest "+newPath, decision)
		return denied(decision)
	}

	oldFullPath, reason, ok := resolveSandboxPath(t.cwd, oldPath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE (source): "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}
	newFullPath, reason, ok := resolveSandboxPath(t.cwd, newPath)
	if !ok {
		t.logEvent(EventError, "PATH ESCAPE (destination): "+reason, nil)
		return ToolResult{Success: false, Error: reason}
	}

	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("mover %q para %q: %v", oldPath, newPath, err)}
	}
	t.budget.RecordToolCall()
	t.logEvent(EventStep, fmt.Sprintf("Renamed %s → %s", oldPath, newPath), nil)

	return ToolResult{Success: true}
}

var shellInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`;`),
	regexp.MustCompile(`&&`),
	regexp.MustCompile(`\|\|`),
	regexp.MustCompile(`\|`),
	regexp.MustCompile(`>`),
	regexp.MustCompile(`>>`),
	regexp.MustCompile(`<$`),
	regexp.MustCompile(`\$\(.*\)`),
	regexp.MustCompile("`.*`"),
	regexp.MustCompile(`\$\{.*\}`),
}

func detectShellInjection(args []string) string {
	for _, arg := range args {
		for _, pattern := range shellInjectionPatterns {
			if pattern.MatchString(arg) {
				return arg
			}
		}
	}
	return ""
}

// Exec executa um comando de forma estrutural (comando + argumentos), sem
// interpolação de shell. O timeout mata o processo filho. O envelope de bwrap
// só é aplicado quando a run é isolada e o host oferece suporte.
func (t *ToolAPI) Exec(command string, args []string, timeout time.Duration) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	if injection := detectShellInjection(args); injection != "" {
		t.logEvent(EventError, fmt.Sprintf("SHELL INJECTION detectado no arg: %q", injection), nil)
		return ToolResult{
			Success: false,
			Error: fmt.Sprintf(
				"Shell injection detectado: argumento contém caracteres proibidos (%q). Use args estruturais, não strings de shell.",
				injection,
			),
		}
	}

	operation := policy.AgentOperation{Type: policy.OpShellExec, Command: command, Args: args}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW shell_exec "+command+" "+strings.Join(args, " "), decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY shell_exec "+command, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	execCommand := command
	execArgs := args
	if t.isolated && sandbox.IsBwrapSupported() {
		network := t.policy.NetworkPolicy()
		wrappedCommand, wrappedArgs := sandbox.WrapWithBwrap(command, args, t.cwd, sandbox.BwrapOptions{
			AllowNetwork: network.AllowAllNetwork,
		})
		execCommand = wrappedCommand
		execArgs = wrappedArgs
	}

	cmd := exec.Command(execCommand, execArgs...)
	cmd.Dir = t.cwd
	cmd.Env = sanitizedEnv()
	// Grupo próprio: matar só o filho deixaria os netos vivos segurando o pipe de
	// saída, e o timeout esperaria por eles.
	proc.ConfigureProcessGroup(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.budget.RecordShellExecution()
		t.logEvent(EventError, fmt.Sprintf("falha ao iniciar processo %s: %v", command, err), nil)
		return ToolResult{Success: false, Error: fmt.Sprintf("falha ao iniciar processo: %v", err)}
	}
	// O processo iniciou: a execução shell é cobrada mesmo que seja morta.
	t.budget.RecordShellExecution()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut := false
	var waitErr error
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		select {
		case waitErr = <-done:
			timer.Stop()
		case <-timer.C:
			timedOut = true
			proc.KillProcessGroup(cmd)
			waitErr = <-done
		}
	} else {
		waitErr = <-done
	}

	if timedOut {
		t.logEvent(EventError, fmt.Sprintf("Process killed by timeout (%dms): %s", timeout.Milliseconds(), command), nil)
		return ToolResult{
			Success: false,
			Error:   fmt.Sprintf("Processo morto por timeout (%dms): %s", timeout.Milliseconds(), command),
		}
	}

	output := ExecOutput{Stdout: stdout.String(), Stderr: stderr.String(), Status: exitStatus(waitErr)}
	t.logEvent(EventStep, fmt.Sprintf("Executed %s %s (exit=%d)", command, strings.Join(args, " "), output.Status), nil)
	return ToolResult{Success: true, Data: output}
}

// HTTPRequest aplica a política de rede. A requisição em si é feita pelo
// chamador, como no original: a Tool API decide, não transporta.
func (t *ToolAPI) HTTPRequest(method, url string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpHTTPRequest, Method: method, URL: url}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW http_request "+method+" "+url, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY http_request "+method+" "+url, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	t.budget.RecordToolCall()
	t.logEvent(EventStep, fmt.Sprintf("HTTP %s %s approved by policy", method, url), nil)
	return ToolResult{Success: true}
}

// DNSLookup aplica a política de rede a um hostname.
func (t *ToolAPI) DNSLookup(hostname string) ToolResult {
	if result, ok := t.preCheck(); !ok {
		return result
	}

	operation := policy.AgentOperation{Type: policy.OpDNSLookup, Hostname: hostname}
	decision := t.policy.Evaluate(operation)
	if decision.Allowed {
		t.logEvent(EventPolicyCheck, "ALLOW dns_lookup "+hostname, decision)
	} else {
		t.logEvent(EventPolicyCheck, "DENY dns_lookup "+hostname, decision)
	}
	if !decision.Allowed {
		return denied(decision)
	}

	t.budget.RecordToolCall()
	t.logEvent(EventStep, "DNS lookup "+hostname+" approved by policy", nil)
	return ToolResult{Success: true}
}

// sanitizedEnv remove a chave do verificador antes de entregar o ambiente ao
// processo do agente, como o original.
func sanitizedEnv() []string {
	env := os.Environ()
	clean := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "PWN_VERIFIER_KEY=") {
			continue
		}
		clean = append(clean, entry)
	}
	return clean
}

func utf16Len(value string) int {
	return len(utf16.Encode([]rune(value)))
}

// exitStatus converte o erro de Wait no código de saída observável. Um processo
// morto por sinal vale 1, como o `status ?? 1` do original.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
	}
	return 1
}

// deepestExistingAncestor devolve o caminho existente mais próximo de target
// (o próprio, se já existir). Usa Lstat: um symlink pendente conta como
// entrada existente, então a resolução falha e a escrita é recusada.
func deepestExistingAncestor(target string) string {
	current := target
	for {
		if _, err := os.Lstat(current); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return current
		}
		current = parent
	}
}

// isContained informa se candidate está em root (ambos já resolvidos).
func isContained(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if relative == "." {
		return true
	}
	if filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// resolveSandboxPath resolve um caminho relativo dentro do sandbox e confere a
// contenção. Devolve o caminho absoluto ou o motivo da recusa.
//
// As verificações são:
//  1. resolve contra cwd e colapsa `..`;
//  2. confere a contenção textual;
//  3. resolve symlinks do ancestral existente mais próximo e reconfere — um
//     diretório-pai symlinkado não pode deixar um arquivo novo escapar.
func resolveSandboxPath(cwd, filePath string) (fullPath, reason string, ok bool) {
	resolved := filePath
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(cwd, resolved)
	}
	resolved = filepath.Clean(resolved)
	normalizedCwd := filepath.Clean(cwd)

	relative, err := filepath.Rel(normalizedCwd, resolved)
	if err != nil || filepath.IsAbs(relative) || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Sprintf(
			"Path escape detectado: %q resolve para %q que está fora do sandbox (%s)",
			filePath, resolved, normalizedCwd,
		), false
	}

	realCwd, err := filepath.EvalSymlinks(normalizedCwd)
	if err != nil {
		return "", fmt.Sprintf("Symlink quebrado ou não resolvido: %q", filePath), false
	}
	realAncestor, err := filepath.EvalSymlinks(deepestExistingAncestor(resolved))
	if err != nil {
		return "", fmt.Sprintf("Symlink quebrado ou não resolvido: %q", filePath), false
	}
	if !isContained(realCwd, realAncestor) {
		kind := "Symlink escape no diretório-pai"
		if _, err := os.Stat(resolved); err == nil {
			kind = "Symlink escape"
		}
		return "", fmt.Sprintf(
			"%s detectado: %q resolve para %q que está fora do sandbox (%s)",
			kind, filePath, realAncestor, realCwd,
		), false
	}

	return resolved, "", true
}
