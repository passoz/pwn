package audit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveKeys identificam linhas cujo valor é redigido antes de ir ao log.
var sensitiveKeys = []string{
	"authorization", "token", "password", "passwd", "cookie", "api_key", "apikey", "secret",
}

// toolchainPatterns identificam erro de ferramenta ou de ambiente que não
// exercita asserção alguma.
var toolchainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)cannot find main module`),
	regexp.MustCompile(`(?i)no required module provides`),
	regexp.MustCompile(`(?i)package .+ is not in`),
	regexp.MustCompile(`(?i)no such file or directory`),
	regexp.MustCompile(`(?i)module not found`),
	regexp.MustCompile(`(?i)cannot find module`),
	regexp.MustCompile(`(?i)error: could not compile`),
	regexp.MustCompile(`(?i)build failed`),
	regexp.MustCompile(`(?i)compilation failed`),
	regexp.MustCompile(`(?i)error\[E\d+\]`),
	regexp.MustCompile(`(?im)^make:\s+\*\*\*`),
	regexp.MustCompile(`(?i)SyntaxError:`),
	regexp.MustCompile(`(?i)ReferenceError:`),
	regexp.MustCompile(`(?i)Parse error`),
	regexp.MustCompile(`(?i)undefined:`),
	regexp.MustCompile(`(?i)type mismatch:`),
	regexp.MustCompile(`TS\d{4}:`),
	regexp.MustCompile(`(?i)cannot find symbol`),
}

// IsToolchainError informa se a saída é exclusivamente erro de ferramenta ou de
// ambiente: o texto esperado só aparece em linhas que casam um padrão de erro,
// sem nenhuma linha de asserção que o contenha.
func IsToolchainError(output, expect string) bool {
	lines := splitOutputLines(output)
	hasToolchainLine := false
	for _, line := range lines {
		if matchesToolchain(line) {
			hasToolchainLine = true
			break
		}
	}
	if !hasToolchainLine {
		return false
	}
	expectLower := strings.ToLower(expect)
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), expectLower) && !matchesToolchain(line) {
			return false
		}
	}
	return true
}

func matchesToolchain(line string) bool {
	for _, pattern := range toolchainPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

var lineBreakPattern = regexp.MustCompile(`\r?\n`)

func splitOutputLines(output string) []string {
	return lineBreakPattern.Split(output, -1)
}

// sanitize redige o valor de toda linha que cita credencial. O separador é o
// primeiro dois-pontos da linha.
func sanitize(output string) string {
	lines := splitOutputLines(output)
	for index, line := range lines {
		lowered := strings.ToLower(line)
		sensitive := false
		for _, key := range sensitiveKeys {
			if strings.Contains(lowered, key) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			continue
		}
		prefix := "sensitive"
		if separator := strings.Index(line, ":"); separator != -1 {
			prefix = line[:separator]
		}
		lines[index] = prefix + ": " + redacted
	}
	return strings.Join(lines, "\n")
}

// execResult é a saída textual de um comando, com stdout e stderr concatenados
// na mesma ordem da referência.
type execResult struct {
	exitCode int
	output   string
}

// rawResult é a saída de um comando que precisa dos bytes de stdout.
type rawResult struct {
	exitCode int
	stdout   []byte
}

var verifierKeyPrefix = "PWN_VERIFIER_KEY="

// childEnv devolve o ambiente herdado sem a chave do verificador. O comando
// auditado é diagnóstico: a autoridade de conclusão é o recibo do verificador.
func childEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, verifierKeyPrefix) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func newCommand(command []string) *exec.Cmd {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = childEnv()
	return cmd
}

// run executa o comando e devolve stdout+stderr sanitizados.
func run(command []string) (execResult, error) {
	if len(command) == 0 {
		return execResult{}, fmt.Errorf("comando vazio")
	}
	cmd := newCommand(command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return execResult{}, err
		}
		exitCode = exitErr.ExitCode()
		if exitCode < 0 {
			exitCode = 1
		}
	}
	return execResult{exitCode: exitCode, output: sanitize(stdout.String() + stderr.String())}, nil
}

// runRaw executa o comando e devolve stdout sem decodificação nem sanitização.
func runRaw(command []string) (rawResult, error) {
	if len(command) == 0 {
		return rawResult{}, fmt.Errorf("comando vazio")
	}
	cmd := newCommand(command)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return rawResult{}, err
		}
		exitCode = exitErr.ExitCode()
		if exitCode < 0 {
			exitCode = 1
		}
	}
	return rawResult{exitCode: exitCode, stdout: stdout.Bytes()}, nil
}

var safeShellToken = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellQuote devolve o token na forma que o shell reconstrói igual.
func shellQuote(value string) string {
	if safeShellToken.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
