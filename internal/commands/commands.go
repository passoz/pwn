// Package commands porta os handlers de src/commands (validate, self-check,
// target, queue, metrics, init, decider, work, task e verify) para o CLI em Go.
//
// Cada handler devolve o código de saída e escreve o texto na ordem da
// referência TypeScript. A raiz do projeto vem de Runner.RootDir; quando vazia,
// o handler usa o diretório de trabalho, como process.cwd() na referência.
package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/passoz/pwn/internal/assets"
)

// Runner executa um handler de comando.
type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
	// Stdin é a entrada das perguntas interativas. nil usa os.Stdin.
	Stdin   io.Reader
	RootDir string
}

func (r *Runner) out() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return io.Discard
}

func (r *Runner) errOut() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return io.Discard
}

// rootDir devolve a raiz do projeto. O diretório de trabalho é usado quando
// RootDir está vazio.
func (r *Runner) rootDir() string {
	if r.RootDir != "" {
		return r.RootDir
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// flagValue devolve o valor de --name. O valor só vale quando o argumento
// seguinte existe e não começa com "--", como na referência.
func flagValue(args []string, name string) string {
	for i, arg := range args {
		if arg != name {
			continue
		}
		if i+1 >= len(args) {
			return ""
		}
		value := args[i+1]
		if strings.HasPrefix(value, "--") {
			return ""
		}
		return value
	}
	return ""
}

// hasFlag informa se a flag exata existe nos argumentos.
func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

// printResults escreve um resultado por documento e devolve a contagem de
// arquivos inválidos.
func (r *Runner) printResults(results []assets.ValidationResult) int {
	errorsCount := 0
	for _, result := range results {
		if result.Valid {
			fmt.Fprintf(r.out(), "✓ %s — VÁLIDO (conforme schema)\n", result.File)
			continue
		}
		fmt.Fprintf(r.out(), "✗ %s — ERRO:\n", result.File)
		for _, validationError := range result.Errors {
			fmt.Fprintf(r.out(), "  - %s\n", validationError)
		}
		errorsCount++
	}
	return errorsCount
}
