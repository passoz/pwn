package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

// contextBackground é o contexto padrão dos handlers. O CLI interrompe por
// sinal no processo; os pacotes do harness aceitam um contexto nil como
// background.
func contextBackground() context.Context {
	return context.Background()
}

// resolvedDir resolve --dir contra o diretório atual, como path.resolve.
func (r *Runner) resolvedDir(args []string) string {
	dir := flagValue(args, "--dir")
	if dir == "" {
		dir = r.rootDir()
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return absolute
}

// flagListAfter devolve os argumentos após a flag até a próxima flag.
func flagListAfter(args []string, name string) []string {
	start := -1
	for i, arg := range args {
		if arg == name {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return []string{}
	}
	end := len(args)
	for i := start; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			end = i
			break
		}
	}
	return args[start:end]
}

// commandAfterSeparator devolve o comando do operador, após o `--`.
func commandAfterSeparator(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return []string{}
}

// timeoutSecondsValue lê --timeout-seconds em segundos inteiros. Flag ausente
// ou valor não numérico vale 600, como o padrão da referência.
func timeoutSecondsValue(args []string) int {
	raw := flagValue(args, "--timeout-seconds")
	if raw == "" {
		return 600
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
		return 600
	}
	seconds := int(math.Ceil(value))
	if seconds < 1 {
		return 1
	}
	return seconds
}

// secondsToDuration converte segundos em duração.
func secondsToDuration(seconds float64) time.Duration {
	return time.Duration(seconds * float64(time.Second))
}

// secondsText escreve a duração com uma casa decimal, como toFixed(1).
func secondsText(duration time.Duration) string {
	return strconv.FormatFloat(float64(duration.Milliseconds())/1000, 'f', 1, 64)
}

// truncate corta o texto no tamanho pedido, como String#slice.
func truncate(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length]
}

// padEnd completa o texto com espaços até a largura em caracteres, como
// String#padEnd.
func padEnd(value string, width int) string {
	length := utf8.RuneCountInString(value)
	if length >= width {
		return value
	}
	return value + strings.Repeat(" ", width-length)
}

// printJSON escreve o valor com a forma de JSON.stringify(value, null, 2),
// preservando a ordem de campos declarada.
func (r *Runner) printJSON(value any) {
	compact, err := jsonx.Insertion(value)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return
	}
	fmt.Fprintln(r.out(), pretty.String())
}
