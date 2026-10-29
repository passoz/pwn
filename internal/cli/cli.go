// Package cli interpreta os argumentos do pwn e despacha os comandos.
// O parsing usa apenas a biblioteca padrão e obedece ao contrato do CLI de referência.
package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/passoz/pwn/internal/config"
)

// Run executa o CLI e devolve o código de saída.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, stdout, stderr)
}

// RunContext executa o CLI e interrompe quando o contexto é cancelado.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr, "pwn: execução interrompida")
		return 130
	default:
	}

	// Flags globais valem só antes do separador `--`. Depois dele vem o comando do
	// operador, que pode conter `--version`/`--help` legítimos.
	own := ownArgs(args)

	if len(own) == 0 || hasFlag(own, "--help", "-h") {
		writeHelp(stdout)
		return 0
	}
	if hasFlag(own, "--version", "-v") {
		fmt.Fprintf(stdout, "pwn v%s\n", Version)
		return 0
	}

	rest, operator, err := extractOperator(args, own)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	runner := &runner{stdout: stdout, stderr: stderr}
	if len(rest) == 0 {
		return runner.unknownCommand("")
	}

	// Comando e subcomando são validados antes de ler o ambiente: um comando
	// desconhecido sempre mostra a ajuda, mesmo com PWN_OPERATOR inválido.
	spec, subcommand, ok := runner.resolve(rest[0], rest[1:])
	if !ok {
		return 1
	}

	cfg, err := config.LoadWithOperator(operator)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return runner.run(cfg, spec, subcommand)
}

type runner struct {
	stdout io.Writer
	stderr io.Writer
}

// resolve valida o comando e o subcomando. Quando inválido, escreve o erro e o uso.
func (r *runner) resolve(command string, args []string) (commandSpec, string, bool) {
	spec, ok := lookupCommand(command)
	if !ok {
		r.unknownCommand(command)
		return commandSpec{}, "", false
	}

	if len(spec.subcommands) == 0 {
		return spec, "", true
	}

	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	if !containsSubcommand(spec, subcommand) {
		shown := subcommand
		if shown == "" {
			shown = "(vazio)"
		}
		fmt.Fprintf(r.stderr, "Subcomando desconhecido para 'pwn %s': %s\n", spec.name, shown)
		fmt.Fprintf(r.stdout, "\nUso:\n  %s\n", spec.usage)
		return commandSpec{}, "", false
	}
	return spec, subcommand, true
}

// run chama o handler do comando. Nenhum handler foi portado para Go ainda.
// cfg fica reservado para os handlers que forem migrados.
func (r *runner) run(_ config.Config, spec commandSpec, subcommand string) int {
	name := spec.name
	if subcommand != "" {
		name += " " + subcommand
	}
	fmt.Fprintf(r.stderr, "✗ pwn %s: comando ainda não portado para Go\n", name)
	return 1
}

func (r *runner) unknownCommand(command string) int {
	fmt.Fprintf(r.stderr, "Comando desconhecido: '%s'\n", command)
	writeHelp(r.stdout)
	return 1
}

func writeHelp(w io.Writer) {
	fmt.Fprintf(w, helpText, Version)
}

func ownArgs(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[:i]
		}
	}
	return args
}

func hasFlag(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name {
				return true
			}
		}
	}
	return false
}

// extractOperator remove `--operator <modo>` ou `--operator=<modo>` dos argumentos.
// O valor é validado antes de qualquer handler, como no CLI de referência.
func extractOperator(args, own []string) ([]string, config.OperatorMode, error) {
	for i, arg := range own {
		if arg != "--operator" && !strings.HasPrefix(arg, "--operator=") {
			continue
		}

		raw := ""
		remove := 1
		if strings.HasPrefix(arg, "--operator=") {
			raw = strings.TrimPrefix(arg, "--operator=")
		} else {
			if i+1 >= len(own) {
				return nil, config.OperatorUnset, fmt.Errorf("--operator inválido: '' (use human ou decider)")
			}
			raw = own[i+1]
			remove = 2
		}

		var mode config.OperatorMode
		switch raw {
		case "human":
			mode = config.OperatorHuman
		case "decider":
			mode = config.OperatorDecider
		default:
			return nil, config.OperatorUnset, fmt.Errorf("--operator inválido: '%s' (use human ou decider)", raw)
		}

		rest := make([]string, 0, len(args)-remove)
		rest = append(rest, args[:i]...)
		rest = append(rest, args[i+remove:]...)
		return rest, mode, nil
	}

	return args, config.OperatorUnset, nil
}
