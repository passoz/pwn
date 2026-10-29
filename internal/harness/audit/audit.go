// Package audit porta src/core/task_evidence.ts: o diagnóstico TDD local de
// uma task (baseline, red, green, check e verify).
//
// O estado fica em `.todo/evidence/<work>/state/<task>.json`, os logs em
// `.todo/evidence/<work>/<task>-<check>.log` e a cadeia de hash em
// `.todo/evidence/<work>/<task>-chain.jsonl`. O audit é diagnóstico: a
// autoridade de conclusão é o recibo do verificador independente.
//
// A saída preserva os códigos da referência: 0 para sucesso, 1 para violação e
// 2 para auditoria incompleta.
package audit

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Códigos de saída da referência.
const (
	// ExitOK é a execução concluída com sucesso.
	ExitOK = 0
	// ExitViolation é violação de contrato ou erro de uso.
	ExitViolation = 1
	// ExitIncomplete é auditoria incompleta: falta evidência ou pré-requisito.
	ExitIncomplete = 2
)

// actions são as fases aceitas na linha de comando.
var actions = []string{"baseline", "red", "green", "verify", "check"}

func isAction(value string) bool {
	for _, action := range actions {
		if action == value {
			return true
		}
	}
	return false
}

// parsedArgs reúne a ação e as opções da linha de comando.
type parsedArgs struct {
	action string
	work   string
	task   string
	paths  workPaths

	implementation []string
	tests          []string

	expect        string
	expectSet     bool
	expectLiteral bool

	name    string
	command []string
}

// takeSingle remove uma opção com um valor da lista de tokens.
func takeSingle(tokens *[]string, name string) (string, bool, error) {
	list := *tokens
	for index, token := range list {
		if token != name {
			continue
		}
		if index+1 >= len(list) {
			return "", false, fmt.Errorf("missing value for %s", name)
		}
		value := list[index+1]
		if value == "" || strings.HasPrefix(value, "--") {
			return "", false, fmt.Errorf("missing value for %s", name)
		}
		*tokens = append(append([]string{}, list[:index]...), list[index+2:]...)
		return value, true, nil
	}
	return "", false, nil
}

// takeMultiple remove uma opção que consome valores até a próxima flag.
func takeMultiple(tokens *[]string, name string) ([]string, error) {
	list := *tokens
	for index, token := range list {
		if token != name {
			continue
		}
		values := make([]string, 0)
		cursor := index + 1
		for cursor < len(list) && !strings.HasPrefix(list[cursor], "--") {
			values = append(values, list[cursor])
			cursor++
		}
		*tokens = append(append([]string{}, list[:index]...), list[cursor:]...)
		return values, nil
	}
	return []string{}, nil
}

// takeFlag remove uma flag booleana e informa se ela estava presente.
func takeFlag(tokens *[]string, name string) bool {
	list := *tokens
	for index, token := range list {
		if token != name {
			continue
		}
		*tokens = append(append([]string{}, list[:index]...), list[index+1:]...)
		return true
	}
	return false
}

func parseArgs(argv []string) (*parsedArgs, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("unknown or missing action")
	}
	action := argv[0]
	if !isAction(action) {
		return nil, fmt.Errorf("unknown or missing action")
	}
	rest := argv[1:]
	options := rest
	command := []string{}
	for index, token := range rest {
		if token == "--" {
			options = append([]string{}, rest[:index]...)
			command = append([]string{}, rest[index+1:]...)
			break
		}
	}

	work, found, err := takeSingle(&options, "--work")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("missing required option: --work")
	}
	task, found, err := takeSingle(&options, "--task")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("missing required option: --task")
	}
	paths, err := configureWork(work)
	if err != nil {
		return nil, err
	}

	parsed := &parsedArgs{action: action, work: work, task: task, paths: paths, command: command}

	switch action {
	case "baseline":
		implementation, err := takeMultiple(&options, "--implementation")
		if err != nil {
			return nil, err
		}
		tests, err := takeMultiple(&options, "--tests")
		if err != nil {
			return nil, err
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(options, " "))
		}
		parsed.implementation = implementation
		parsed.tests = tests
	case "red":
		parsed.expectLiteral = takeFlag(&options, "--expect-literal")
		expect, found, err := takeSingle(&options, "--expect")
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("missing required option: --expect")
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(options, " "))
		}
		if len(command) == 0 {
			return nil, fmt.Errorf("RED command is required after --")
		}
		parsed.expect = expect
		parsed.expectSet = true
	case "green":
		expect, found, err := takeSingle(&options, "--expect")
		if err != nil {
			return nil, err
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(options, " "))
		}
		if len(command) == 0 {
			return nil, fmt.Errorf("GREEN command is required after --")
		}
		parsed.expect = expect
		parsed.expectSet = found
	case "check":
		parsed.expectLiteral = takeFlag(&options, "--expect-literal")
		name, found, err := takeSingle(&options, "--name")
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("missing required option: --name")
		}
		expect, hasExpect, err := takeSingle(&options, "--expect")
		if err != nil {
			return nil, err
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(options, " "))
		}
		parsed.name = name
		parsed.expect = expect
		parsed.expectSet = hasExpect
	default:
		if len(options) > 0 {
			return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(options, " "))
		}
		if len(command) == 0 {
			return nil, fmt.Errorf(
				"%s command is required after -- (o comando RED gravado no estado não é executado)",
				strings.ToUpper(action),
			)
		}
	}

	return parsed, nil
}

// auditor executa uma fase e escreve nos fluxos informados.
type auditor struct {
	out   io.Writer
	err   io.Writer
	paths workPaths
}

// reportIncomplete lista o que falta e devolve EXIT_INCOMPLETE.
func (a *auditor) reportIncomplete(items []string) int {
	fmt.Fprintf(a.err, "INCOMPLETO: faltam %d evidência(s):\n", len(items))
	for _, item := range items {
		fmt.Fprintf(a.err, "  - %s\n", item)
	}
	return ExitIncomplete
}

// reportViolations lista todas as violações e devolve EXIT_VIOLATION.
func (a *auditor) reportViolations(items []string) int {
	fmt.Fprintf(a.err, "FAIL: %d violação(ões):\n", len(items))
	for _, item := range items {
		fmt.Fprintf(a.err, "  - %s\n", item)
	}
	return ExitViolation
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: task_evidence.js baseline --work NNNN|legacy --task ID [--implementation PATH...] [--tests PATH...]")
	fmt.Fprintln(writer, "       task_evidence.js red --work NNNN|legacy --task ID --expect TEXT [--expect-literal] -- COMMAND...")
	fmt.Fprintln(writer, "       task_evidence.js green --work NNNN|legacy --task ID [--expect TEXT] -- COMMAND...")
	fmt.Fprintln(writer, "       task_evidence.js verify --work NNNN|legacy --task ID -- COMMAND...")
	fmt.Fprintln(writer, "       task_evidence.js check --work NNNN|legacy --task ID --name NAME [--expect TEXT] [--expect-literal] -- COMMAND...")
	fmt.Fprintln(writer, "O comando após `--` é sempre obrigatório e precisa ser o declarado no plano: o harness nunca executa comandos lidos do repositório.")
}

// Main executa uma fase do audit e devolve o código de saída.
func Main(argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		usage(stderr)
	}
	parsed, err := parseArgs(argv)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL: %s\n", err)
		return ExitViolation
	}
	runner := &auditor{out: stdout, err: stderr, paths: parsed.paths}
	code, err := runner.dispatch(parsed)
	if err != nil {
		var incomplete *incompleteError
		if errors.As(err, &incomplete) {
			return runner.reportIncomplete(incomplete.items)
		}
		fmt.Fprintf(stderr, "FAIL: %s\n", err)
		return ExitViolation
	}
	return code
}

func (a *auditor) dispatch(args *parsedArgs) (int, error) {
	switch args.action {
	case "baseline":
		return a.baseline(args)
	case "red":
		return a.red(args)
	case "green":
		return a.green(args)
	case "check":
		return a.check(args)
	default:
		return a.verify(args)
	}
}
