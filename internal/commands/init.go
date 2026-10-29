package commands

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/passoz/pwn/internal/harness/decider"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/gitx"
)

// initUsage é o texto de `pwn init --help`.
var initUsage = strings.Join([]string{
	"pwn init                                   Inicializa o PWN no projeto e pergunta pela configuração do decisor",
	"pwn init --decider <provedor:modelo> [--decider-key-env VAR] [--decider-max-risk L0..L4] [--decider-endpoint URL]",
	"                                           Configura o decisor sem perguntar (CI, terminal sem TTY)",
	"pwn init --no-decider                      Registra que o projeto não usa decisor",
}, "\n") + "\n"

// deciderUsage é o texto de uso de `pwn decider`.
var deciderUsage = strings.Join([]string{
	"pwn decider show                           Mostra a configuração do decisor deste projeto",
	"pwn decider set [--decider <provedor:modelo>] [--decider-key-env VAR] [--decider-max-risk L0..L4] [--decider-endpoint URL|default]",
	"                                           Cria ou altera a configuração; campos omitidos mantêm o valor atual",
	"pwn decider remove                         Remove a configuração: o projeto passa a não usar decisor",
	"pwn decider log [--work NNNN]              Decisões tomadas pelo decisor, com motivos e assinatura conferida",
}, "\n")

// Init porta `pwn init` de src/commands/init.ts.
func (r *Runner) Init(args []string) int {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Fprint(r.out(), initUsage)
		return 0
	}
	repositoryRoot, ok := repositoryRootOrNil(r.rootDir())
	if !ok {
		fmt.Fprint(r.errOut(), "✗ pwn init precisa rodar dentro de um repositório Git (worktrees, diff guard e recibos dependem dele).\n")
		return 1
	}
	deciderName, deciderOK := flagValuePresent(args, "--decider")
	if hasFlag(args, "--decider") && !deciderOK {
		fmt.Fprint(r.errOut(), "✗ --decider exige <provedor>:modelo\n")
		return 1
	}
	if deciderName != "" && hasFlag(args, "--no-decider") {
		fmt.Fprint(r.errOut(), "✗ use --decider ou --no-decider, não os dois\n")
		return 1
	}

	fmt.Fprintf(r.out(), "=== [pwn init] %s ===\n", repositoryRoot)
	root, err := verify.Root()
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	previous, err := decider.ReadConfig(repositoryRoot, root)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if previous != nil {
		fmt.Fprintf(r.out(), "Configuração atual: %s\n", describeDecider(previous))
	}

	var input *decider.Input
	switch {
	case deciderName != "":
		keyEnv, keyOK := flagValuePresent(args, "--decider-key-env")
		if !keyOK {
			keyEnv = decider.DefaultKeyEnv
		}
		maxRisk, riskOK := flagValuePresent(args, "--decider-max-risk")
		if !riskOK {
			maxRisk = string(decider.DefaultMaxRisk)
		}
		input = &decider.Input{
			Decider:  deciderName,
			KeyEnv:   keyEnv,
			MaxRisk:  maxRisk,
			Endpoint: optionalFlag(args, "--decider-endpoint"),
		}
	case hasFlag(args, "--no-decider"):
		input = nil
	case stdinIsTTY(r.stdin()):
		input, err = r.askDecider(previous)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
	default:
		// Sem terminal não há a quem perguntar: nunca trava esperando entrada.
		if previous != nil {
			fmt.Fprint(r.out(), "Sem terminal e sem flags: configuração do decisor mantida.\n")
			return 0
		}
		fmt.Fprintf(r.errOut(), "⚠  Sem terminal para perguntar pelo decisor: projeto registrado sem decisor. Para configurar: pwn init --decider %s\n", decider.DefaultDecider)
		input = nil
	}

	config, err := decider.WriteConfig(repositoryRoot, input, root)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(r.out(), "✓ %s\n", describeDecider(config))
	fmt.Fprintf(r.out(), "  gravado fora do repositório, em %s/deciders/\n", root)
	if config.Enabled && os.Getenv(config.KeyEnv) == "" {
		fmt.Fprintf(r.errOut(), "⚠  $%s não está definida nesta sessão: sem ela, cada decisão vai para a fila humana.\n", config.KeyEnv)
	}
	return 0
}

// Decider porta `pwn decider <ação>` de src/commands/init.ts.
func (r *Runner) Decider(action string, args []string) int {
	repositoryRoot, ok := repositoryRootOrNil(r.rootDir())
	if !ok {
		fmt.Fprint(r.errOut(), "✗ pwn decider precisa rodar dentro de um repositório Git.\n")
		return 1
	}
	root, err := verify.Root()
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	code, err := r.deciderAction(repositoryRoot, root, action, args)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	return code
}

// deciderAction executa uma ação do comando decider.
func (r *Runner) deciderAction(repositoryRoot, root, action string, args []string) (int, error) {
	switch action {
	case "show":
		config, err := decider.ReadConfig(repositoryRoot, root)
		if err != nil {
			return 0, err
		}
		if config == nil {
			fmt.Fprint(r.out(), "nenhuma configuração: rode 'pwn decider set' ou 'pwn init'\n")
			return 0, nil
		}
		fmt.Fprint(r.out(), describeDecider(config)+"\n")
		return 0, nil

	case "set":
		previous, err := decider.ReadConfig(repositoryRoot, root)
		if err != nil {
			return 0, err
		}
		var current *decider.Config
		if previous != nil && previous.Enabled {
			current = previous
		}
		deciderName, deciderOK := flagValuePresent(args, "--decider")
		if !deciderOK && current != nil {
			deciderName = current.Decider
		}
		if deciderName == "" {
			return 0, fmt.Errorf("não há decisor configurado: informe --decider <provedor:modelo>")
		}

		keyEnv, keyOK := flagValuePresent(args, "--decider-key-env")
		if !keyOK && current != nil {
			keyEnv = current.KeyEnv
		}
		if keyEnv == "" {
			keyEnv = decider.DefaultKeyEnv
		}
		maxRisk, riskOK := flagValuePresent(args, "--decider-max-risk")
		if !riskOK && current != nil {
			maxRisk = string(current.MaxRisk)
		}
		if maxRisk == "" {
			maxRisk = string(decider.DefaultMaxRisk)
		}
		var endpoint *string
		if raw, ok := flagValuePresent(args, "--decider-endpoint"); ok {
			if raw != "default" {
				value := raw
				endpoint = &value
			}
		} else if current != nil {
			endpoint = current.Endpoint
		}

		config, err := decider.WriteConfig(repositoryRoot, &decider.Input{
			Decider:  deciderName,
			KeyEnv:   keyEnv,
			MaxRisk:  maxRisk,
			Endpoint: endpoint,
		}, root)
		if err != nil {
			return 0, err
		}
		fmt.Fprintf(r.out(), "✓ %s\n", describeDecider(config))
		if config.Enabled && os.Getenv(config.KeyEnv) == "" {
			fmt.Fprintf(r.errOut(), "⚠  $%s não está definida nesta sessão: sem ela, cada decisão vai para a fila humana.\n", config.KeyEnv)
		}
		return 0, nil

	case "remove":
		removed, err := decider.RemoveConfig(repositoryRoot, root)
		if err != nil {
			return 0, err
		}
		if removed {
			fmt.Fprint(r.out(), "✓ configuração removida: o projeto não usa decisor\n")
			return 0, nil
		}
		fmt.Fprint(r.out(), "nenhuma configuração para remover\n")
		return 0, nil

	case "log":
		workID := flagValue(args, "--work")
		project, err := decider.ProjectIdentity(repositoryRoot)
		if err != nil {
			return 0, err
		}
		records, err := decider.ListDecisions(project, root)
		if err != nil {
			return 0, err
		}
		printed := 0
		for _, record := range records {
			if workID != "" && record.WorkID != workID {
				continue
			}
			printed++
			tokens := ""
			if record.Usage != nil {
				tokens = fmt.Sprintf(", %d+%d tokens", record.Usage.InputTokens, record.Usage.OutputTokens)
			}
			signature := "ASSINATURA INVÁLIDA"
			if decider.DecisionSignatureValid(record, root) {
				signature = "assinatura ok"
			}
			action := ""
			if record.Action != nil {
				action = " (" + *record.Action + ")"
			}
			fmt.Fprintf(r.out(), "%s  %s %s/%s  %s%s\n",
				record.CreatedAt, padEnd(string(record.Point), 7), record.WorkID, record.TaskID, record.Outcome, action)
			model := record.Decider
			if record.Model != nil {
				model = *record.Model
			}
			fmt.Fprintf(r.out(), "  %s — %s%s, %s\n", record.DecisionID, model, tokens, signature)
			for _, reason := range record.Reasons {
				fmt.Fprintf(r.out(), "  · %s\n", reason)
			}
		}
		if printed == 0 {
			fmt.Fprint(r.out(), "nenhuma decisão registrada\n")
		}
		return 0, nil

	default:
		shown := action
		if shown == "" {
			shown = "(vazia)"
		}
		fmt.Fprintf(r.errOut(), "Ação desconhecida para 'pwn decider': %s\n\nUso:\n%s\n", shown, deciderUsage)
		return 1, nil
	}
}

// describeDecider descreve a configuração para o operador.
func describeDecider(config *decider.Config) string {
	if !config.Enabled {
		return "sem decisor: as decisões do operador continuam com você"
	}
	text := fmt.Sprintf("decisor %s (chave em $%s, teto de risco %s", config.Decider, config.KeyEnv, config.MaxRisk)
	if config.Endpoint != nil {
		text += ", endpoint " + *config.Endpoint
	}
	return text + ")"
}

// askDecider pergunta a configuração ao operador no terminal.
func (r *Runner) askDecider(previous *decider.Config) (*decider.Input, error) {
	reader := bufio.NewReader(r.stdin())
	// Fim de entrada vale o padrão; as linhas que chegam antes de cada pergunta
	// (colagem, pipe) são consumidas na ordem.
	question := func(text, fallback string) (string, error) {
		fmt.Fprintf(r.out(), "%s [%s]: ", text, fallback)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if errors.Is(err, io.EOF) && line == "" {
			fmt.Fprint(r.out(), "\n")
			return fallback, nil
		}
		value := strings.TrimSpace(line)
		if value == "" {
			return fallback, nil
		}
		return value, nil
	}

	var current *decider.Config
	if previous != nil && previous.Enabled {
		current = previous
	}

	enabledFallback := "n"
	if previous != nil && previous.Enabled {
		enabledFallback = "s"
	}
	answer, err := question("Usar um modelo decisor no lugar do operador? (s/n)", enabledFallback)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(answer) {
	case "s", "sim", "y", "yes":
	default:
		return nil, nil
	}

	deciderFallback := decider.DefaultDecider
	if current != nil {
		deciderFallback = current.Decider
	} else if value, ok := os.LookupEnv(decider.HostDeciderEnv); ok {
		deciderFallback = strings.TrimSpace(value)
	}
	deciderName, err := question("Decisor (<provedor>:<modelo>)", deciderFallback)
	if err != nil {
		return nil, err
	}

	keyEnvFallback := decider.DefaultKeyEnv
	maxRiskFallback := string(decider.DefaultMaxRisk)
	var endpoint *string
	if current != nil {
		keyEnvFallback = current.KeyEnv
		maxRiskFallback = string(current.MaxRisk)
		endpoint = current.Endpoint
	}
	keyEnv, err := question("Variável de ambiente com a chave da API", keyEnvFallback)
	if err != nil {
		return nil, err
	}
	maxRisk, err := question("Teto de risco decidido pelo modelo; acima dele a decisão volta para você", maxRiskFallback)
	if err != nil {
		return nil, err
	}

	valid, err := decider.ValidateInput(decider.Input{
		Decider:  deciderName,
		KeyEnv:   keyEnv,
		MaxRisk:  maxRisk,
		Endpoint: endpoint,
	})
	if err != nil {
		return nil, err
	}
	return &decider.Input{
		Decider:  valid.Decider,
		KeyEnv:   valid.KeyEnv,
		MaxRisk:  string(valid.MaxRisk),
		Endpoint: valid.Endpoint,
	}, nil
}

// stdin devolve a entrada padrão do handler.
func (r *Runner) stdin() io.Reader {
	if r.Stdin != nil {
		return r.Stdin
	}
	return os.Stdin
}

// stdinIsTTY informa se a entrada é um terminal, como process.stdin.isTTY.
func stdinIsTTY(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	return isTerminal(file)
}

// optionalFlag devolve o ponteiro do valor da flag, ou nil quando ausente.
func optionalFlag(args []string, name string) *string {
	value, ok := flagValuePresent(args, name)
	if !ok {
		return nil
	}
	return &value
}

// repositoryRootOrNil devolve a raiz Git do diretório, como
// `git rev-parse --show-toplevel`.
func repositoryRootOrNil(dir string) (string, bool) {
	result, err := gitx.New(dir).Run(contextBackground(), []string{"rev-parse", "--show-toplevel"}, gitx.Options{})
	if err != nil || result.Exit != 0 {
		return "", false
	}
	root := strings.TrimSpace(string(result.Stdout))
	if root == "" {
		return "", false
	}
	return root, true
}
