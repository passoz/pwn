package decider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/verify"
)

// Configuração do operador-decisor de UM projeto.
//
// Vive na raiz do verificador, fora do repositório: o agente que escreve plano,
// testes e código não pode escolher quem o aprova. Presença de configuração
// habilitada liga o decisor por padrão no projeto; ausência significa que não há
// decisor. A credencial nunca é gravada: guarda-se o NOME da variável de
// ambiente que a contém.

// Providers são os provedores com adaptador conhecido.
var Providers = []string{"jev"}

// RiskLevels é a ordem crescente de risco aceita como teto do decisor.
var RiskLevels = []contract.RiskLevel{contract.RiskL0, contract.RiskL1, contract.RiskL2, contract.RiskL3, contract.RiskL4}

// Valores padrão de `decider set`.
const (
	DefaultDecider = "jev:jev-latest"
	DefaultKeyEnv  = "TYPESAFE_API_KEY"
)

// DefaultMaxRisk é o teto padrão do decisor.
const DefaultMaxRisk = contract.RiskL3

// HostDeciderEnv é o anúncio do agente hospedeiro: vira a sugestão padrão no
// `pwn init`, nunca autorização.
const HostDeciderEnv = "PWN_DECIDER"

// DecisionPoint é um ponto de decisão do operador que o decisor pode assumir.
type DecisionPoint string

// Pontos de decisão que o decisor pode assumir.
const (
	PointApprove DecisionPoint = "approve"
	PointQueue   DecisionPoint = "queue"
	PointBatch   DecisionPoint = "batch"
	PointRisk    DecisionPoint = "risk"
)

// Scopes são todos os pontos que uma configuração habilitada assume.
var Scopes = []DecisionPoint{PointApprove, PointQueue, PointBatch, PointRisk}

// Config é o conteúdo do arquivo de configuração do projeto.
type Config struct {
	Version      int                `json:"version"`
	Enabled      bool               `json:"enabled"`
	Project      string             `json:"project"`
	Decider      string             `json:"decider"`
	KeyEnv       string             `json:"key_env"`
	MaxRisk      contract.RiskLevel `json:"max_risk"`
	Scope        []DecisionPoint    `json:"scope"`
	Endpoint     *string            `json:"endpoint"`
	ConfiguredAt string             `json:"configured_at"`
}

type enabledFile struct {
	Version      int                `json:"version"`
	Enabled      bool               `json:"enabled"`
	Project      string             `json:"project"`
	Decider      string             `json:"decider"`
	KeyEnv       string             `json:"key_env"`
	MaxRisk      contract.RiskLevel `json:"max_risk"`
	Scope        []DecisionPoint    `json:"scope"`
	Endpoint     *string            `json:"endpoint"`
	ConfiguredAt string             `json:"configured_at"`
}

type disabledFile struct {
	Version      int    `json:"version"`
	Enabled      bool   `json:"enabled"`
	Project      string `json:"project"`
	ConfiguredAt string `json:"configured_at"`
}

// Input são os valores informados pelo operador em `decider set` e `init`.
type Input struct {
	Decider  string
	KeyEnv   string
	MaxRisk  string
	Endpoint *string
}

// ValidInput é a entrada depois da validação.
type ValidInput struct {
	Decider  string
	KeyEnv   string
	MaxRisk  contract.RiskLevel
	Endpoint *string
}

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
var endpointPattern = regexp.MustCompile(`^https?://[^\s]+$`)

// ValidateInput valida os valores informados pelo operador. Erro traz uma
// mensagem acionável.
func ValidateInput(input Input) (ValidInput, error) {
	decider := strings.TrimSpace(input.Decider)
	provider, model, found := strings.Cut(decider, ":")
	if !found || provider == "" || model == "" {
		return ValidInput{}, fmt.Errorf("decisor inválido: '%s' (formato <provedor>:<modelo>, ex.: %s)", decider, DefaultDecider)
	}
	if !contains(Providers, provider) {
		return ValidInput{}, fmt.Errorf("provedor de decisor sem adaptador: '%s' (disponíveis: %s)", provider, strings.Join(Providers, ", "))
	}
	keyEnv := strings.TrimSpace(input.KeyEnv)
	if !envNamePattern.MatchString(keyEnv) {
		return ValidInput{}, fmt.Errorf("nome de variável de ambiente inválido para a chave: '%s'", keyEnv)
	}
	maxRisk := contract.RiskLevel(strings.ToUpper(strings.TrimSpace(input.MaxRisk)))
	if !maxRisk.Valid() {
		return ValidInput{}, fmt.Errorf("teto de risco inválido: '%s' (use %s)", input.MaxRisk, riskLevelList())
	}
	var endpoint *string
	if input.Endpoint != nil {
		trimmed := strings.TrimSpace(*input.Endpoint)
		if trimmed != "" {
			if !endpointPattern.MatchString(trimmed) {
				return ValidInput{}, fmt.Errorf("endpoint do decisor inválido: '%s' (use http(s)://…)", trimmed)
			}
			endpoint = &trimmed
		}
	}
	return ValidInput{Decider: decider, KeyEnv: keyEnv, MaxRisk: maxRisk, Endpoint: endpoint}, nil
}

func riskLevelList() string {
	levels := make([]string, len(RiskLevels))
	for index, level := range RiskLevels {
		levels[index] = string(level)
	}
	return strings.Join(levels, ", ")
}

// ProjectIdentity devolve a raiz canônica do projeto: a mesma configuração vale
// de qualquer subdiretório ou symlink.
func ProjectIdentity(repositoryRoot string) (string, error) {
	resolved, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("decider: resolver a raiz do projeto: %w", err)
	}
	return resolved, nil
}

// ConfigPath devolve o arquivo de configuração do projeto na raiz do
// verificador.
func ConfigPath(repositoryRoot, root string) (string, error) {
	identity, err := ProjectIdentity(repositoryRoot)
	if err != nil {
		return "", err
	}
	resolved, err := resolveRoot(root)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(resolved, "deciders", hex.EncodeToString(digest[:])[:16]+".json"), nil
}

// ReadConfig lê a configuração do projeto. Devolve nil quando não existe;
// erro quando o arquivo é inválido ou pertence a outro projeto.
func ReadConfig(repositoryRoot, root string) (*Config, error) {
	file, err := ConfigPath(repositoryRoot, root)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("decider: ler a configuração: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("configuração do decisor inválida ou de outro projeto: %s", file)
	}
	identity, err := ProjectIdentity(repositoryRoot)
	if err != nil {
		return nil, err
	}
	if config.Version != 1 || config.Project != identity {
		return nil, fmt.Errorf("configuração do decisor inválida ou de outro projeto: %s", file)
	}
	return &config, nil
}

// WriteConfig grava a escolha do operador (habilitada ou explicitamente sem
// decisor) com modo 0600.
func WriteConfig(repositoryRoot string, input *Input, root string) (*Config, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	if _, err := verify.InitializeVerifierHome(resolved); err != nil {
		return nil, err
	}
	if err := verify.AssertProtectedOutsideRepository(resolved, repositoryRoot); err != nil {
		return nil, err
	}
	identity, err := ProjectIdentity(repositoryRoot)
	if err != nil {
		return nil, err
	}
	configuredAt := nowISO()
	file, err := ConfigPath(repositoryRoot, resolved)
	if err != nil {
		return nil, err
	}
	var config Config
	var encoded []byte
	if input != nil {
		valid, err := ValidateInput(*input)
		if err != nil {
			return nil, err
		}
		config = Config{
			Version:      1,
			Enabled:      true,
			Project:      identity,
			Decider:      valid.Decider,
			KeyEnv:       valid.KeyEnv,
			MaxRisk:      valid.MaxRisk,
			Scope:        append([]DecisionPoint(nil), Scopes...),
			Endpoint:     valid.Endpoint,
			ConfiguredAt: configuredAt,
		}
		encoded, err = json.MarshalIndent(enabledFile{
			Version:      config.Version,
			Enabled:      config.Enabled,
			Project:      config.Project,
			Decider:      config.Decider,
			KeyEnv:       config.KeyEnv,
			MaxRisk:      config.MaxRisk,
			Scope:        config.Scope,
			Endpoint:     config.Endpoint,
			ConfiguredAt: config.ConfiguredAt,
		}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("decider: serializar a configuração: %w", err)
		}
	} else {
		config = Config{Version: 1, Enabled: false, Project: identity, ConfiguredAt: configuredAt}
		encoded, err = json.MarshalIndent(disabledFile{
			Version:      config.Version,
			Enabled:      config.Enabled,
			Project:      config.Project,
			ConfiguredAt: config.ConfiguredAt,
		}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("decider: serializar a configuração: %w", err)
		}
	}
	if err := verify.WriteFileAtomic(file, string(encoded)+"\n", 0o600); err != nil {
		return nil, err
	}
	return &config, nil
}

// RemoveConfig remove a configuração do projeto: sem ela, não há decisor.
// Devolve se havia algo a remover.
func RemoveConfig(repositoryRoot, root string) (bool, error) {
	file, err := ConfigPath(repositoryRoot, root)
	if err != nil {
		return false, err
	}
	if err := os.Remove(file); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("decider: remover a configuração: %w", err)
	}
	return true, nil
}

// nowISO devolve o instante em UTC no formato usado pelos artefatos do pwn.
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// resolveRoot devolve a raiz informada ou a raiz padrão do verificador.
func resolveRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return verify.Root()
}
