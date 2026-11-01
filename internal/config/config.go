// Package config é a única porta de entrada para variáveis de ambiente do pwn.
// Os demais pacotes recebem os valores já tipados e não chamam os.Getenv.
package config

import (
	"fmt"
	"os"
	"strings"
)

// OperatorEnv seleciona quem decide os pontos do operador nesta execução.
const OperatorEnv = "PWN_OPERATOR"

// LogLevelEnv define o nível mínimo dos logs estruturados (debug, info, warn, error).
const LogLevelEnv = "PWN_LOG_LEVEL"

// LogStderrEnv espelha os logs estruturados em stderr quando vale 1/true.
// O padrão é falso para preservar o contrato de stdout/stderr do CLI.
const LogStderrEnv = "PWN_LOG_STDERR"

// ServeAuthEnv define o token exigido pelo painel de observabilidade.
const ServeAuthEnv = "PWN_SERVE_TOKEN"

// OperatorMode é o modo do operador para uma execução.
type OperatorMode string

const (
	// OperatorUnset mantém o padrão do projeto: o decisor decide se estiver configurado.
	OperatorUnset OperatorMode = ""
	// OperatorHuman devolve todas as decisões do operador ao humano.
	OperatorHuman OperatorMode = "human"
	// OperatorDecider exige o decisor do projeto.
	OperatorDecider OperatorMode = "decider"
)

// Config guarda a configuração lida do ambiente uma única vez por execução.
type Config struct {
	Operator OperatorMode
	// LogLevel é o nível mínimo dos logs estruturados. Vazio significa info.
	LogLevel string
	// LogStderr espelha os logs em stderr. O padrão preserva o contrato do CLI.
	LogStderr bool
	// ServeToken é o token do painel. Vazio desliga a autenticação.
	ServeToken string
}

// Load lê o ambiente do processo e devolve a configuração tipada.
func Load() (Config, error) {
	mode, err := ParseOperator(os.Getenv(OperatorEnv))
	if err != nil {
		return Config{}, err
	}
	cfg := loadNonOperator()
	cfg.Operator = mode
	return cfg, nil
}

// loadNonOperator lê os campos que não dependem do modo do operador.
func loadNonOperator() Config {
	return Config{
		LogLevel:   strings.TrimSpace(os.Getenv(LogLevelEnv)),
		LogStderr:  parseBool(os.Getenv(LogStderrEnv)),
		ServeToken: os.Getenv(ServeAuthEnv),
	}
}

// parseBool aceita as formas usadas em arquivos .env e shells.
func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// LoadWithOperator devolve a configuração com o modo vindo da linha de comando.
// Um modo diferente de OperatorUnset substitui PWN_OPERATOR e evita ler o ambiente.
func LoadWithOperator(operator OperatorMode) (Config, error) {
	if operator != OperatorUnset {
		cfg := loadNonOperator()
		cfg.Operator = operator
		return cfg, nil
	}
	return Load()
}

// ParseOperator converte o valor de PWN_OPERATOR. O valor vazio significa padrão
// do projeto. Espaços nas pontas são ignorados, como no CLI de referência.
func ParseOperator(raw string) (OperatorMode, error) {
	value := strings.TrimSpace(raw)
	switch value {
	case "":
		return OperatorUnset, nil
	case "human":
		return OperatorHuman, nil
	case "decider":
		return OperatorDecider, nil
	default:
		return OperatorUnset, fmt.Errorf("%s inválido: '%s' (use human ou decider)", OperatorEnv, value)
	}
}
