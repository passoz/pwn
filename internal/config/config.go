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
}

// Load lê o ambiente do processo e devolve a configuração tipada.
func Load() (Config, error) {
	mode, err := ParseOperator(os.Getenv(OperatorEnv))
	if err != nil {
		return Config{}, err
	}
	return Config{Operator: mode}, nil
}

// LoadWithOperator devolve a configuração com o modo vindo da linha de comando.
// Um modo diferente de OperatorUnset substitui PWN_OPERATOR e evita ler o ambiente.
func LoadWithOperator(operator OperatorMode) (Config, error) {
	if operator != OperatorUnset {
		return Config{Operator: operator}, nil
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
