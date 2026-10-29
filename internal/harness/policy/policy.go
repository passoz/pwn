// Package policy porta src/core/policy-config.ts e src/core/policy-engine.ts.
//
// A política declarativa é OPCIONAL e vive em `.pwn/policy.json`. Arquivo
// ausente, malformado ou fora do schema nunca interrompe a execução: os
// defaults valem e a leitura devolve um aviso em vez de erro. Cada seção
// declarada é mesclada SOBRE os defaults, nunca os substitui por inteiro.
//
// O motor aplica a política antes da execução. A ordem é sempre a mesma:
// primeiro a denylist (a negação vence), depois a allowlist. Allowlist vazia
// nega tudo, salvo quando `AllowAllShell` ou `AllowAllNetwork` está ligado.
// Comandos são comparados de forma estrutural (`Comando` mais prefixo de
// `Args`); não há parsing de string de shell.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/platform/jsonschema"
)

// PolicyRelativePath é o caminho canônico do arquivo, relativo à raiz.
const PolicyRelativePath = ".pwn/policy.json"

// PolicyFilePath devolve o caminho canônico do arquivo de política.
func PolicyFilePath(rootDir string) string {
	return filepath.Join(rootDir, filepath.FromSlash(PolicyRelativePath))
}

// RiskKeywords são as palavras-chave de classificação de risco. Os nomes JSON
// seguem o arquivo em snake_case.
type RiskKeywords struct {
	L3 []string `json:"l3"`
	L1 []string `json:"l1"`
}

// GateThresholds são os limiares dos gates de traceabilidade.
type GateThresholds struct {
	MaxFindingsBeforeBlock int `json:"max_findings_before_block"`
	MaxACsPerTask          int `json:"max_acs_per_task"`
}

// GateThresholdOverrides preserva a diferença entre valor ausente e valor zero
// no arquivo declarativo.
type GateThresholdOverrides struct {
	MaxFindingsBeforeBlock *int `json:"max_findings_before_block,omitempty"`
	MaxACsPerTask          *int `json:"max_acs_per_task,omitempty"`
}

// ConfigFile é o documento já validado e normalizado para os tipos do motor.
// Um ponteiro nil em um campo indica que o campo não foi declarado no arquivo.
type ConfigFile struct {
	RiskKeywords   *RiskKeywords           `json:"risk_keywords,omitempty"`
	GateThresholds *GateThresholdOverrides `json:"gate_thresholds,omitempty"`
	Shell          *ShellPolicy            `json:"shell,omitempty"`
	Network        *NetworkPolicy          `json:"network,omitempty"`
}

// Source diz de onde veio a política efetiva.
type Source string

const (
	// SourceDefaults indica que nenhum arquivo válido foi aplicado.
	SourceDefaults Source = "defaults"
	// SourceFile indica que um arquivo válido foi mesclado sobre os defaults.
	SourceFile Source = "file"
)

// Resolved é a política efetiva: arquivo válido mesclado sobre os defaults.
type Resolved struct {
	RiskKeywords   RiskKeywords   `json:"risk_keywords"`
	GateThresholds GateThresholds `json:"gate_thresholds"`
	Shell          ShellPolicy    `json:"shell"`
	Network        NetworkPolicy  `json:"network"`
	Source         Source         `json:"source"`
}

// DefaultRiskKeywords devolve uma cópia dos defaults de `risk_keywords`.
//
// FONTE DE VERDADE ESPELHADA: as listas canônicas vivem em
// internal/harness/contract/risk.go (`riskL3Keywords` e `riskL1Keywords`) e são
// copiadas aqui LITERALMENTE. O contrato não as exporta, e importá-las criaria
// dependência circular. Mantenha as duas cópias em sincronia.
func DefaultRiskKeywords() RiskKeywords {
	return RiskKeywords{
		L3: []string{
			"auth", "autentica", "login", "signin", "signup", "password", "senha", "credencial",
			"sessao", "session", "token", "cookie", "rbac", "permissao", "autorizacao", "papel",
			"seguranca", "security", "hardening", "webhook", "hmac", "assinatura", "signature",
			"pagamento", "payment", "estorno", "refund", "crypto", "secret", "csrf", "cors",
			"rate limit", "rate-limit", "privacidade", "privacy", "lgpd", "middleware", "bcrypt",
			"argon2", "hash", "csrf", "oauth",
		},
		L1: []string{
			"readme", "documentacao", "documentation", "comentario", "formatacao", "estilo",
			"tipografia", "copy", "changelog", "licenca", "license",
		},
	}
}

// DefaultGateThresholds devolve os limiares default. Zero significa nenhum
// achado tolerado ou nenhum limite explícito.
func DefaultGateThresholds() GateThresholds {
	return GateThresholds{MaxFindingsBeforeBlock: 0, MaxACsPerTask: 0}
}

// LoadPolicyFile lê e valida `.pwn/policy.json`.
//
// Devolve nil e nenhum aviso quando o arquivo não existe. Devolve nil e um
// aviso quando o arquivo não é JSON válido ou não passa no schema; nunca
// devolve erro e nunca lança.
func LoadPolicyFile(rootDir string) (*ConfigFile, []string) {
	filePath := PolicyFilePath(rootDir)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []string{warningf(filePath, "não foi possível ler o arquivo (%v) — usando defaults", err)}
	}

	document, err := jsonschema.Decode(data)
	if err != nil {
		return nil, []string{warningf(filePath, "não é JSON válido (%v) — usando defaults", err)}
	}

	schema, err := policySchema()
	if err != nil {
		return nil, []string{warningf(filePath, "schema embutido indisponível (%v) — usando defaults", err)}
	}
	if validationErrors := schema.Validate(document); len(validationErrors) > 0 {
		return nil, []string{warningf(filePath, "fora do schema: %s — usando defaults", strings.Join(validationErrors, "; "))}
	}

	object, ok := document.(map[string]any)
	if !ok {
		// O schema exige objeto; esta guarda é inalcançável após a validação.
		return nil, []string{warningf(filePath, "documento não é um objeto — usando defaults")}
	}
	return normalizePolicyFile(object), nil
}

// ResolvePolicy resolve a política efetiva: arquivo válido mesclado sobre os
// defaults. O segundo resultado carrega avisos de arquivo inválido; nunca há
// erro, porque um arquivo de política inválido não deve interromper o trabalho.
func ResolvePolicy(rootDir string) (Resolved, []string) {
	file, warnings := LoadPolicyFile(rootDir)

	riskKeywords := DefaultRiskKeywords()
	if file != nil && file.RiskKeywords != nil {
		if file.RiskKeywords.L3 != nil {
			riskKeywords.L3 = slices.Clone(file.RiskKeywords.L3)
		}
		if file.RiskKeywords.L1 != nil {
			riskKeywords.L1 = slices.Clone(file.RiskKeywords.L1)
		}
	}

	gateThresholds := DefaultGateThresholds()
	if file != nil && file.GateThresholds != nil {
		if file.GateThresholds.MaxFindingsBeforeBlock != nil {
			gateThresholds.MaxFindingsBeforeBlock = *file.GateThresholds.MaxFindingsBeforeBlock
		}
		if file.GateThresholds.MaxACsPerTask != nil {
			gateThresholds.MaxACsPerTask = *file.GateThresholds.MaxACsPerTask
		}
	}

	shell := DefaultShellPolicy()
	if file != nil && file.Shell != nil {
		shell = cloneShell(*file.Shell)
	}

	network := DefaultNetworkPolicy()
	if file != nil && file.Network != nil {
		network = cloneNetwork(*file.Network)
	}

	source := SourceDefaults
	if file != nil {
		source = SourceFile
	}

	return Resolved{
		RiskKeywords:   riskKeywords,
		GateThresholds: gateThresholds,
		Shell:          shell,
		Network:        network,
		Source:         source,
	}, warnings
}

var (
	policySchemaOnce sync.Once
	policySchemaDoc  *jsonschema.Schema
	policySchemaErr  error
)

// policySchema compila uma única vez o schema embutido no bundle. O binário
// movido para outro diretório valida o arquivo contra a mesma lei.
func policySchema() (*jsonschema.Schema, error) {
	policySchemaOnce.Do(func() {
		data, ok := assets.Schema("policy.schema.json")
		if !ok {
			policySchemaErr = errors.New("assets: policy.schema.json ausente")
			return
		}
		policySchemaDoc, policySchemaErr = jsonschema.Compile(data)
	})
	return policySchemaDoc, policySchemaErr
}

func warningf(filePath, format string, args ...any) string {
	return fmt.Sprintf("[policy] %s "+format, append([]any{filePath}, args...)...)
}

// normalizePolicyFile converte um documento já validado para a forma tipada.
// Subcampos ausentes caem nos defaults; uma seção ausente não é preenchida.
func normalizePolicyFile(raw map[string]any) *ConfigFile {
	out := &ConfigFile{}

	if risks, ok := raw["risk_keywords"].(map[string]any); ok {
		defaults := DefaultRiskKeywords()
		out.RiskKeywords = &RiskKeywords{}
		if value, declared := risks["l3"]; declared {
			out.RiskKeywords.L3 = copyStringArray(value, defaults.L3)
		}
		if value, declared := risks["l1"]; declared {
			out.RiskKeywords.L1 = copyStringArray(value, defaults.L1)
		}
	}

	if thresholds, ok := raw["gate_thresholds"].(map[string]any); ok {
		out.GateThresholds = &GateThresholdOverrides{}
		out.GateThresholds.MaxFindingsBeforeBlock = integerOverride(thresholds["max_findings_before_block"])
		out.GateThresholds.MaxACsPerTask = integerOverride(thresholds["max_acs_per_task"])
	}

	if shell, ok := raw["shell"].(map[string]any); ok {
		defaults := DefaultShellPolicy()
		out.Shell = &ShellPolicy{
			AllowedCommands: copyCommandRules(shell["allowed_commands"], defaults.AllowedCommands),
			DeniedCommands:  copyCommandRules(shell["denied_commands"], defaults.DeniedCommands),
			AllowAllShell:   boolOrDefault(shell["allow_all_shell"], defaults.AllowAllShell),
		}
	}

	if network, ok := raw["network"].(map[string]any); ok {
		defaults := DefaultNetworkPolicy()
		out.Network = &NetworkPolicy{
			AllowedDomains:  copyStringArray(network["allowed_domains"], defaults.AllowedDomains),
			DeniedDomains:   copyStringArray(network["denied_domains"], defaults.DeniedDomains),
			AllowAllNetwork: boolOrDefault(network["allow_all_network"], defaults.AllowAllNetwork),
		}
	}

	return out
}

func copyStringArray(value any, fallback []string) []string {
	array, ok := value.([]any)
	if !ok {
		return slices.Clone(fallback)
	}
	out := make([]string, 0, len(array))
	for _, entry := range array {
		if text, ok := entry.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func copyCommandRules(value any, fallback []CommandRule) []CommandRule {
	array, ok := value.([]any)
	if !ok {
		return cloneRules(fallback)
	}
	out := make([]CommandRule, 0, len(array))
	for _, entry := range array {
		object, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		command, _ := object["command"].(string)
		rule := CommandRule{Command: command}
		if rawArgs, declared := object["args"].([]any); declared {
			rule.Args = make([]string, 0, len(rawArgs))
			for _, rawArg := range rawArgs {
				if arg, ok := rawArg.(string); ok {
					rule.Args = append(rule.Args, arg)
				}
			}
		}
		out = append(out, rule)
	}
	return out
}

func integerOverride(value any) *int {
	number, ok := value.(json.Number)
	if !ok {
		return nil
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 0)
	if err != nil {
		return nil
	}
	result := int(parsed)
	return &result
}

func boolOrDefault(value any, fallback bool) bool {
	if flag, ok := value.(bool); ok {
		return flag
	}
	return fallback
}
