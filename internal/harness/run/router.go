package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/fsx"
)

// AgentRole é o papel do agente que executa a task.
type AgentRole string

const (
	RoleCheap  AgentRole = "cheap"
	RoleStrong AgentRole = "strong"
	RoleReview AgentRole = "review"
	RolePlan   AgentRole = "plan"
)

// ReasoningEffort é o esforço de raciocínio pedido ao modelo.
type ReasoningEffort string

const (
	EffortOff    ReasoningEffort = "off"
	EffortLow    ReasoningEffort = "low"
	EffortMedium ReasoningEffort = "medium"
	EffortHigh   ReasoningEffort = "high"
)

// ModelRoutingConfig é a configuração de um papel.
type ModelRoutingConfig struct {
	Role            AgentRole       `json:"role"`
	DefaultModel    string          `json:"defaultModel"`
	MaxTokens       int             `json:"maxTokens"`
	Temperature     float64         `json:"temperature"`
	ReasoningEffort ReasoningEffort `json:"reasoningEffort,omitempty"`
	BaseURL         string          `json:"baseUrl,omitempty"`
	Provider        string          `json:"provider,omitempty"`
	APIKeyEnv       string          `json:"apiKeyEnv,omitempty"`
	APIKey          string          `json:"apiKey,omitempty"`
}

// ExecutionPolicy separa a escolha do modelo das permissões. Um modelo barato
// numa task de risco alto continua com permissões restritas.
type ExecutionPolicy struct {
	CanWrite       bool `json:"canWrite"`
	CanShell       bool `json:"canShell"`
	CanNetwork     bool `json:"canNetwork"`
	MaxFileWrites  int  `json:"maxFileWrites"`
	RequiresReview bool `json:"requiresReview"`
}

// DefaultRoutingTable é a tabela base de modelos por papel.
var DefaultRoutingTable = map[AgentRole]ModelRoutingConfig{
	RoleCheap: {
		Role:            RoleCheap,
		DefaultModel:    "qwen3.5:27b",
		MaxTokens:       4000,
		Temperature:     0.2,
		ReasoningEffort: EffortLow,
	},
	RoleStrong: {
		Role:            RoleStrong,
		DefaultModel:    "claude-3-7-sonnet",
		MaxTokens:       16000,
		Temperature:     0.1,
		ReasoningEffort: EffortHigh,
	},
	RoleReview: {
		Role:            RoleReview,
		DefaultModel:    "claude-3-5-haiku",
		MaxTokens:       8000,
		Temperature:     0.1,
		ReasoningEffort: EffortLow,
	},
	RolePlan: {
		Role:            RolePlan,
		DefaultModel:    "claude-3-7-sonnet",
		MaxTokens:       12000,
		Temperature:     0.2,
		ReasoningEffort: EffortMedium,
	},
}

// RiskRole é o papel inicial e a exigência de revisão de um nível de risco.
type RiskRole struct {
	InitialRole    AgentRole
	RequiresReview bool
}

// RiskRoleMap mapeia risco → papel inicial.
//
// L0-L1: execução barata. L2: barata com revisão obrigatória. L3: forte.
// L4: forte com revisão humana; nunca totalmente autônomo.
var RiskRoleMap = map[contract.RiskLevel]RiskRole{
	contract.RiskL0: {InitialRole: RoleCheap, RequiresReview: false},
	contract.RiskL1: {InitialRole: RoleCheap, RequiresReview: false},
	contract.RiskL2: {InitialRole: RoleCheap, RequiresReview: true},
	contract.RiskL3: {InitialRole: RoleStrong, RequiresReview: false},
	contract.RiskL4: {InitialRole: RoleStrong, RequiresReview: true},
}

// RiskExecutionPolicy são as permissões por nível de risco. Risco mais alto
// restringe mais, mesmo quando o modelo é poderoso.
var RiskExecutionPolicy = map[contract.RiskLevel]ExecutionPolicy{
	contract.RiskL0: {CanWrite: true, CanShell: true, CanNetwork: true, MaxFileWrites: 50, RequiresReview: false},
	contract.RiskL1: {CanWrite: true, CanShell: true, CanNetwork: true, MaxFileWrites: 30, RequiresReview: false},
	contract.RiskL2: {CanWrite: true, CanShell: true, CanNetwork: false, MaxFileWrites: 20, RequiresReview: true},
	contract.RiskL3: {CanWrite: true, CanShell: false, CanNetwork: false, MaxFileWrites: 10, RequiresReview: false},
	contract.RiskL4: {CanWrite: false, CanShell: false, CanNetwork: false, MaxFileWrites: 0, RequiresReview: true},
}

// RoutingPatch é uma sobrescrita parcial de um papel. Campo nil não altera a
// tabela vigente.
type RoutingPatch struct {
	DefaultModel    *string          `json:"defaultModel,omitempty"`
	MaxTokens       *int             `json:"maxTokens,omitempty"`
	Temperature     *float64         `json:"temperature,omitempty"`
	ReasoningEffort *ReasoningEffort `json:"reasoningEffort,omitempty"`
	BaseURL         *string          `json:"baseUrl,omitempty"`
	Provider        *string          `json:"provider,omitempty"`
	APIKeyEnv       *string          `json:"apiKeyEnv,omitempty"`
	APIKey          *string          `json:"apiKey,omitempty"`
}

// routingTableJSON preserva a ordem dos papéis do arquivo do original.
type routingTableJSON struct {
	Cheap  ModelRoutingConfig `json:"cheap"`
	Strong ModelRoutingConfig `json:"strong"`
	Review ModelRoutingConfig `json:"review"`
	Plan   ModelRoutingConfig `json:"plan"`
}

type routingFileJSON struct {
	Cheap  *RoutingPatch `json:"cheap"`
	Strong *RoutingPatch `json:"strong"`
	Review *RoutingPatch `json:"review"`
	Plan   *RoutingPatch `json:"plan"`
}

// GetRoutingTable resolve a tabela efetiva: defaults, `.pwn/routing.json` e
// variáveis de ambiente, nesta ordem.
func GetRoutingTable(rootDir string) map[AgentRole]ModelRoutingConfig {
	table := cloneRoutingTable(DefaultRoutingTable)

	configPath := filepath.Join(resolveRoutingRoot(rootDir), ".pwn", "routing.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var file routingFileJSON
		// JSON corrompido é ignorado, como no original.
		if json.Unmarshal(data, &file) == nil {
			applyPatch(table, RoleCheap, file.Cheap)
			applyPatch(table, RoleStrong, file.Strong)
			applyPatch(table, RoleReview, file.Review)
			applyPatch(table, RolePlan, file.Plan)
		}
	}

	applyRoutingEnv(table)
	return table
}

func resolveRoutingRoot(rootDir string) string {
	if rootDir != "" {
		return rootDir
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func applyPatch(table map[AgentRole]ModelRoutingConfig, role AgentRole, patch *RoutingPatch) {
	if patch == nil {
		return
	}
	current := table[role]
	if patch.DefaultModel != nil && *patch.DefaultModel != "" {
		current.DefaultModel = *patch.DefaultModel
	}
	if patch.MaxTokens != nil && *patch.MaxTokens != 0 {
		current.MaxTokens = *patch.MaxTokens
	}
	if patch.Temperature != nil {
		current.Temperature = *patch.Temperature
	}
	if patch.ReasoningEffort != nil {
		current.ReasoningEffort = *patch.ReasoningEffort
	}
	if patch.BaseURL != nil {
		current.BaseURL = *patch.BaseURL
	}
	if patch.Provider != nil {
		current.Provider = *patch.Provider
	}
	if patch.APIKeyEnv != nil {
		current.APIKeyEnv = *patch.APIKeyEnv
	}
	if patch.APIKey != nil {
		current.APIKey = *patch.APIKey
	}
	table[role] = current
}

func applyRoutingEnv(table map[AgentRole]ModelRoutingConfig) {
	roles := []AgentRole{RoleCheap, RoleStrong, RoleReview, RolePlan}
	suffixes := map[AgentRole]string{
		RoleCheap:  "CHEAP",
		RoleStrong: "STRONG",
		RoleReview: "REVIEW",
		RolePlan:   "PLAN",
	}
	for _, role := range roles {
		suffix := suffixes[role]
		current := table[role]
		if value := os.Getenv("PWN_MODEL_" + suffix); value != "" {
			current.DefaultModel = value
		}
		if value := os.Getenv("PWN_API_BASE_URL_" + suffix); value != "" {
			current.BaseURL = value
		}
		if value := os.Getenv("PWN_API_KEY_" + suffix); value != "" {
			current.APIKey = value
		}
		if value := os.Getenv("PWN_REASONING_" + suffix); value != "" {
			current.ReasoningEffort = ReasoningEffort(value)
		}
		table[role] = current
	}
}

func cloneRoutingTable(source map[AgentRole]ModelRoutingConfig) map[AgentRole]ModelRoutingConfig {
	cloned := make(map[AgentRole]ModelRoutingConfig, len(source))
	for role, config := range source {
		cloned[role] = config
	}
	return cloned
}

// SaveRoutingConfig grava a tabela efetiva com as sobrescritas aplicadas em
// `.pwn/routing.json`, criando o diretório quando necessário.
func SaveRoutingConfig(newConfig map[AgentRole]RoutingPatch, rootDir string) error {
	root := resolveRoutingRoot(rootDir)
	pwnDir := filepath.Join(root, ".pwn")
	if err := os.MkdirAll(pwnDir, 0o755); err != nil {
		return fmt.Errorf("routing: criar %s: %w", pwnDir, err)
	}

	table := GetRoutingTable(root)
	for role, patch := range newConfig {
		patchCopy := patch
		applyPatch(table, role, &patchCopy)
	}

	document := routingTableJSON{
		Cheap:  table[RoleCheap],
		Strong: table[RoleStrong],
		Review: table[RoleReview],
		Plan:   table[RolePlan],
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("routing: serializar configuração: %w", err)
	}
	configPath := filepath.Join(pwnDir, "routing.json")
	if err := fsx.WriteFileAtomic(configPath, string(data)); err != nil {
		return err
	}
	return nil
}

// RoutingDecision é a escolha de papel, modelo e permissões para um risco.
type RoutingDecision struct {
	Role            AgentRole
	Model           ModelRoutingConfig
	ExecutionPolicy ExecutionPolicy
	RequiresReview  bool
	Reason          string
}

// SelectForRisk escolhe o papel inicial e a política de execução pelo risco.
func SelectForRisk(riskLevel contract.RiskLevel, rootDir string) RoutingDecision {
	riskRole, present := RiskRoleMap[riskLevel]
	if !present {
		riskRole = RiskRoleMap[contract.RiskL3]
		riskLevel = contract.RiskL3
	}
	executionPolicy, present := RiskExecutionPolicy[riskLevel]
	if !present {
		executionPolicy = RiskExecutionPolicy[contract.RiskL3]
	}
	table := GetRoutingTable(rootDir)
	model := table[riskRole.InitialRole]

	return RoutingDecision{
		Role:            riskRole.InitialRole,
		Model:           model,
		ExecutionPolicy: executionPolicy,
		RequiresReview:  riskRole.RequiresReview,
		Reason: fmt.Sprintf(
			"Risk %s → role %q (review: %t)", riskLevel, riskRole.InitialRole, riskRole.RequiresReview,
		),
	}
}

// EscalationDecision é o veredicto de escalação.
type EscalationDecision struct {
	ShouldEscalate bool
	TargetRole     AgentRole
	Reason         string
}

// EvaluateEscalation decide se a execução deve escalar. riskLevel vazio
// significa "não informado", como o parâmetro opcional do original.
func EvaluateEscalation(
	currentRole AgentRole,
	attempts, maxAttempts int,
	hasWriteViolation, hasContractViolation bool,
	riskLevel contract.RiskLevel,
) EscalationDecision {
	if riskLevel == contract.RiskL4 {
		return EscalationDecision{
			ShouldEscalate: true,
			TargetRole:     RoleReview,
			Reason:         "Risk L4: requer revisão humana — nunca totalmente autônomo",
		}
	}
	if hasWriteViolation {
		return EscalationDecision{
			ShouldEscalate: true,
			TargetRole:     RoleStrong,
			Reason:         "Violação mecânica de allowlist de escrita detectada",
		}
	}
	if hasContractViolation {
		return EscalationDecision{
			ShouldEscalate: true,
			TargetRole:     RoleStrong,
			Reason:         "Violação de invariante ou contrato arquitetural detectada",
		}
	}
	if attempts >= maxAttempts && currentRole == RoleCheap {
		return EscalationDecision{
			ShouldEscalate: true,
			TargetRole:     RoleStrong,
			Reason:         fmt.Sprintf("Tentativas esgotadas (%d/%d) para agente 'cheap'", attempts, maxAttempts),
		}
	}
	if riskLevel == contract.RiskL3 && attempts >= 1 && currentRole == RoleCheap {
		return EscalationDecision{
			ShouldEscalate: true,
			TargetRole:     RoleStrong,
			Reason:         "Risk L3: primeira falha já aciona modelo forte",
		}
	}
	return EscalationDecision{ShouldEscalate: false, TargetRole: currentRole}
}
