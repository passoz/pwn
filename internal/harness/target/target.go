// Package target materializa as especificações do PWN nos formatos nativos de
// cada runtime de agente (pi, OpenCode, omp e raw).
//
// A matriz de capacidades é a fonte única da degradação: cada runtime declara o
// que suporta, e o materializador traduz o restante sem perda silenciosa.
package target

// Runtime identifica um runtime de agente suportado.
type Runtime string

const (
	RuntimePi       Runtime = "pi"
	RuntimeOpenCode Runtime = "opencode"
	RuntimeOmp      Runtime = "omp"
	RuntimeRaw      Runtime = "raw"
)

// CapabilityFlag nomeia uma capacidade booleana da matriz.
type CapabilityFlag string

const (
	CapSupportsSystemPrompt    CapabilityFlag = "supportsSystemPrompt"
	CapSupportsSubagents       CapabilityFlag = "supportsSubagents"
	CapSupportsSkills          CapabilityFlag = "supportsSkills"
	CapSupportsToolCalling     CapabilityFlag = "supportsToolCalling"
	CapSupportsContractV4      CapabilityFlag = "supportsContractV4"
	CapSupportsWorktreeSandbox CapabilityFlag = "supportsWorktreeSandbox"
)

// Capabilities descreve o que um runtime suporta e qual arquivo ele consome.
type Capabilities struct {
	Target                  Runtime `json:"target"`
	Name                    string  `json:"name"`
	SupportsSystemPrompt    bool    `json:"supportsSystemPrompt"`
	SupportsSubagents       bool    `json:"supportsSubagents"`
	SupportsSkills          bool    `json:"supportsSkills"`
	SupportsToolCalling     bool    `json:"supportsToolCalling"`
	SupportsContractV4      bool    `json:"supportsContractV4"`
	SupportsWorktreeSandbox bool    `json:"supportsWorktreeSandbox"`
	PromptFileFormat        string  `json:"promptFileFormat"`
}

// Has informa se a capacidade declarada é suportada. Capacidade desconhecida
// nunca é suportada, como o acesso a chave ausente no TypeScript.
func (c Capabilities) Has(flag CapabilityFlag) bool {
	switch flag {
	case CapSupportsSystemPrompt:
		return c.SupportsSystemPrompt
	case CapSupportsSubagents:
		return c.SupportsSubagents
	case CapSupportsSkills:
		return c.SupportsSkills
	case CapSupportsToolCalling:
		return c.SupportsToolCalling
	case CapSupportsContractV4:
		return c.SupportsContractV4
	case CapSupportsWorktreeSandbox:
		return c.SupportsWorktreeSandbox
	default:
		return false
	}
}

// CapabilityMatrix é a matriz de capacidades por runtime.
var CapabilityMatrix = map[Runtime]Capabilities{
	RuntimePi: {
		Target:                  RuntimePi,
		Name:                    "Pi Agent Harness",
		SupportsSystemPrompt:    true,
		SupportsSubagents:       true,
		SupportsSkills:          true,
		SupportsToolCalling:     true,
		SupportsContractV4:      true,
		SupportsWorktreeSandbox: true,
		PromptFileFormat:        "AGENTS.md",
	},
	RuntimeOpenCode: {
		Target:                  RuntimeOpenCode,
		Name:                    "OpenCode Interpreter",
		SupportsSystemPrompt:    true,
		SupportsSubagents:       true,
		SupportsSkills:          true,
		SupportsToolCalling:     true,
		SupportsContractV4:      true,
		SupportsWorktreeSandbox: true,
		PromptFileFormat:        "AGENTS.md",
	},
	RuntimeOmp: {
		Target:                  RuntimeOmp,
		Name:                    "omp (oh my pi) Coding Agent",
		SupportsSystemPrompt:    true,
		SupportsSubagents:       true,
		SupportsSkills:          true,
		SupportsToolCalling:     true,
		SupportsContractV4:      true,
		SupportsWorktreeSandbox: true,
		PromptFileFormat:        "AGENTS.md",
	},
	RuntimeRaw: {
		Target:                  RuntimeRaw,
		Name:                    "Raw Model API / LLM Prompt",
		SupportsSystemPrompt:    true,
		SupportsSubagents:       false,
		SupportsSkills:          false,
		SupportsToolCalling:     false,
		SupportsContractV4:      false,
		SupportsWorktreeSandbox: false,
		PromptFileFormat:        "prompt.txt",
	},
}

// Runtimes devolve os runtimes na ordem da referência.
func Runtimes() []Runtime {
	return []Runtime{RuntimePi, RuntimeOpenCode, RuntimeOmp, RuntimeRaw}
}

// CapabilityFlags lista as capacidades verificáveis, na ordem da referência.
var CapabilityFlags = []CapabilityFlag{
	CapSupportsSystemPrompt,
	CapSupportsSubagents,
	CapSupportsSkills,
	CapSupportsToolCalling,
	CapSupportsContractV4,
	CapSupportsWorktreeSandbox,
}

// DeriveUnsupportedCapabilities deriva a degradação da matriz. Runtime
// desconhecido não degrada nada, como no TypeScript.
func DeriveUnsupportedCapabilities(runtime Runtime) []string {
	caps, ok := CapabilityMatrix[runtime]
	unsupported := make([]string, 0, len(CapabilityFlags))
	if !ok {
		return unsupported
	}
	for _, flag := range CapabilityFlags {
		if !caps.Has(flag) {
			unsupported = append(unsupported, string(flag))
		}
	}
	return unsupported
}

// SupportCheck é o resultado da validação de capacidades exigidas.
type SupportCheck struct {
	Valid   bool
	Missing []string
}

// ValidateTargetSupport valida se o runtime satisfaz as capacidades exigidas.
func ValidateTargetSupport(runtime Runtime, required []CapabilityFlag) SupportCheck {
	caps, ok := CapabilityMatrix[runtime]
	if !ok {
		return SupportCheck{Valid: false, Missing: []string{"Target desconhecido: " + string(runtime)}}
	}
	missing := make([]string, 0, len(required))
	for _, req := range required {
		if !caps.Has(req) {
			missing = append(missing, string(req))
		}
	}
	return SupportCheck{Valid: len(missing) == 0, Missing: missing}
}

// MaterializationResult descreve o que foi gerado e o que degradou.
type MaterializationResult struct {
	Target                  Runtime  `json:"target"`
	Success                 bool     `json:"success"`
	UnsupportedCapabilities []string `json:"unsupportedCapabilities"`
	GeneratedFiles          []string `json:"generatedFiles"`
	Notes                   []string `json:"notes"`
}
