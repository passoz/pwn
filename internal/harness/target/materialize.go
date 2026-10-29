package target

import (
	"fmt"
	"os"
	"path/filepath"
)

const piAgentsHeader = "# Regras do Pi Harness (Pi Target)\n\n" +
	"> Configuração materializada via `pwn target materialize --target pi`\n\n" +
	"## Invariantes Globais\n" +
	"- **Precedência**: Seguir AGENTS.md e especificações normativas JSON.\n" +
	"- **Segurança**: Respeitar allowlist de escrita de arquivos.\n" +
	"- **Validação**: Conclusão só com a atestação do audit — siga o protocolo abaixo.\n"

const openCodeAgentsHeader = "# OpenCode Agents Rulebook\n\n" +
	"> Materializado via `pwn target materialize --target opencode`\n\n" +
	"## Regras Globais\n" +
	"- Respeitar contratos contratuais V4 de tarefas.\n" +
	"- Modificações Restritas à allowlist declarada.\n" +
	"- Conclusão só com a atestação do audit — siga o protocolo abaixo.\n"

const ompAgentsHeader = "# Regras do omp (oh my pi)\n\n" +
	"> Configuração materializada via `pwn target materialize --target omp`\n\n" +
	"## Invariantes Globais\n" +
	"- **Precedência**: Seguir AGENTS.md e especificações normativas JSON.\n" +
	"- **Segurança**: Respeitar allowlist de escrita de arquivos.\n" +
	"- **Validação**: Conclusão só com a atestação do audit — siga o protocolo abaixo.\n"

const rawPromptHeader = "# PWN Raw Model Prompt\n\n" +
	"> Materializado via `pwn target materialize --target raw`\n\n" +
	"## Invariantes Globais\n" +
	"- **Precedência**: Seguir o contrato V4 e as especificações normativas JSON.\n" +
	"- **Segurança**: Respeitar allowlist de escrita de arquivos.\n" +
	"- **Validação**: Conclusão só com a atestação do audit — siga o protocolo abaixo.\n"

const openCodeConfigJSON = `{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "edit": "allow",
    "bash": "allow"
  }
}`

const ompConfigYAML = "# Materializado via `pwn target materialize --target omp`\n" +
	"# Instale copiando este arquivo para <raiz-do-repo>/.omp/config.yml\n" +
	"#   (ou carregue só nesta execução: omp --config <caminho>)\n" +
	"# Chaves validadas contra `omp config list` (omp v18.x).\n" +
	"\n" +
	"# Sessões headless (`omp --print`) não têm UI para responder prompts: qualquer\n" +
	"# policy \"prompt\" falha fechado. O gate de escrita do PWN é o Diff Guard\n" +
	"# (write_allow/write_deny), então o approvalMode do projeto fica explícito.\n" +
	"tools:\n" +
	"  approvalMode: yolo\n"

// MaterializePi gera AGENTS.md para o Pi Agent Harness.
func MaterializePi(outDir string, context *ContractContext) (MaterializationResult, error) {
	generatedFiles := make([]string, 0, 1)
	notes := make([]string, 0, 2)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: criar %s: %w", outDir, err)
	}

	agentsPath := filepath.Join(outDir, "AGENTS.md")
	if err := os.WriteFile(agentsPath, []byte(agentsDocument(piAgentsHeader, context)), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar AGENTS.md: %w", err)
	}
	generatedFiles = append(generatedFiles, agentsPath)
	notes = append(notes, "Gerado AGENTS.md para Pi")
	notes = append(notes, "Instale copiando AGENTS.md para a raiz do projeto (pi descobre AGENTS.md e CLAUDE.md na inicialização)")

	return MaterializationResult{
		Target:                  RuntimePi,
		Success:                 true,
		UnsupportedCapabilities: DeriveUnsupportedCapabilities(RuntimePi),
		GeneratedFiles:          generatedFiles,
		Notes:                   notes,
	}, nil
}

// MaterializeOpenCode gera AGENTS.md e opencode.jsonc para o OpenCode.
func MaterializeOpenCode(outDir string, context *ContractContext) (MaterializationResult, error) {
	generatedFiles := make([]string, 0, 2)
	notes := make([]string, 0, 3)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: criar %s: %w", outDir, err)
	}

	agentsPath := filepath.Join(outDir, "AGENTS.md")
	if err := os.WriteFile(agentsPath, []byte(agentsDocument(openCodeAgentsHeader, context)), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar AGENTS.md: %w", err)
	}
	generatedFiles = append(generatedFiles, agentsPath)

	configPath := filepath.Join(outDir, "opencode.jsonc")
	if err := os.WriteFile(configPath, []byte(openCodeConfigJSON), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar opencode.jsonc: %w", err)
	}
	generatedFiles = append(generatedFiles, configPath)

	notes = append(notes, "Gerado opencode.jsonc e AGENTS.md para OpenCode")
	notes = append(notes, "Instale copiando AGENTS.md e opencode.jsonc para a raiz do projeto (ou exporte OPENCODE_CONFIG apontando para o opencode.jsonc)")
	notes = append(notes, "permission explícita: sessões headless não respondem prompts; o gate de escrita é o Diff Guard do PWN (write_allow/write_deny)")

	return MaterializationResult{
		Target:                  RuntimeOpenCode,
		Success:                 true,
		UnsupportedCapabilities: DeriveUnsupportedCapabilities(RuntimeOpenCode),
		GeneratedFiles:          generatedFiles,
		Notes:                   notes,
	}, nil
}

// MaterializeOmp gera AGENTS.md e .omp/config.yml para o omp (oh my pi).
func MaterializeOmp(outDir string, context *ContractContext) (MaterializationResult, error) {
	generatedFiles := make([]string, 0, 2)
	notes := make([]string, 0, 3)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: criar %s: %w", outDir, err)
	}

	agentsPath := filepath.Join(outDir, "AGENTS.md")
	if err := os.WriteFile(agentsPath, []byte(agentsDocument(ompAgentsHeader, context)), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar AGENTS.md: %w", err)
	}
	generatedFiles = append(generatedFiles, agentsPath)

	configDir := filepath.Join(outDir, ".omp")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: criar %s: %w", configDir, err)
	}
	configPath := filepath.Join(configDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(ompConfigYAML), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar .omp/config.yml: %w", err)
	}
	generatedFiles = append(generatedFiles, configPath)

	notes = append(notes, "Gerado AGENTS.md e .omp/config.yml para omp (oh my pi)")
	notes = append(notes, "Instale copiando AGENTS.md para a raiz do projeto e .omp/config.yml para <raiz>/.omp/config.yml")
	notes = append(notes, "tools.approvalMode: yolo no config de projeto sobrepõe a policy global do operador; use --approval-mode write para sessões interativas")

	return MaterializationResult{
		Target:                  RuntimeOmp,
		Success:                 true,
		UnsupportedCapabilities: DeriveUnsupportedCapabilities(RuntimeOmp),
		GeneratedFiles:          generatedFiles,
		Notes:                   notes,
	}, nil
}

// MaterializeRaw gera prompt.txt para um runtime de modelo cru.
//
// O runtime raw não tem tool calling nem contratos V4; o prompt registra o
// protocolo e o escopo para uso por um runtime construído pelo operador.
func MaterializeRaw(outDir string, context *ContractContext) (MaterializationResult, error) {
	generatedFiles := make([]string, 0, 1)
	notes := make([]string, 0, 2)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: criar %s: %w", outDir, err)
	}

	promptPath := filepath.Join(outDir, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte(agentsDocument(rawPromptHeader, context)), 0o644); err != nil {
		return MaterializationResult{}, fmt.Errorf("target: gerar prompt.txt: %w", err)
	}
	generatedFiles = append(generatedFiles, promptPath)

	notes = append(notes, "Gerado prompt.txt para Raw Model API")
	notes = append(notes, "Instale enviando prompt.txt como system prompt do seu runtime (sem tool calling, subagentes nem contratos V4 nativos)")

	return MaterializationResult{
		Target:                  RuntimeRaw,
		Success:                 true,
		UnsupportedCapabilities: DeriveUnsupportedCapabilities(RuntimeRaw),
		GeneratedFiles:          generatedFiles,
		Notes:                   notes,
	}, nil
}

// Materialize despacha a materialização pelo runtime.
func Materialize(runtime Runtime, outDir string, context *ContractContext) (MaterializationResult, error) {
	switch runtime {
	case RuntimePi:
		return MaterializePi(outDir, context)
	case RuntimeOpenCode:
		return MaterializeOpenCode(outDir, context)
	case RuntimeOmp:
		return MaterializeOmp(outDir, context)
	case RuntimeRaw:
		return MaterializeRaw(outDir, context)
	default:
		return MaterializationResult{}, fmt.Errorf("target: runtime desconhecido ou não suportado para materialização automática: %s", runtime)
	}
}

// agentsDocument monta o documento de prompt com o protocolo de aceitação e,
// quando existe contrato, a seção de escopo.
func agentsDocument(header string, context *ContractContext) string {
	document := header + RenderAcceptanceProtocol() + "\n"
	if context != nil {
		document += RenderScopeSection(*context)
	}
	return document + "\n"
}
