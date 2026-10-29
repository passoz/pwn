package commands

import (
	"fmt"
	"path/filepath"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/target"
)

// Target porta `pwn target list` e `pwn target materialize`.
func (r *Runner) Target(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.targetList()
	case "materialize":
		return r.targetMaterialize(args)
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn target': %s\n", subcommand)
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn target list                           Exibe a matriz de capacidades\n")
		fmt.Fprint(r.out(), "  pwn target materialize --target <target>  Materializa artefatos no diretório target\n")
		return 1
	}
}

// targetList escreve a matriz de capacidades de cada runtime.
func (r *Runner) targetList() int {
	fmt.Fprint(r.out(), "=== [pwn target list] Runtimes e Matriz de Capacidades ===\n\n")
	for _, runtime := range target.Runtimes() {
		caps := target.CapabilityMatrix[runtime]
		fmt.Fprintf(r.out(), "• Target: %s (%s)\n", upper(string(caps.Target)), caps.Name)
		fmt.Fprintf(r.out(), "  System Prompt:       %s\n", mark(caps.SupportsSystemPrompt))
		fmt.Fprintf(r.out(), "  Subagents:           %s\n", mark(caps.SupportsSubagents))
		fmt.Fprintf(r.out(), "  Skills:              %s\n", mark(caps.SupportsSkills))
		fmt.Fprintf(r.out(), "  Tool Calling:        %s\n", mark(caps.SupportsToolCalling))
		fmt.Fprintf(r.out(), "  Contratos V4:        %s\n", mark(caps.SupportsContractV4))
		fmt.Fprintf(r.out(), "  Worktree Sandbox:    %s\n", mark(caps.SupportsWorktreeSandbox))
		fmt.Fprintf(r.out(), "  Formato Principal:   %s\n\n", caps.PromptFileFormat)
	}
	return 0
}

// targetMaterialize gera os artefatos do runtime pedido. O contexto de contrato
// é derivado dos contratos V4 congelados quando --work é informado.
func (r *Runner) targetMaterialize(args []string) int {
	rootDir := r.rootDir()
	targetName := flagValue(args, "--target")
	if targetName == "" {
		targetName = "pi"
	}

	workID := flagValue(args, "--work")

	outDir := flagValue(args, "--out")
	if outDir == "" {
		outDir = filepath.Join(rootDir, ".pwn", "targets", targetName)
	}

	fmt.Fprintf(r.out(), "=== [pwn target materialize] Materializando artefatos para %s ===\n", upper(targetName))

	var context *target.ContractContext
	if workID != "" {
		loaded, err := plan.LoadWorkContracts(workID, rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ Não foi possível carregar contratos do Work %s: %s\n", workID, err.Error())
			return 1
		}
		collected := target.CollectContractContext(dereferenceContracts(loaded))
		context = &collected
		fmt.Fprintf(r.out(), "✓ Escopo derivado de %d contrato(s) do Work %s (risco %s).\n", context.TaskCount, workID, context.RiskLevel)
	}

	var (
		result target.MaterializationResult
		err    error
	)
	switch target.Runtime(targetName) {
	case target.RuntimePi, target.RuntimeOpenCode, target.RuntimeOmp:
		result, err = target.Materialize(target.Runtime(targetName), outDir, context)
	default:
		fmt.Fprintf(r.errOut(), "Target desconhecido ou não suportado para materialização automática: %s\n", targetName)
		return 1
	}
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ Materialização falhou: %s\n", err.Error())
		return 1
	}

	fmt.Fprintf(r.out(), "✓ Materialização concluída com sucesso em: %s\n", outDir)
	fmt.Fprint(r.out(), "Arquivos Gerados:\n")
	for _, file := range result.GeneratedFiles {
		fmt.Fprintf(r.out(), "  + %s\n", file)
	}

	if len(result.Notes) > 0 {
		fmt.Fprint(r.out(), "\nNotas de Adaptação:\n")
		for _, note := range result.Notes {
			fmt.Fprintf(r.out(), "  ! %s\n", note)
		}
	}

	if len(result.UnsupportedCapabilities) > 0 {
		fmt.Fprint(r.out(), "\nCapacidades Não Suportadas (Degradação Graciosa):\n")
		for _, capability := range result.UnsupportedCapabilities {
			fmt.Fprintf(r.out(), "  - %s\n", capability)
		}
	}

	return 0
}

// dereferenceContracts converte os contratos carregados do plano para o tipo
// de valor usado pelo agregador de contexto.
func dereferenceContracts(loaded []*contract.TaskContractV4) []contract.TaskContractV4 {
	contracts := make([]contract.TaskContractV4, 0, len(loaded))
	for _, taskContract := range loaded {
		if taskContract == nil {
			continue
		}
		contracts = append(contracts, *taskContract)
	}
	return contracts
}

func mark(supported bool) string {
	if supported {
		return "✓"
	}
	return "✗"
}

// upper sobe as letras ASCII sem alterar o restante, como String#toUpperCase
// para nomes de runtime.
func upper(value string) string {
	bytes := []byte(value)
	for i, char := range bytes {
		if char >= 'a' && char <= 'z' {
			bytes[i] = char - ('a' - 'A')
		}
	}
	return string(bytes)
}
