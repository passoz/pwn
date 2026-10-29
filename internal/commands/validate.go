package commands

import (
	"fmt"

	"github.com/passoz/pwn/internal/assets"
)

// Validate porta `pwn validate [--work NNNN]`.
//
// Com Work, valida os documentos do Work. Sem Work, valida todos os Works
// existentes e, na ausência deles, valida os documentos core do framework.
func (r *Runner) Validate(args []string) int {
	workID := flagValue(args, "--work")
	rootDir := r.rootDir()

	if workID != "" {
		fmt.Fprintf(r.out(), "=== [pwn validate] Validador de Documentos do Work %s ===\n\n", workID)
		results := assets.ValidateWorkDocuments(workID, rootDir)
		if len(results) == 0 {
			fmt.Fprintf(r.out(), "Nenhum documento com schema encontrado em .pwn/work/%s/.\n", workID)
			return 0
		}
		errorsCount := r.printResults(results)
		r.printSummary(len(results), errorsCount)
		return exitForErrors(errorsCount)
	}

	ids, err := existingWorkIDs(rootDir)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if len(ids) > 0 {
		fmt.Fprint(r.out(), "=== [pwn validate] Validador de Documentos dos Works do projeto ===\n\n")
		total := 0
		errorsCount := 0
		for _, id := range ids {
			results := assets.ValidateWorkDocuments(id, rootDir)
			total += len(results)
			errorsCount += r.printResults(results)
		}
		r.printSummary(total, errorsCount)
		return exitForErrors(errorsCount)
	}

	// Repositório do framework, sem Works: valida os documentos core.
	fmt.Fprint(r.out(), "=== [pwn validate] Validador de Documentos Normativos JSON ===\n\n")
	results := assets.ValidateAllCoreNormatives(rootDir)
	errorsCount := r.printResults(results)
	r.printSummary(len(results), errorsCount)
	return exitForErrors(errorsCount)
}

// printSummary escreve a linha final do relatório de validação.
func (r *Runner) printSummary(total, errorsCount int) {
	fmt.Fprintf(r.out(), "\n=== RESUMO: %d/%d arquivos válidos, %d erros ===\n", total-errorsCount, total, errorsCount)
}

func exitForErrors(errorsCount int) int {
	if errorsCount > 0 {
		return 1
	}
	return 0
}
