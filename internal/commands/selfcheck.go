package commands

import (
	"fmt"
	"strings"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/gates"
)

// SelfCheck porta `pwn self-check [--mutate [--work NNNN]]`.
//
// Sem --mutate, valida os documentos normativos do framework. Com --mutate,
// roda o mutation testing dos gates sobre o Work indicado ou o mais recente.
func (r *Runner) SelfCheck(args []string) int {
	if hasFlag(args, "--mutate") {
		return r.mutationCheck(args)
	}

	fmt.Fprint(r.out(), "=== [pwn self-check] Validador dos documentos normativos do framework ===\n\n")
	results := assets.ValidateAllCoreNormatives(r.rootDir())
	errorsCount := r.printResults(results)
	r.printSummary(len(results), errorsCount)
	return exitForErrors(errorsCount)
}

// mutationCheck roda o mutation testing determinístico dos gates: cada mutação
// viola um artefato numa cópia temporária do Work e o relatório mostra quais
// gates bloqueiam a violação.
func (r *Runner) mutationCheck(args []string) int {
	rootDir := r.rootDir()
	explicitWork := flagValue(args, "--work")
	workID := explicitWork
	if workID == "" {
		latest, err := latestWorkID(rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		workID = latest
	}

	fmt.Fprint(r.out(), "=== [pwn self-check --mutate] Mutation testing dos gates do harness ===\n\n")

	if explicitWork != "" {
		ids, err := existingWorkIDs(rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		if !containsString(ids, workID) {
			fmt.Fprintf(r.errOut(), "Work %s não encontrado em .pwn/work/.\n", workID)
			return 1
		}
	}

	options := gates.RunMutationsOptions{WorkID: workID, RootDir: rootDir}
	fmt.Fprintf(r.out(), "Baseline: %s\n\n", gates.DescribeBaseline(options))

	cases := gates.MutationCases()
	results := gates.RunMutations(options)
	expectedDetected := make([]gates.MutationResult, 0, len(results))
	for _, result := range results {
		expectation, ok := findMutationCase(cases, result.ID)
		if ok && expectation.ExpectBlocked {
			expectedDetected = append(expectedDetected, result)
		}

		advisory := ""
		if ok && !expectation.ExpectBlocked {
			advisory = " (advisory)"
		}
		mark := "✗"
		outcome := "NÃO DETECTADO"
		if result.Detected {
			mark = "✓"
			outcome = "detectado"
		}
		fmt.Fprintf(r.out(), "%s %s — %s — %s%s — %s\n", mark, result.ID, result.Gate, outcome, advisory, result.Detail)
	}

	detected := 0
	for _, result := range results {
		if result.Detected {
			detected++
		}
	}
	fmt.Fprintf(r.out(), "\n=== RESUMO: %d/%d mutações detectadas ===\n", detected, len(results))

	advisoryGates := make([]string, 0)
	for _, result := range results {
		expectation, ok := findMutationCase(cases, result.ID)
		if !result.Detected && ok && !expectation.ExpectBlocked {
			advisoryGates = append(advisoryGates, result.Gate)
		}
	}
	if len(advisoryGates) > 0 {
		fmt.Fprintf(r.out(), "Gates decorativos (mutação aceita como advisory): %s\n", strings.Join(advisoryGates, ", "))
	}

	allExpectedDetected := len(expectedDetected) > 0
	for _, result := range expectedDetected {
		if !result.Detected {
			allExpectedDetected = false
			break
		}
	}
	if !allExpectedDetected {
		missed := make([]string, 0, len(expectedDetected))
		for _, result := range expectedDetected {
			if !result.Detected {
				missed = append(missed, result.ID)
			}
		}
		joined := strings.Join(missed, ", ")
		if joined == "" {
			joined = "(nenhuma declarada)"
		}
		fmt.Fprintf(r.errOut(), "Esperava detecção nas mutações bloqueantes: %s\n", joined)
	}

	if allExpectedDetected {
		return 0
	}
	return 1
}

func findMutationCase(cases []gates.MutationCase, id string) (gates.MutationCase, bool) {
	for _, mutationCase := range cases {
		if mutationCase.ID == id {
			return mutationCase, true
		}
	}
	return gates.MutationCase{}, false
}
