package verify

import (
	"fmt"
	"io"
	"strings"
)

// AutoVerification é o resultado da aceitação automática logo depois de uma
// execução.
type AutoVerification struct {
	Attempted bool
	Outcome   string
	ReceiptID string
	Reason    string
}

// AfterRunOptions são as entradas de AfterRun.
type AfterRunOptions struct {
	RootDir         string
	WorkID          string
	TaskID          string
	TimeoutSeconds  int
	VerifierRootDir string
}

// AfterRun aciona a aceitação independente logo depois de uma execução.
//
// Um agente não tem como pular esta etapa: o fluxo do harness avalia assim que a
// execução termina. Sem aprovação vigente a avaliação não acontece — e o
// resultado fica explicitamente sem aceitação, nunca com um "pass" inventado.
func AfterRun(options AfterRunOptions) (AutoVerification, error) {
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return AutoVerification{}, err
	}
	approval := CurrentApproval(options.WorkID, options.TaskID, root)
	if approval == nil {
		return AutoVerification{
			Attempted: false,
			Reason: fmt.Sprintf(
				"sem aprovação de aceitação independente para %s/%s; "+
					"a execução não produz conclusão (pwn verify approve --work %s --task %s --by <nome>)",
				options.WorkID, options.TaskID, options.WorkID, options.TaskID,
			),
		}, nil
	}
	result, err := RunVerification(RunVerificationOptions{
		RootDir:         options.RootDir,
		Approval:        *approval,
		TimeoutSeconds:  options.TimeoutSeconds,
		VerifierRootDir: root,
	})
	if err != nil {
		if IsUnavailable(err) {
			return AutoVerification{Attempted: true, Outcome: "blocked", Reason: err.Error()}, nil
		}
		return AutoVerification{}, err
	}
	receipt, err := BuildReceipt(BuildReceiptOptions{Approval: *approval, Result: result, VerifierRootDir: root})
	if err != nil {
		if IsUnavailable(err) {
			return AutoVerification{Attempted: true, Outcome: "blocked", Reason: err.Error()}, nil
		}
		return AutoVerification{}, err
	}
	if _, err := StoreReceipt(receipt, options.RootDir, root); err != nil {
		return AutoVerification{}, err
	}
	return AutoVerification{Attempted: true, Outcome: receipt.Outcome, ReceiptID: receipt.ReceiptID}, nil
}

// ReportAutoVerification escreve o relatório legível do resultado.
func ReportAutoVerification(verification AutoVerification, stdout, stderr io.Writer) {
	if !verification.Attempted {
		_, _ = fmt.Fprintf(stderr, "⚠  %s\n", verification.Reason)
		return
	}
	switch verification.Outcome {
	case "pass":
		_, _ = fmt.Fprintf(stdout, "✓ Aceitação independente: PASS (recibo %s)\n", verification.ReceiptID)
	case "blocked":
		_, _ = fmt.Fprintf(stderr, "✗ Aceitação independente BLOQUEADA: %s\n", verification.Reason)
	default:
		_, _ = fmt.Fprintf(stderr, "✗ Aceitação independente: %s (recibo %s)\n", strings.ToUpper(verification.Outcome), verification.ReceiptID)
	}
}
