package commands

import (
	"fmt"

	"github.com/passoz/pwn/internal/harness/decider"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
)

// deciderGatekeeper liga o decisor do projeto à fila L4 da run, como o
// `decide({ policy: queuePolicy, ... })` de src/core/run-orchestrator.ts. O
// pacote run não importa o motor de decisão; a ligação fica aqui.
type deciderGatekeeper struct{}

func (deciderGatekeeper) Decide(request run.GateRequest) run.GateDecision {
	root, err := verify.Root()
	if err != nil {
		return run.GateDecision{Err: err}
	}
	risk := request.Risk
	result, err := decider.Decide(decider.DecideOptions{
		Context:      contextBackground(),
		RootDir:      request.RootDir,
		WorkID:       request.WorkID,
		TaskID:       request.TaskID,
		Risk:         &risk,
		Policy:       decider.QueuePolicy,
		VerifierRoot: root,
		Request: func() (decider.Request, error) {
			return decider.QueueRequest(request.Contracts, request.Command), nil
		},
	})
	if err != nil {
		return run.GateDecision{Err: err}
	}
	if result.Record == nil {
		gate := run.GateDecision{Outcome: run.GateEscalate}
		if result.Kind == decider.ResultHuman && result.Reason != nil {
			gate.Log = []string{fmt.Sprintf("[DECISOR] %s", *result.Reason)}
		}
		return gate
	}
	record := result.Record
	return run.GateDecision{
		Outcome:    run.GateOutcome(record.Outcome),
		Reasons:    record.Reasons,
		DecisionID: record.DecisionID,
		Log:        decider.DescribeDecision(*record),
	}
}
