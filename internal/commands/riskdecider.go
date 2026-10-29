package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/passoz/pwn/internal/harness/batch"
	"github.com/passoz/pwn/internal/harness/decider"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
)

// deciderRisk liga o decisor do projeto à elevação de risco de `work import
// --risk auto`, como `raiseRiskByDecider` de src/core/v3-import.ts. O modelo só
// sobe o risco; sem decisor, ou indisponível, vale a heurística.
type deciderRisk struct{ rootDir string }

func (d deciderRisk) RaiseRisk(ctx context.Context, workID string, candidates []work.RiskCandidate) (work.RiskDecision, error) {
	root, err := verify.Root()
	if err != nil {
		return work.RiskDecision{}, err
	}
	tasks := make([]decider.RiskTask, 0, len(candidates))
	for _, candidate := range candidates {
		tasks = append(tasks, decider.RiskTask{
			ID:            candidate.Task,
			Title:         candidate.Title,
			Description:   candidate.Description,
			Files:         candidate.Files,
			Deterministic: candidate.Deterministic,
		})
	}
	result, err := decider.Decide(decider.DecideOptions{
		Context:      ctx,
		RootDir:      d.rootDir,
		WorkID:       workID,
		TaskID:       "WORK",
		Policy:       decider.RiskPolicy(tasks),
		VerifierRoot: root,
		Request: func() (decider.Request, error) {
			return decider.RiskRequest(tasks), nil
		},
	})
	if err != nil {
		return work.RiskDecision{}, err
	}
	if result.Kind == decider.ResultHuman {
		decision := work.RiskDecision{}
		if result.Reason != nil {
			decision.HumanReason = *result.Reason
		}
		return decision, nil
	}
	record := result.Record
	if record == nil {
		return work.RiskDecision{}, fmt.Errorf("o decisor não devolveu registro para %s/WORK", workID)
	}
	if record.Answers == nil {
		return work.RiskDecision{Unanswered: true, DecisionID: record.DecisionID, Reasons: record.Reasons}, nil
	}
	decision := work.RiskDecision{DecisionID: record.DecisionID, Reasons: record.Reasons}
	for _, raise := range decider.RiskRaises(record.Answers, tasks) {
		decision.Raises = append(decision.Raises, work.RiskRaise{
			Task:       raise.TaskID,
			From:       raise.From,
			To:         raise.To,
			Confidence: raise.Confidence,
			DecisionID: record.DecisionID,
		})
	}
	return decision, nil
}

// autoRebase refaz sobre o HEAD integrado as tasks retidas só por base
// desatualizada, quando o projeto tem decisor: o `rebase` que o operador rodaria
// à mão vira regra (autoRebase de src/commands/batch.ts). Conflito de 3-way
// continua com o agente; regressão e entrega incompleta continuam retidas.
func (r *Runner) autoRebase(ctx context.Context, result batch.IntegrationResult) {
	var rebasable []batch.HeldTask
	for _, entry := range result.Failed {
		if entry.Kind == batch.HoldClash || entry.Kind == batch.HoldStaleBase {
			rebasable = append(rebasable, entry)
		}
	}
	if len(rebasable) == 0 || len(result.Integrated) == 0 {
		return
	}
	root, err := verify.Root()
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err)
		return
	}
	governed, err := decider.Govern(r.rootDir(), decider.PointBatch, nil, root)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err)
		return
	}
	if governed.Config == nil {
		return
	}
	fmt.Fprint(r.out(), "\n[DECISOR] tasks retidas só por base desatualizada: refazendo sobre o HEAD integrado.\n")
	for _, entry := range rebasable {
		rebased, err := batch.RebaseTask(ctx, batch.RebaseOptions{Root: r.rootDir(), TaskID: entry.ID})
		if err == nil {
			conflicts := "reaplicada sem conflitos"
			if len(rebased.Conflicts) > 0 {
				conflicts = "conflitos para o agente: " + strings.Join(rebased.Conflicts, ", ")
			}
			var record decider.DecisionRecord
			record, err = decider.RecordRuleDecision(decider.RuleDecisionOptions{
				RootDir: r.rootDir(),
				WorkID:  result.WorkID,
				TaskID:  entry.ID,
				Point:   decider.PointBatch,
				Action:  "rebase",
				Reasons: []string{fmt.Sprintf("retida por %s: %s", entry.Kind, firstReason(entry.Reasons)), conflicts},
			}, root)
			if err == nil {
				for _, line := range decider.DescribeDecision(record) {
					fmt.Fprintln(r.out(), line)
				}
				printRebase(r.out(), rebased)
			}
		}
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ rebase automático de %s falhou: %s\n", entry.ID, err)
		}
	}
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0]
}
