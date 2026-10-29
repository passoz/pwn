package decider

import (
	"fmt"

	"github.com/passoz/pwn/internal/harness/contract"
)

// Fila AFK (L4): a execução suspensa pode prosseguir? Só chega aqui com
// `max_risk: L4` no decisor. Efeito destrutivo provável nunca é aprovado pelo
// modelo: vai para o operador.

// Limiares da fila L4.
const (
	queueDestructiveMax     = 0.1
	queueMatchesMin         = 0.85
	queueRejectMatchesBelow = 0.2
)

// QueueThresholds são os limiares serializados na decisão da fila.
var QueueThresholds = map[string]any{
	"destructive_max":      queueDestructiveMax,
	"matches_min":          queueMatchesMin,
	"reject_matches_below": queueRejectMatchesBelow,
}

// QueueRequest monta o estado da fila: as tasks L4 envolvidas (contratos
// originais, não o agregado) e o comando a executar.
func QueueRequest(contracts []contract.TaskContractV4, command []string) Request {
	tasks := make([]map[string]any, 0, len(contracts))
	for _, taskContract := range contracts {
		outOfScope := taskContract.ScopeContract.OutOfScope
		if outOfScope == nil {
			outOfScope = []string{}
		}
		tasks = append(tasks, map[string]any{
			"id":           taskContract.TaskID,
			"title":        taskContract.Title,
			"risk":         taskContract.Risk,
			"scenarios":    taskContract.BehavioralContract.Scenarios,
			"invariants":   taskContract.ArchitectureContract.Invariants,
			"write_allow":  taskContract.ScopeContract.WriteAllow,
			"write_deny":   taskContract.ScopeContract.WriteDeny,
			"out_of_scope": outOfScope,
		})
	}
	return Request{
		State: map[string]any{"tasks": tasks, "command": command},
		Questions: map[string]Question{
			"destructive": {
				Type:         QuestionNoul,
				Instructions: "Executar `command` para estas tasks pode ter efeito destrutivo ou irreversível (apagar dados, migração sem volta, deploy, publicação, operação financeira, alteração de credenciais)?",
				Criteria: NoulCriteria{
					True:  "Há efeito destrutivo ou irreversível plausível",
					False: "O efeito fica restrito ao repositório e é reversível",
				},
			},
			"matches_task": {
				Type:         QuestionNoul,
				Instructions: "`command` corresponde ao que as tasks descrevem (`scenarios`) e cabe no escopo declarado (`write_allow`, `out_of_scope`)?",
			},
		},
	}
}

// QueuePolicy decide a fila L4.
var QueuePolicy = Policy{
	Point:      PointQueue,
	Thresholds: QueueThresholds,
	Judge:      judgeQueue,
}

func judgeQueue(answers map[string]Answer) Judgment {
	destructive := noulValue(answers, "destructive")
	matches := noulValue(answers, "matches_task")
	facts := fmt.Sprintf("destrutivo=%.2f, corresponde=%.2f", destructive, matches)
	if matches < queueRejectMatchesBelow {
		return Judgment{Outcome: OutcomeReject, Reasons: []string{"o comando não corresponde à task (" + facts + ")"}}
	}
	if destructive < queueDestructiveMax && matches > queueMatchesMin {
		return Judgment{Outcome: OutcomeApprove, Reasons: []string{facts}}
	}
	reason := fmt.Sprintf("incerto se o comando corresponde à task (%s)", facts)
	if destructive >= queueDestructiveMax {
		reason = fmt.Sprintf("efeito destrutivo possível (%s)", facts)
	}
	return Judgment{Outcome: OutcomeEscalate, Reasons: []string{reason}}
}
