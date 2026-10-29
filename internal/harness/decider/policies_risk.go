package decider

import (
	"fmt"

	"github.com/passoz/pwn/internal/harness/contract"
)

// `--risk auto`: o decisor só SOBE o risco determinístico, nunca rebaixa, e
// nunca atribui L4 (L4 suspende a execução: continua sendo escolha deliberada do
// operador).

// Limiares da elevação de risco.
const (
	riskConfidenceMin = 0.7
	riskCeiling       = contract.RiskL3
)

// RiskThresholds são os limiares serializados na decisão de risco.
var RiskThresholds = map[string]any{"confidence_min": riskConfidenceMin, "ceiling": string(riskCeiling)}

var riskOptions = ChoiceCriteria{
	"L1": "Só documentação, comentários ou formatação; sem mudança de comportamento",
	"L2": "Mudança de comportamento comum, sem superfície sensível",
	"L3": "Superfície sensível: autenticação, autorização, sessão, credenciais, pagamentos, dados pessoais, criptografia, webhooks, migração de dados",
}

// RiskTask é uma task avaliada para elevação de risco.
type RiskTask struct {
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	Files         []string           `json:"files"`
	Deterministic contract.RiskLevel `json:"deterministic"`
}

func riskQuestionID(taskID string) string { return "risk:" + taskID }

// RiskRequest monta o estado e as perguntas da elevação de risco.
func RiskRequest(tasks []RiskTask) Request {
	projected := make([]map[string]any, 0, len(tasks))
	questions := make(map[string]Question, len(tasks))
	for _, task := range tasks {
		projected = append(projected, map[string]any{
			"id":          task.ID,
			"title":       task.Title,
			"description": task.Description,
			"files":       task.Files,
		})
		questions[riskQuestionID(task.ID)] = Question{
			Type:         QuestionChoice,
			Instructions: fmt.Sprintf("Qual o nível de risco da task de id `%s` em `tasks`?", task.ID),
			Criteria:     riskOptions,
		}
	}
	return Request{State: map[string]any{"tasks": projected}, Questions: questions}
}

// RiskRaise é uma elevação aplicável: escolha acima do determinístico, até L3,
// com confiança mínima.
type RiskRaise struct {
	TaskID     string             `json:"task"`
	From       contract.RiskLevel `json:"from"`
	To         contract.RiskLevel `json:"to"`
	Confidence float64            `json:"confidence"`
}

// RiskRaises devolve as elevações aplicáveis. Função pura.
func RiskRaises(answers map[string]Answer, tasks []RiskTask) []RiskRaise {
	raises := make([]RiskRaise, 0, len(tasks))
	for _, task := range tasks {
		answer, ok := answers[riskQuestionID(task.ID)]
		if !ok || answer.Confidence == nil || *answer.Confidence < riskConfidenceMin {
			continue
		}
		chosen := contract.RiskLevel(answer.Choice)
		if chosen.Rank() > task.Deterministic.Rank() && chosen.Rank() >= 0 && chosen.Rank() <= riskCeiling.Rank() {
			raises = append(raises, RiskRaise{TaskID: task.ID, From: task.Deterministic, To: chosen, Confidence: *answer.Confidence})
		}
	}
	return raises
}

// RiskPolicy devolve a política de elevação de risco para um conjunto de tasks.
func RiskPolicy(tasks []RiskTask) Policy {
	return Policy{
		Point:      PointRisk,
		Thresholds: RiskThresholds,
		Judge: func(answers map[string]Answer) Judgment {
			raises := RiskRaises(answers, tasks)
			if len(raises) == 0 {
				return Judgment{Outcome: OutcomeApprove, Reasons: []string{"nenhuma elevação: risco determinístico mantido"}}
			}
			action := ""
			reasons := make([]string, 0, len(raises))
			for index, raise := range raises {
				if index > 0 {
					action += ", "
				}
				action += fmt.Sprintf("%s:%s→%s", raise.TaskID, raise.From, raise.To)
				reasons = append(reasons, fmt.Sprintf("task %s: risco elevado de %s para %s (confiança %.2f)", raise.TaskID, raise.From, raise.To, raise.Confidence))
			}
			return Judgment{Outcome: OutcomeApprove, Action: &action, Reasons: reasons}
		},
	}
}
