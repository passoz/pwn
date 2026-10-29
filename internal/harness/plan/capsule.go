package plan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// CapsuleCheckBinding é um check exigido pela task no plano v3: nome (`AC-1`,
// `REGRESSION`, ...) e comandos autorizados.
type CapsuleCheckBinding struct {
	Name     string
	Commands []string
	Error    string
}

// CapsulePlanContext são os comandos do plano v3 que o audit exige. Sem isto a
// cápsula mostraria só a allowlist do contrato, que não é o critério de aceite.
type CapsulePlanContext struct {
	RedCommand  string
	Checks      []CapsuleCheckBinding
	GlobalGates []string
}

// ContextCapsuleOptions são as entradas de GenerateContextCapsule.
type ContextCapsuleOptions struct {
	Task               contract.TaskContractV4
	RelevantInterfaces []string
	Plan               *CapsulePlanContext
}

// renderPlanCommands emite o bloco da seção de validação do plano.
func renderPlanCommands(plan CapsulePlanContext) []string {
	lines := []string{"", "PLANO (o audit exige EXATAMENTE estes comandos):"}
	red := plan.RedCommand
	if red == "" {
		red = "(o plano não declara RED)"
	}
	lines = append(lines, "  RED:        "+red)
	if len(plan.Checks) == 0 {
		lines = append(lines, "  (o plano não declara checks de aceitação)")
	}
	for _, check := range plan.Checks {
		commands := ""
		if check.Error != "" {
			commands = "[" + check.Error + "]"
		} else {
			quoted := make([]string, len(check.Commands))
			for index, command := range check.Commands {
				quoted[index] = "`" + command + "`"
			}
			commands = strings.Join(quoted, " | ")
		}
		lines = append(lines, "  "+padEnd(check.Name, 11)+" "+commands)
	}
	gates := "(N/A)"
	if len(plan.GlobalGates) > 0 {
		quoted := make([]string, len(plan.GlobalGates))
		for index, command := range plan.GlobalGates {
			quoted[index] = "`" + command + "`"
		}
		gates = strings.Join(quoted, " | ")
	}
	lines = append(lines, "  GATES GLOBAIS: "+gates)
	return lines
}

// padEnd completa value com espaços até width, como String.padEnd.
func padEnd(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}

// optionalNumber formata um limite opcional como o TypeScript: `N/A` quando
// ausente.
func optionalNumber(value *int) string {
	if value == nil {
		return "N/A"
	}
	return strconv.Itoa(*value)
}

// optionalNumberFloat formata um limite fracionário com a forma numérica do
// JavaScript.
func optionalNumberFloat(value *float64) string {
	if value == nil {
		return "N/A"
	}
	data, err := jsonx.Insertion(*value)
	if err != nil {
		return "N/A"
	}
	return string(data)
}

// GenerateContextCapsule monta a cápsula de contexto da task.
func GenerateContextCapsule(options ContextCapsuleOptions) string {
	task := options.Task
	writeAllow := task.ScopeContract.WriteAllow
	writeDeny := task.ScopeContract.WriteDeny
	outOfScope := task.ScopeContract.OutOfScope
	frozenTests := task.AcceptanceContract.FrozenTests

	lines := []string{
		"================================================================================",
		"                      PWN TASK CONTEXT CAPSULE (v4.0)",
		"================================================================================",
		fmt.Sprintf("TASK ID:    %s (Work: %s)", task.TaskID, task.WorkID),
		"TITLE:      " + task.Title,
		"RISK LEVEL: " + string(task.Risk.Level) + " (" + strings.Join(task.Risk.Reasons, "; ") + ")",
		"STRATEGY:   " + string(task.ValidationStrategy),
		"",
		"--------------------------------------------------------------------------------",
		"1. BEHAVIORAL SCENARIOS",
		"--------------------------------------------------------------------------------",
	}

	scenarios := make([]string, len(task.BehavioralContract.Scenarios))
	for index, scenario := range task.BehavioralContract.Scenarios {
		scenarios[index] = "[" + scenario.ID + "]\nGiven: " + scenario.Given + "\nWhen:  " + scenario.When + "\nThen:  " + scenario.Then
	}
	lines = append(lines, strings.Join(scenarios, "\n\n"))

	lines = append(lines,
		"",
		"--------------------------------------------------------------------------------",
		"2. CHANGE & WRITE ALLOWLIST",
		"--------------------------------------------------------------------------------",
		"WRITE ALLOW:",
	)
	for _, path := range writeAllow {
		lines = append(lines, "  + "+path)
	}
	lines = append(lines, "", "WRITE DENY (PROHIBITED):")
	for _, path := range writeDeny {
		lines = append(lines, "  - "+path)
	}
	lines = append(lines, "", "OUT OF SCOPE:")
	if len(outOfScope) > 0 {
		for _, entry := range outOfScope {
			lines = append(lines, "  ! "+entry)
		}
	} else {
		lines = append(lines, "  (não declarado)")
	}

	lines = append(lines,
		"",
		"--------------------------------------------------------------------------------",
		"3. VALIDATION COMMANDS",
		"--------------------------------------------------------------------------------",
		"CONTRACT ALLOWLIST (o shell do sandbox só executa estes prefixos):",
	)
	for _, command := range task.AcceptanceContract.Commands {
		lines = append(lines, "  $ "+command)
	}
	lines = append(lines, "")
	if options.Plan != nil {
		// renderPlanCommands começa com uma linha vazia que substitui o
		// separador acima, como a interpolação do template TypeScript.
		lines = append(lines, renderPlanCommands(*options.Plan)[1:]...)
	}
	lines = append(lines, "FROZEN ACCEPTANCE TESTS (não editar — o audit recusa a atestação se mudarem):")
	if len(frozenTests) > 0 {
		for _, entry := range frozenTests {
			lines = append(lines, "  = "+entry.Path)
		}
	} else {
		lines = append(lines, "  (nenhum)")
	}
	lines = append(lines,
		"",
		"ACEITAÇÃO: o audit local (red/green/check) é DIAGNÓSTICO e não conclui nada.",
		"A conclusão exige o verificador independente: 'pwn verify run --work <W> --task <T>'.",
		"Você não aprova critérios nem emite o recibo: isso é ato do operador.",
		"",
		"--------------------------------------------------------------------------------",
		"4. BUDGET & ESCALATION RULES",
		"--------------------------------------------------------------------------------",
		"Max Agent Attempts:   "+strconv.Itoa(task.BudgetContract.MaxAgentAttempts),
		"Max LLM Calls:        "+optionalNumber(task.BudgetContract.MaxLLMCalls),
		"Max Tool Calls:       "+optionalNumber(task.BudgetContract.MaxToolCalls),
		"Max Shell Executions: "+optionalNumber(task.BudgetContract.MaxShellExecutions),
		"Max Duration:         "+optionalNumber(task.BudgetContract.MaxDurationMinutes)+" mins",
		"Max USD:              $"+optionalNumberFloat(task.BudgetContract.MaxCostUSD),
		"",
		"On Write Violation: "+task.EscalationContract.OnWriteViolation,
		"On Budget Exceeded:  "+task.EscalationContract.OnBudgetExceeded,
		"On Attempt Failed:   "+task.EscalationContract.OnAttemptFailed,
		"================================================================================",
	)
	return strings.Join(lines, "\n")
}
