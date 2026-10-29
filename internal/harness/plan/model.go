// Package plan porta src/core/plan-renderer.ts, src/core/acceptance.ts,
// src/core/validate_tasks.ts, src/core/validate_prompt.ts,
// src/core/capsule.ts e src/core/task-contract.ts.
//
// O modelo canônico do plano é a única fonte de verdade: ele é renderizado no
// markdown de contrato v3 consumido pelo validador, pelos portões e pela
// auditoria. O identificador canônico da task é a forma pontuada ("1.1").
//
// O pacote não executa o harness. Ele lê e escreve os artefatos do plano e
// devolve os mesmos diagnósticos da referência TypeScript.
package plan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

// AssuranceColumn é uma coluna de garantia na ordem do contrato v3:
// [chave do modelo, cabeçalho do markdown].
type AssuranceColumn struct {
	Key    string
	Header string
}

// AssuranceColumns é a ordem canônica das colunas de garantia.
var AssuranceColumns = []AssuranceColumn{
	{Key: "root", Header: "Root"},
	{Key: "regression", Header: "Regression"},
	{Key: "lint", Header: "Lint"},
	{Key: "build", Header: "Build"},
	{Key: "security", Header: "Security"},
	{Key: "dev", Header: "Dev"},
	{Key: "health", Header: "Health"},
}

// PlanComponent é um componente do contrato de execução. As colunas de garantia
// são ponteiros para distinguir ausente de "N/A": quando qualquer componente
// declara uma coluna, o renderizador emite a tabela v3 completa.
type PlanComponent struct {
	Name       string  `json:"name"`
	Purpose    string  `json:"purpose"`
	Root       *string `json:"root,omitempty"`
	Regression *string `json:"regression,omitempty"`
	Lint       *string `json:"lint,omitempty"`
	Build      *string `json:"build,omitempty"`
	Security   *string `json:"security,omitempty"`
	Dev        *string `json:"dev,omitempty"`
	Health     *string `json:"health,omitempty"`
}

// column devolve o valor da coluna, ou nil quando ela está ausente.
func (c PlanComponent) column(key string) *string {
	switch key {
	case "root":
		return c.Root
	case "regression":
		return c.Regression
	case "lint":
		return c.Lint
	case "build":
		return c.Build
	case "security":
		return c.Security
	case "dev":
		return c.Dev
	case "health":
		return c.Health
	}
	return nil
}

// PlanRed é o comando de RED declarado na task.
type PlanRed struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// PlanAC é um critério de aceite declarado na task.
type PlanAC struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// PlanTask é uma task do plano canônico.
type PlanTask struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	RequirementID       string   `json:"requirement_id"`
	DependsOn           []string `json:"depends_on"`
	Behavior            string   `json:"behavior"`
	Components          []string `json:"components"`
	Files               []string `json:"files"`
	ImplementationFiles []string `json:"implementation_files"`
	TestFiles           []string `json:"test_files"`
	Red                 PlanRed  `json:"red"`
	ImplementationSteps []string `json:"implementation_steps"`
	AcceptanceCriteria  []PlanAC `json:"acceptance_criteria"`
	Visual              string   `json:"visual,omitempty"`
	Documentation       string   `json:"documentation,omitempty"`
	SpecReference       string   `json:"spec_reference"`
	ContractID          string   `json:"contract_id"`
	Complexity          string   `json:"complexity"`
	Status              string   `json:"status,omitempty"`
}

// Plan é o plano canônico de um Work.
type Plan struct {
	WorkID      string          `json:"work_id"`
	Title       string          `json:"title"`
	Components  []PlanComponent `json:"components"`
	GlobalGates []string        `json:"global_gates"`
	Tasks       []PlanTask      `json:"tasks"`
}

// marker devolve o marcador de estado do heading.
func marker(task PlanTask) string {
	switch task.Status {
	case "done":
		return "x"
	case "blocked":
		return "!"
	}
	return " "
}

// separator emite a linha separadora do markdown: um traço a mais de cada lado
// do cabeçalho, como o escritor v3.
func separator(headers []string) string {
	cells := make([]string, len(headers))
	for i, header := range headers {
		cells[i] = strings.Repeat("-", len(header)+2)
	}
	return "|" + strings.Join(cells, "|") + "|"
}

// codeList envolve cada valor em crase e separa por vírgula.
func codeList(values []string) string {
	wrapped := make([]string, len(values))
	for i, value := range values {
		wrapped[i] = "`" + value + "`"
	}
	return strings.Join(wrapped, ", ")
}

// RenderTasksMarkdown renderiza o plano canônico no markdown v3 consumido pelo
// validador, pelo status e pela evidência da task.
//
// A saída é determinística: o mesmo plano produz os mesmos bytes.
func RenderTasksMarkdown(plan Plan) string {
	lines := make([]string, 0, 64)

	lines = append(lines, "# Tasks: "+plan.Title)
	lines = append(lines, "")
	lines = append(lines, "**Contract version:** 3")
	lines = append(lines, "**Work ID:** "+plan.WorkID)
	lines = append(lines, "")
	lines = append(lines, "## Execution contract")
	lines = append(lines, "")

	extended := false
	for _, component := range plan.Components {
		for _, column := range AssuranceColumns {
			if component.column(column.Key) != nil {
				extended = true
				break
			}
		}
		if extended {
			break
		}
	}

	if extended {
		headers := []string{"Component"}
		for _, column := range AssuranceColumns {
			headers = append(headers, column.Header)
		}
		lines = append(lines, "| "+strings.Join(headers, " | ")+" |")
		lines = append(lines, separator(headers))
		for _, component := range plan.Components {
			cells := make([]string, len(AssuranceColumns))
			for i, column := range AssuranceColumns {
				value := "N/A"
				if cell := component.column(column.Key); cell != nil {
					value = *cell
				}
				cells[i] = "`" + value + "`"
			}
			lines = append(lines, "| "+component.Name+" | "+strings.Join(cells, " | ")+" |")
		}
	} else {
		headers := []string{"Component", "Purpose"}
		lines = append(lines, "| "+strings.Join(headers, " | ")+" |")
		lines = append(lines, separator(headers))
		for _, component := range plan.Components {
			lines = append(lines, "| `"+component.Name+"` | "+component.Purpose+" |")
		}
	}

	lines = append(lines, "")
	lines = append(lines, "## Global gates")
	for _, gate := range plan.GlobalGates {
		lines = append(lines, "- [ ] "+gate)
	}

	for _, task := range plan.Tasks {
		lines = append(lines, "")
		lines = append(lines, "### ["+marker(task)+"] ["+task.ID+"] "+task.Title)
		lines = append(lines, "")
		lines = append(lines, "**Requirement:** "+task.RequirementID)
		depends := "none"
		if len(task.DependsOn) > 0 {
			depends = strings.Join(task.DependsOn, ", ")
		}
		lines = append(lines, "**Depends on:** "+depends)
		lines = append(lines, "**Behavior:** "+task.Behavior)
		lines = append(lines, "**Components:** "+strings.Join(task.Components, ", "))
		lines = append(lines, "**Files:** "+codeList(task.Files))
		lines = append(lines, "**Implementation files:** "+codeList(task.ImplementationFiles))
		lines = append(lines, "**Test files:** "+codeList(task.TestFiles))
		lines = append(lines, "")
		lines = append(lines, "**RED:**")
		lines = append(lines, "- `"+task.Red.Command+"` — "+task.Red.Description)
		lines = append(lines, "")
		lines = append(lines, "**Implementation:**")
		for index, step := range task.ImplementationSteps {
			lines = append(lines, strconv.Itoa(index+1)+". "+step)
		}
		lines = append(lines, "")
		lines = append(lines, "**ACs:**")
		for _, ac := range task.AcceptanceCriteria {
			lines = append(lines, "- [ ] `"+ac.Command+"` — "+ac.Description)
		}
		lines = append(lines, "")
		visual := task.Visual
		if visual == "" {
			visual = "N/A"
		}
		documentation := task.Documentation
		if documentation == "" {
			documentation = "N/A"
		}
		lines = append(lines, "**Visual:** "+visual)
		lines = append(lines, "**Documentation:** "+documentation)
	}

	joined := strings.Join(lines, "\n")
	return strings.TrimRight(joined, "\n") + "\n"
}

var (
	taskHeadingMarker = regexp.MustCompile(`(?m)^### \[[ x!]\]`)
	gateMarker        = regexp.MustCompile(`(?m)^- \[[ xX!]\]`)
)

// NormalizeMarkers normaliza os marcadores de checkbox para que o estado de
// execução (marcado/bloqueado) não conte como divergência do plano.
func NormalizeMarkers(markdown string) string {
	normalized := gateMarker.ReplaceAllString(markdown, "- [ ]")
	return taskHeadingMarker.ReplaceAllString(normalized, "### [ ]")
}

// LoadPlan lê o plano canônico de um Work. Devolve nil quando o arquivo não
// existe, não é JSON ou não declara a lista de tasks.
func LoadPlan(workID, rootDir string) *Plan {
	if rootDir == "" {
		rootDir = "."
	}
	planPath := filepath.Join(rootDir, ".pwn", "work", workID, "plan.json")
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil
	}
	if plan.Tasks == nil {
		return nil
	}
	return &plan
}

// PlanMatchesMarkdown compara o plano renderizado com um markdown existente e
// ignora o estado dos checkboxes. Espaço em branco no fim do arquivo não é
// divergência de plano.
func PlanMatchesMarkdown(plan Plan, existingMarkdown string) bool {
	rendered := NormalizeMarkers(RenderTasksMarkdown(plan))
	existing := NormalizeMarkers(existingMarkdown)
	return trimEnd(rendered) == trimEnd(existing)
}

func trimEnd(value string) string {
	return strings.TrimRightFunc(value, unicode.IsSpace)
}

// TasksMarkdownPath resolve o caminho canônico do markdown de um Work.
func TasksMarkdownPath(workID, rootDir string) string {
	if rootDir == "" {
		rootDir = "."
	}
	return filepath.Join(rootDir, ".todo", workID+"-tasks.md")
}

// canonicalJSON devolve o JSON com as chaves ordenadas em todos os níveis.
func canonicalJSON(value any) string {
	data, err := jsonx.Canonical(value)
	if err != nil {
		// Os valores usados aqui são sempre serializáveis. Mantenha a função
		// total e determinística mesmo assim.
		return ""
	}
	return string(data)
}
