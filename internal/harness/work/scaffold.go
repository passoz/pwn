package work

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
	"github.com/passoz/pwn/internal/harness/plan"
)

// DefaultAcceptance é a suíte completa usada como gate global do scaffold.
const DefaultAcceptance = "bun test"

// DefaultTypeCheck é o typecheck estrito usado como gate global do scaffold.
const DefaultTypeCheck = "bun run check"

// maxSlugLength limita o slug do título, como o `slice(0, 48)` da referência.
const maxSlugLength = 48

// ScaffoldTaskSpec é uma task explícita do scaffold: arquivos concretos e,
// opcionalmente, o escopo exato de escrita.
type ScaffoldTaskSpec struct {
	Title               string   `json:"title"`
	ImplementationFiles []string `json:"implementation_files"`
	TestFiles           []string `json:"test_files"`
	Behavior            string   `json:"behavior,omitempty"`
	// WriteAllow restringe a escrita; sem ele o contrato usa a allowlist
	// genérica do scaffold.
	WriteAllow []string `json:"write_allow,omitempty"`
	WriteDeny  []string `json:"write_deny,omitempty"`
}

// ScaffoldNarrative substitui o texto padrão de discovery/PRD.
type ScaffoldNarrative struct {
	Problem   string `json:"problem"`
	Solution  string `json:"solution"`
	Objective string `json:"objective"`
	Scenario  string `json:"scenario"`
	Author    string `json:"author"`
}

// ScaffoldOptions descreve a criação de um Work completo.
type ScaffoldOptions struct {
	RootDir    string
	Title      string
	WorkID     string
	SourcePath string
	Risk       contract.RiskLevel
	Force      bool
	Narrative  *ScaffoldNarrative
	Tasks      []ScaffoldTaskSpec
}

// SkippedFile é um artefato preservado por já existir.
type SkippedFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// ScaffoldResult é o resultado do scaffold.
type ScaffoldResult struct {
	WorkID    string        `json:"workId"`
	WorkDir   string        `json:"workDir"`
	Generated []string      `json:"generated"`
	Skipped   []SkippedFile `json:"skipped"`
	Review    []string      `json:"review"`
}

// scaffoldWriter acumula os arquivos gerados e os preservados.
type scaffoldWriter struct {
	rootDir   string
	force     bool
	generated []string
	skipped   []SkippedFile
}

// write grava content em filePath, ou registra o arquivo preservado.
func (w *scaffoldWriter) write(filePath, content string) error {
	if _, err := os.Stat(filePath); err == nil && !w.force {
		relative, err := filepath.Rel(w.rootDir, filePath)
		if err != nil {
			return fmt.Errorf("work: resolver %s: %w", filePath, err)
		}
		w.skipped = append(w.skipped, SkippedFile{
			File:   normalizeWorkPath(relative),
			Reason: "já existe (use --force para sobrescrever)",
		})
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return fmt.Errorf("work: criar diretório de %s: %w", filePath, err)
	}
	if err := writeFileAtomic(filePath, content); err != nil {
		return err
	}
	relative, err := filepath.Rel(w.rootDir, filePath)
	if err != nil {
		return fmt.Errorf("work: resolver %s: %w", filePath, err)
	}
	w.generated = append(w.generated, normalizeWorkPath(relative))
	return nil
}

// writeForce grava content ignorando a política de preservação.
func (w *scaffoldWriter) writeForce(filePath, content string) error {
	previous := w.force
	w.force = true
	err := w.write(filePath, content)
	w.force = previous
	return err
}

// writeJSON grava value como documento JSON indentado.
func (w *scaffoldWriter) writeJSON(filePath string, value any) error {
	content, err := marshalDocument(value)
	if err != nil {
		return err
	}
	return w.write(filePath, content)
}

// titleSlug é o slug determinístico do título para nomear os arquivos
// esqueleto da task.
//
// O plano nunca pode declarar diretório, glob ou placeholder — o gate de
// aceitação bloqueia — então o scaffold precisa de caminhos concretos desde o
// início.
func titleSlug(title string) string {
	var builder strings.Builder
	for _, character := range title {
		mapped := stripDiacritic(character)
		if mapped == 0 {
			continue
		}
		switch {
		case mapped >= 'A' && mapped <= 'Z':
			builder.WriteRune(mapped - 'A' + 'a')
		case (mapped >= 'a' && mapped <= 'z') || (mapped >= '0' && mapped <= '9'):
			builder.WriteRune(mapped)
		default:
			builder.WriteRune('-')
		}
	}
	slug := collapseDashes(builder.String())
	if len(slug) > maxSlugLength {
		slug = slug[:maxSlugLength]
	}
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "task"
	}
	return slug
}

// collapseDashes substitui sequências de hífens por um hífen.
func collapseDashes(value string) string {
	var builder strings.Builder
	previousDash := false
	for _, character := range value {
		if character == '-' {
			if previousDash {
				continue
			}
			previousDash = true
		} else {
			previousDash = false
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

// stripDiacritic devolve a letra sem o acento. A decomposição NFD do
// `String.prototype.normalize` do JavaScript é reproduzida pela tabela das
// letras latinas acentuadas e pelo descarte de marcas combinantes.
func stripDiacritic(character rune) rune {
	if unicode.Is(unicode.Mn, character) {
		return 0
	}
	if mapped, ok := diacriticTable[character]; ok {
		return mapped
	}
	return character
}

var diacriticTable = func() map[rune]rune {
	table := make(map[rune]rune)
	groups := []struct {
		base    rune
		accents string
	}{
		{'a', "áàâãäåāăą"},
		{'c', "çćč"},
		{'e', "éèêëēĕėęě"},
		{'i', "íìîïīĭį"},
		{'n', "ñńň"},
		{'o', "óòôõöōŏő"},
		{'s', "śšş"},
		{'u', "úùûüūŭůűų"},
		{'y', "ýÿŷ"},
		{'z', "źżž"},
	}
	for _, group := range groups {
		for _, accented := range group.accents {
			table[accented] = group.base
			table[unicode.ToUpper(accented)] = unicode.ToUpper(group.base)
		}
	}
	return table
}()

// ScaffoldContract monta o contrato V4 congelado de uma task recém-criada.
// Os comandos de aceitação dirigem a allowlist de shell do runtime.
func ScaffoldContract(workID, taskID, title string, risk contract.RiskLevel, scope *ScaffoldScope) (contract.TaskContractV4, error) {
	options := &contract.DefaultOptions{
		WriteAllow: []string{"src/**", "tests/**"},
		WriteDeny:  []string{".git/**", "package.json", ".env*"},
	}
	if scope != nil {
		options.WriteAllow = scope.WriteAllow
		options.WriteDeny = scope.WriteDeny
	}
	taskContract, err := contract.CreateDefaultContractV4(taskID, workID, title, risk, options)
	if err != nil {
		return contract.TaskContractV4{}, err
	}
	taskContract.ValidationStrategy = contract.StrategyTDDStrict
	taskContract.AcceptanceContract.Commands = []string{DefaultAcceptance, DefaultTypeCheck}
	return taskContract, nil
}

// ScaffoldScope é o escopo de escrita explícito de uma task.
type ScaffoldScope struct {
	WriteAllow []string
	WriteDeny  []string
}

// discoveryDocument é o artefato discovery.json do scaffold.
type discoveryDocument struct {
	WorkID        string   `json:"work_id"`
	Title         string   `json:"title"`
	GrillingDepth string   `json:"grilling_depth"`
	Problem       string   `json:"problem"`
	Actors        []string `json:"actors"`
	Objectives    []string `json:"objectives"`
	Constraints   []string `json:"constraints"`
	LegacySpec    string   `json:"legacy_spec,omitempty"`
	ImportedFrom  string   `json:"imported_from,omitempty"`
}

// requirementDocument é o artefato requirements.json.
type requirementDocument struct {
	WorkID       string             `json:"work_id"`
	Requirements []requirementEntry `json:"requirements"`
}

type requirementEntry struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	UserStory          string   `json:"user_story,omitempty"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
}

// prdDocument é o artefato prd.json do scaffold.
type prdDocument struct {
	Schema               string           `json:"$schema"`
	ID                   string           `json:"id"`
	Meta                 prdMeta          `json:"meta"`
	Title                string           `json:"title"`
	Status               string           `json:"status"`
	Scenario             string           `json:"scenario"`
	Problem              prdStatement     `json:"problem"`
	Solution             prdStatement     `json:"solution"`
	Decisions            []prdDecision    `json:"decisions"`
	Requirements         []prdRequirement `json:"requirements"`
	Stakeholders         []prdStakeholder `json:"stakeholders"`
	Scope                prdScope         `json:"scope"`
	AcceptedRequirements []string         `json:"accepted_requirements"`
}

type prdMeta struct {
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`
	Author    string `json:"author"`
}

type prdStatement struct {
	Statement string `json:"statement"`
}

type prdDecision struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Status    string `json:"status"`
	MadeBy    string `json:"made_by,omitempty"`
}

type prdRequirement struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Statement          string   `json:"statement"`
	AcceptanceCriteria []string `json:"acceptance_criteria,omitempty"`
}

type prdStakeholder struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type prdScope struct {
	InScope    []string `json:"in_scope"`
	OutOfScope []string `json:"out_of_scope"`
}

// specDocument é o artefato spec.json.
type specDocument struct {
	WorkID       string       `json:"work_id"`
	Title        string       `json:"title"`
	Capabilities []capability `json:"capabilities"`
	Rules        []specRule   `json:"rules"`
}

type capability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Rules       []string `json:"rules"`
}

type specRule struct {
	ID        string   `json:"id"`
	Statement string   `json:"statement"`
	Coverage  []string `json:"coverage,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
}

// traceabilityDocument é a matriz de rastreabilidade.
type traceabilityDocument struct {
	WorkID string              `json:"work_id"`
	Matrix []traceabilityEntry `json:"matrix"`
}

type traceabilityEntry struct {
	Origin        string `json:"origin"`
	RequirementID string `json:"requirement_id"`
	DecisionID    string `json:"decision_id"`
	SpecSection   string `json:"spec_section"`
	TaskID        string `json:"task_id"`
	ContractID    string `json:"contract_id"`
	EvidenceID    string `json:"evidence_id"`
	Status        string `json:"status"`
}

// nonNilSkipped devolve a lista de preservados sem nil.
func nonNilSkipped(values []SkippedFile) []SkippedFile {
	if values == nil {
		return []SkippedFile{}
	}
	return values
}

// planDocument é o plan.json com o `$schema` declarado.
type planDocument struct {
	Schema string `json:"$schema"`
	plan.Plan
}

// ScaffoldWork cria a cadeia completa do Work: discovery → requirements → prd
// → spec → plan + contrato V4 congelado + matriz de rastreabilidade + o
// markdown v3 derivado.
func ScaffoldWork(options ScaffoldOptions) (ScaffoldResult, error) {
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	title := options.Title
	if len([]rune(title)) < 5 {
		return ScaffoldResult{}, fmt.Errorf("--title deve ter ao menos 5 caracteres")
	}
	workID := options.WorkID
	if workID == "" {
		workID = GetNextWorkID(rootDir)
	}
	if !WorkIDPattern.MatchString(workID) {
		return ScaffoldResult{}, fmt.Errorf("Work ID inválido: %s (esperado quatro dígitos)", workID)
	}
	risk := options.Risk
	if risk == "" {
		risk = contract.RiskL2
	}
	if _, err := contract.BudgetForRisk(risk); err != nil {
		return ScaffoldResult{}, fmt.Errorf("work: risco do scaffold: %w", err)
	}

	// `work init` cria os modelos de discovery/requirements/prd/traceability. Um
	// Work recém-criado é nosso para preencher; um Work preexistente exige
	// --force.
	workDirPath := GetWorkArtifactsPaths(workID, rootDir).WorkDir
	_, statErr := os.Stat(workDirPath)
	if statErr != nil && !os.IsNotExist(statErr) {
		return ScaffoldResult{}, fmt.Errorf("work: inspecionar %s: %w", workDirPath, statErr)
	}
	freshWork := os.IsNotExist(statErr)
	paths, err := InitWorkDirectory(workID, rootDir)
	if err != nil {
		return ScaffoldResult{}, err
	}
	writer := &scaffoldWriter{rootDir: rootDir, force: options.Force || freshWork}
	now := nowISO()

	legacyReference := ""
	if options.SourcePath != "" {
		absolute := options.SourcePath
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(rootDir, options.SourcePath)
		}
		info, err := os.Stat(absolute)
		if err != nil || info.IsDir() {
			return ScaffoldResult{}, fmt.Errorf("--source não encontrado: %s", options.SourcePath)
		}
		data, err := os.ReadFile(absolute)
		if err != nil {
			return ScaffoldResult{}, fmt.Errorf("work: ler --source %s: %w", options.SourcePath, err)
		}
		snapshot := filepath.Join(paths.WorkDir, "legacy-spec.md")
		// O snapshot é cópia fiel: sobrescrever é obrigatório.
		if err := writer.writeForce(snapshot, string(data)); err != nil {
			return ScaffoldResult{}, err
		}
		legacyReference = "legacy-spec.md"
	}

	problem := `O projeto precisa de "` + title + `" implementado com comportamento verificável e escopo de escrita limitado por contrato.`
	solution := `Executar "` + title + `" em TDD estrito sob sandbox Git worktree, com diff guard e orçamento congelados no contrato V4.`
	objective := `Entregar "` + title + `" com critérios de aceite observáveis`
	author := "pwn-scaffold"
	scenario := "greenfield"
	if legacyReference != "" {
		scenario = "brownfield"
	}
	if options.Narrative != nil {
		if options.Narrative.Problem != "" {
			problem = options.Narrative.Problem
		}
		if options.Narrative.Solution != "" {
			solution = options.Narrative.Solution
		}
		if options.Narrative.Objective != "" {
			objective = options.Narrative.Objective
		}
		if options.Narrative.Scenario != "" {
			scenario = options.Narrative.Scenario
		}
		if options.Narrative.Author != "" {
			author = options.Narrative.Author
		}
	}

	discovery := discoveryDocument{
		WorkID:        workID,
		Title:         title,
		GrillingDepth: "medium",
		Problem:       problem,
		Actors:        []string{"ACT-001"},
		Objectives:    []string{objective},
		Constraints: []string{
			"Manter a suíte de testes existente verde (sem regressões)",
			"Permanecer dentro da write_allow do contrato V4",
		},
		LegacySpec: legacyReference,
	}
	if err := writer.writeJSON(paths.Discovery, discovery); err != nil {
		return ScaffoldResult{}, err
	}

	requirements := requirementDocument{
		WorkID: workID,
		Requirements: []requirementEntry{{
			ID:        "FR-001",
			Title:     `Implementar "` + title + `"`,
			UserStory: `Como operador, quero "` + title + `" para obter o resultado descrito no objetivo`,
			AcceptanceCriteria: []string{
				DefaultAcceptance + " — a suíte completa passa com exit 0",
				DefaultTypeCheck + " — typecheck estrito passa com exit 0",
			},
		}},
	}
	if err := writer.writeJSON(paths.Requirements, requirements); err != nil {
		return ScaffoldResult{}, err
	}

	prdProblem := problem
	if len([]rune(prdProblem)) < 20 {
		prdProblem += " (escopo mínimo)"
	}
	prdSolution := solution
	if len([]rune(prdSolution)) < 20 {
		prdSolution += " (escopo mínimo)"
	}
	prdTitle := "PRD — " + title
	if len([]rune(prdTitle)) > 100 {
		prdTitle = string([]rune(prdTitle)[:100])
	}
	prd := prdDocument{
		Schema:   "../../../schemas/prd.schema.json",
		ID:       "PRD-" + workID,
		Meta:     prdMeta{Version: "1.0", CreatedAt: now, Author: author},
		Title:    prdTitle,
		Status:   "draft",
		Scenario: scenario,
		Problem:  prdStatement{Statement: prdProblem},
		Solution: prdStatement{Statement: prdSolution},
		Decisions: []prdDecision{{
			ID:        "DEC-001",
			Statement: fmt.Sprintf("Adotar contrato V4 congelado (risco %s) como fronteira de execução do Work %s.", risk, workID),
			Status:    "accepted",
			MadeBy:    author,
		}},
		Requirements: []prdRequirement{{
			ID:        "FR-001",
			Type:      "functional",
			Statement: `Implementar "` + title + `" com critérios observáveis.`,
		}},
		Stakeholders:         []prdStakeholder{{Name: "Operador humano", Role: "ACT-001"}},
		Scope:                prdScope{InScope: []string{`Implementação de "` + title + `"`}, OutOfScope: []string{"Mudanças de infraestrutura não declaradas no contrato"}},
		AcceptedRequirements: []string{"FR-001"},
	}
	if err := writer.writeJSON(paths.PRD, prd); err != nil {
		return ScaffoldResult{}, err
	}

	spec := specDocument{
		WorkID: workID,
		Title:  title,
		Capabilities: []capability{{
			ID:          "CAP-001",
			Name:        title,
			Description: fmt.Sprintf("Capacidade entregue pelo Work %s: %s.", workID, title),
			Rules:       []string{"BR-001", "BR-002"},
		}},
		Rules: []specRule{
			{
				ID:        "BR-001",
				Statement: "A execução deve permanecer dentro da write_allow do contrato V4.",
				Coverage:  []string{"CAP-001"},
				Evidence:  "diff guard",
			},
			{
				ID:        "BR-002",
				Statement: "Nenhuma regressão: a suíte existente deve permanecer verde.",
				Coverage:  []string{"CAP-001"},
				Evidence:  DefaultAcceptance,
			},
		},
	}
	if err := writer.writeJSON(paths.Spec, spec); err != nil {
		return ScaffoldResult{}, err
	}

	slug := titleSlug(title)
	specs := options.Tasks
	if len(specs) == 0 {
		specs = []ScaffoldTaskSpec{{
			Title:               title,
			ImplementationFiles: []string{"src/" + slug + ".ts"},
			TestFiles:           []string{"tests/" + slug + ".test.ts"},
		}}
	}
	tasks := make([]plan.PlanTask, 0, len(specs))
	for index, spec := range specs {
		behavior := spec.Behavior
		if behavior == "" {
			behavior = fmt.Sprintf(`implementa "%s" com o resultado observável declarado nos critérios de aceite`, spec.Title)
		}
		focusedAcceptance := DefaultAcceptance + " " + strings.Join(spec.TestFiles, " ")
		tasks = append(tasks, plan.PlanTask{
			ID:                  fmt.Sprintf("1.%d", index+1),
			Title:               spec.Title,
			RequirementID:       "FR-001",
			DependsOn:           []string{},
			Behavior:            behavior,
			Components:          []string{"core"},
			Files:               append(append([]string{}, spec.ImplementationFiles...), spec.TestFiles...),
			ImplementationFiles: nonNil(spec.ImplementationFiles),
			TestFiles:           nonNil(spec.TestFiles),
			Red: plan.PlanRed{
				Command:     focusedAcceptance,
				Description: "a asserção do novo comportamento falha antes da implementação de " + strings.Join(spec.ImplementationFiles, ", "),
			},
			ImplementationSteps: []string{
				"Escrever o teste que falha (RED) para o comportamento declarado",
				"Implementar o mínimo para o teste passar (GREEN) e refatorar preservando a suíte verde",
			},
			AcceptanceCriteria: []plan.PlanAC{{
				Command:     focusedAcceptance,
				Description: "o comportamento declarado é observado pelo teste focado da task",
			}},
			Visual:        "N/A",
			Documentation: "N/A",
			SpecReference: "CAP-001",
			ContractID:    fmt.Sprintf("CTR-%03d", index+1),
			Complexity:    "standard",
			Status:        "pending",
		})
	}
	planValue := plan.Plan{
		WorkID: workID,
		Title:  title,
		Components: []plan.PlanComponent{{
			Name:    "core",
			Purpose: `Componente principal de "` + title + `"`,
		}},
		GlobalGates: []string{
			"`" + DefaultAcceptance + "` — a suíte completa passa com exit 0.",
			"`" + DefaultTypeCheck + "` — typecheck estrito passa com exit 0.",
		},
		Tasks: tasks,
	}
	if err := writer.writeJSON(paths.Plan, planDocument{Schema: "../../../schemas/plan.schema.json", Plan: planValue}); err != nil {
		return ScaffoldResult{}, err
	}
	for index, spec := range specs {
		var scope *ScaffoldScope
		if len(spec.WriteAllow) > 0 {
			writeDeny := spec.WriteDeny
			if len(writeDeny) == 0 {
				writeDeny = []string{".git/**", "package.json", ".env*"}
			}
			scope = &ScaffoldScope{WriteAllow: spec.WriteAllow, WriteDeny: writeDeny}
		}
		taskContract, err := ScaffoldContract(workID, fmt.Sprintf("1.%d", index+1), spec.Title, risk, scope)
		if err != nil {
			return ScaffoldResult{}, err
		}
		contractPath := filepath.Join(paths.WorkDir, fmt.Sprintf("CTR-%03d.json", index+1))
		if err := writer.writeJSON(contractPath, taskContract); err != nil {
			return ScaffoldResult{}, err
		}
	}

	traceability := traceabilityDocument{WorkID: workID, Matrix: make([]traceabilityEntry, 0, len(specs))}
	for index := range specs {
		traceability.Matrix = append(traceability.Matrix, traceabilityEntry{
			Origin:        "DISC-001",
			RequirementID: "FR-001",
			DecisionID:    "DEC-001",
			SpecSection:   "CAP-001",
			TaskID:        fmt.Sprintf("1.%d", index+1),
			ContractID:    fmt.Sprintf("CTR-%03d", index+1),
			EvidenceID:    fmt.Sprintf("EVD-%03d", index+1),
			Status:        "planned",
		})
	}
	if err := writer.writeJSON(paths.TraceabilityMatrix, traceability); err != nil {
		return ScaffoldResult{}, err
	}

	// Markdown v3 derivado (a fonte canônica continua sendo plan.json).
	markdownPath := plan.TasksMarkdownPath(workID, rootDir)
	if err := writer.write(markdownPath, plan.RenderTasksMarkdown(planValue)); err != nil {
		return ScaffoldResult{}, err
	}
	relativeMarkdown, err := filepath.Rel(rootDir, markdownPath)
	if err != nil {
		return ScaffoldResult{}, fmt.Errorf("work: resolver %s: %w", markdownPath, err)
	}
	relativeMarkdown = normalizeWorkPath(relativeMarkdown)

	review := make([]string, 0, 4)
	if len(options.Tasks) == 0 {
		review = append(review, fmt.Sprintf(
			"Renomeie os arquivos esqueleto da task 1.1 (%s, %s) para os nomes reais do módulo e do teste — o audit congela exatamente o que o plano declarar.",
			specs[0].ImplementationFiles[0], specs[0].TestFiles[0]))
	}
	review = append(review,
		fmt.Sprintf("Revise %s: o RED/AC de cada task apontam para o teste focado dela; a suíte e o typecheck ficam nos gates globais.", relativeMarkdown),
		fmt.Sprintf("O risco congelado é %s; ajuste com --risk se a mudança for mais sensível.", risk))
	if gates.FrozenTestsRequired(risk) && len(options.Tasks) == 0 {
		review = append(review, fmt.Sprintf(
			"Risco %s: comite o teste de aceitação e rode 'pwn work contract --work %s --task 1.1 --freeze-tests %s' ANTES da implementação — o gate GATE-PLAN-CONTRACT bloqueia até os testes estarem congelados.",
			risk, workID, specs[0].TestFiles[0]))
	}
	workDirRelative, err := filepath.Rel(rootDir, paths.WorkDir)
	if err != nil {
		return ScaffoldResult{}, fmt.Errorf("work: resolver %s: %w", paths.WorkDir, err)
	}
	return ScaffoldResult{
		WorkID:    workID,
		WorkDir:   normalizeWorkPath(workDirRelative),
		Generated: nonNil(writer.generated),
		Skipped:   nonNilSkipped(writer.skipped),
		Review:    review,
	}, nil
}
