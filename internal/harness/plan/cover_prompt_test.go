package plan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
)

// writePromptFiles grava o prompt em <tmp>/<relPath> e a spec do sistema em
// <tmp>/system.md. Devolve os dois caminhos.
func writePromptFiles(t *testing.T, relPath, content string) (promptPath, systemPath string) {
	t.Helper()
	dir := t.TempDir()
	promptPath = filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(promptPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	systemPath = filepath.Join(dir, "system.md")
	if err := os.WriteFile(systemPath, []byte(systemSpecFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return promptPath, systemPath
}

func TestValidatePromptFileAccessErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nao-existe.md")
	result := plan.ValidatePrompt(missing, "")
	if len(result.Errors) != 1 || result.Errors[0] != "file not found: "+missing || result.Counts != nil {
		t.Errorf("arquivo ausente: %#v", result)
	}

	// Um diretório existe para os.Stat, mas não pode ser lido como arquivo.
	result = plan.ValidatePrompt(dir, "")
	if len(result.Errors) != 1 || result.Errors[0] != "file not found: "+dir || result.Counts != nil {
		t.Errorf("diretório no lugar do prompt: %#v", result)
	}

	promptPath, _ := writePromptFiles(t, ".prompts/0001-change.md", validPrompt())
	absent := filepath.Join(filepath.Dir(promptPath), "sem-spec.md")
	mustPromptError(t, plan.ValidatePrompt(promptPath, absent).Errors, "system spec not found: "+absent)
}

func TestValidatePromptReportsEachBrokenRule(t *testing.T) {
	const storyWithoutScenario = "### US-002 — Segunda história (P2)\n\n" +
		"**Ator:** Pessoa cadastrada.\n\n**Valor independente:** Valor próprio.\n\n**Verificação independente:** Verificação própria.\n\n"
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name: "título genérico",
			mutate: func(text string) string {
				return strings.Replace(text, "# PROMPT: Recuperação de senha", "# Recuperação", 1)
			},
			want: "missing concrete title: # PROMPT: ...",
		},
		{
			name:   "status diferente de pronto",
			mutate: func(text string) string { return strings.Replace(text, "Pronto para planejamento", "Rascunho", 1) },
			want:   "missing status: **Status:** Pronto para planejamento",
		},
		{
			name:   "Work ID ausente",
			mutate: func(text string) string { return strings.Replace(text, "**Work ID:** 0001\n", "", 1) },
			want:   "missing or invalid Work ID: **Work ID:** NNNN",
		},
		{
			name: "snapshot de origem ausente",
			mutate: func(text string) string {
				return strings.Replace(text, "**Origem:** `.sources/0001-request.md`\n", "", 1)
			},
			want: "missing canonical numbered source snapshot reference",
		},
		{
			name:   "referência à system spec ausente",
			mutate: func(text string) string { return strings.Replace(text, "**System spec:** `.specs/system.md`\n", "", 1) },
			want:   "missing system spec reference",
		},
		{
			name: "baseline ausente",
			mutate: func(text string) string {
				return strings.Replace(text, "**Baseline:** versão 1, Baseline validada\n", "", 1)
			},
			want: "missing concrete system baseline version and status",
		},
		{
			name:   "seção obrigatória ausente",
			mutate: func(text string) string { return strings.Replace(text, "## Premissas", "## Hipóteses", 1) },
			want:   "missing section: ## Premissas",
		},
		{
			name:   "seção duplicada",
			mutate: func(text string) string { return text + "\n## Escopo\n\n- Repetido.\n" },
			want:   "duplicate section: ## Escopo",
		},
		{
			name: "seção fora de ordem",
			mutate: func(text string) string {
				text = strings.Replace(text, "## Atores e valor", "## @@trocada", 1)
				text = strings.Replace(text, "## Escopo", "## Atores e valor", 1)
				return strings.Replace(text, "## @@trocada", "## Escopo", 1)
			},
			want: "section out of order: ## Escopo",
		},
		{
			name: "seção vazia",
			mutate: func(text string) string {
				return strings.Replace(text, "- **A-001:** O cadastro usa endereço de e-mail. **Impacto se falsa:** o identificador da solicitação precisa ser revisado.\n", "", 1)
			},
			want: "empty section: ## Premissas",
		},
		{
			name: "subseção ausente",
			mutate: func(text string) string {
				return strings.Replace(text, "### Funcionais", "### Requisitos funcionais", 1)
			},
			want: "missing subsection: ### Funcionais",
		},
		{
			name: "subseção duplicada",
			mutate: func(text string) string {
				return strings.Replace(text, "## Premissas", "### Inclui\n\n- Outro item.\n\n## Premissas", 1)
			},
			want: "duplicate subsection: ### Inclui",
		},
		{
			name: "sem história de usuário canônica",
			mutate: func(text string) string {
				return strings.Replace(text, "### US-001 — Recuperar acesso (P1)", "### Recuperar acesso", 1)
			},
			want: "at least one canonical user scenario is required: ### US-001 — Title (P1)",
		},
		{
			name: "sem cenário Given/When/Then",
			mutate: func(text string) string {
				return strings.ReplaceAll(strings.ReplaceAll(text, "**Given**", "Dado"), "**When**", "Quando")
			},
			want: "at least one Given/When/Then acceptance scenario with requirement references is required",
		},
		{
			name: "história sem cenário próprio",
			mutate: func(text string) string {
				return strings.Replace(text, "## Contrato observável", storyWithoutScenario+"## Contrato observável", 1)
			},
			want: "US-002 needs at least one canonical Given/When/Then acceptance scenario",
		},
		{
			name: "sem requisito funcional",
			mutate: func(text string) string {
				return strings.ReplaceAll(text, "- **FR-", "- **QR-")
			},
			want: "at least one functional requirement FR-001 is required",
		},
		{
			name:   "sem critério de sucesso",
			mutate: func(text string) string { return strings.ReplaceAll(text, "- **SC-", "- **XX-") },
			want:   "at least one success criterion SC-001 is required",
		},
		{
			name:   "sem caso de borda",
			mutate: func(text string) string { return strings.ReplaceAll(text, "- **EC-", "- **XX-") },
			want:   "at least one edge case EC-001 is required",
		},
		{
			name: "ID duplicado",
			mutate: func(text string) string {
				return strings.Replace(text, "## Critérios de sucesso", "- **EC-001:** Outro caso repetido sem sequência correta. (FR-001)\n\n## Critérios de sucesso", 1)
			},
			want: "duplicate ID: EC-001",
		},
		{
			name: "campo do delta ausente",
			mutate: func(text string) string {
				return strings.Replace(text, "- **Gaps tocados:** nenhum.\n", "", 1)
			},
			want: "Delta da system spec missing concrete field: Gaps tocados",
		},
		{
			name: "delta sem capacidades nem contratos",
			mutate: func(text string) string {
				start := strings.Index(text, "## Delta da system spec")
				end := strings.Index(text, "## Problema e resultado")
				return text[:start] + "## Delta da system spec\n\nDescrição livre.\n\n" + text[end:]
			},
			want: "delta must identify affected CAP-* capabilities or explicitly state none",
		},
		{
			name: "delta sem contratos",
			mutate: func(text string) string {
				start := strings.Index(text, "## Delta da system spec")
				end := strings.Index(text, "## Problema e resultado")
				return text[:start] + "## Delta da system spec\n\nCapacidade afetada: CAP-001.\n\n" + text[end:]
			},
			want: "delta must identify affected CON-* contracts or explicitly state none",
		},
		{
			name: "cenários sem referência a FR nem QR",
			mutate: func(text string) string {
				text = strings.Replace(text, "permite autenticação. (FR-001)", "permite autenticação. (US-001)", 1)
				return strings.Replace(text, "nenhuma senha é alterada. (FR-002)", "nenhuma senha é alterada. (US-001)", 1)
			},
			want: "acceptance scenarios must reference FR-* or QR-* IDs",
		},
		{
			name: "linha de rastreabilidade duplicada",
			mutate: func(text string) string {
				row := "| `FR-001` | `US-001`, `SC-001` | Nova senha autentica e senha anterior deixa de autenticar. |\n"
				return strings.Replace(text, row, row+row, 1)
			},
			want: "duplicate traceability row: FR-001",
		},
		{
			name: "rastreabilidade de requisito desconhecido",
			mutate: func(text string) string {
				return text + "| `FR-009` | `US-001` | Evidência específica com palavras suficientes. |\n"
			},
			want: "traceability row references unknown requirement: FR-009",
		},
		{
			name: "requisito curto demais",
			mutate: func(text string) string {
				return strings.Replace(text, "O sistema deve rejeitar uma prova inválida ou expirada sem alterar a senha atual da conta associada.", "Rejeitar prova inválida.", 1)
			},
			want: "FR-002 is too short to be reliably testable",
		},
		{
			name: "problema sem campo",
			mutate: func(text string) string {
				return strings.Replace(text, "**Problema:**", "**Tema:**", 1)
			},
			want: "Problema e resultado must contain a concrete **Problema:** field",
		},
		{
			name: "resultado esperado sem campo",
			mutate: func(text string) string {
				return strings.Replace(text, "**Resultado esperado:**", "**Saída:**", 1)
			},
			want: "Problema e resultado must contain a concrete **Resultado esperado:** field",
		},
		{
			name: "escopo sem item de inclusão",
			mutate: func(text string) string {
				return strings.Replace(text, "- Solicitação e conclusão da recuperação de senha.", "", 1)
			},
			want: "### Inclui must contain at least one concrete list item",
		},
		{
			name:   "escopo sem subseção de inclusão",
			mutate: func(text string) string { return strings.Replace(text, "### Inclui", "### Incluído", 1) },
			want:   "missing subsection: ### Inclui",
		},
		{
			name:   "contrato observável sem erros",
			mutate: func(text string) string { return strings.Replace(text, "- **Erros:**", "- **Falhas:**", 1) },
			want:   "Contrato observável missing concrete field: Erros",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := validatePromptContent(t, testCase.mutate(validPrompt()))
			if testCase.want == "" {
				if len(result.Errors) != 0 {
					t.Fatalf("erros inesperados: %q", result.Errors)
				}
				return
			}
			mustPromptError(t, result.Errors, testCase.want)
		})
	}
}

func TestValidatePromptSecondStoryHasOwnBlock(t *testing.T) {
	// A primeira história termina onde a segunda começa: os campos da segunda
	// não contam para a primeira, e a ausência na segunda é atribuída a ela.
	second := "### US-002 — Segunda história (P2)\n\n**Ator:** Pessoa.\n\n" +
		"1. **Given** um contexto, **When** algo ocorre, **Then** algo muda. (FR-001)\n\n"
	content := strings.Replace(validPrompt(), "## Contrato observável", second+"## Contrato observável", 1)
	errors := validatePromptContent(t, content).Errors
	mustPromptError(t, errors, "US-002 missing concrete field: Valor independente")
	mustPromptError(t, errors, "US-002 missing concrete field: Verificação independente")
	for _, issue := range errors {
		if strings.HasPrefix(issue, "US-001 ") {
			t.Errorf("US-001 não deveria herdar o bloco da US-002: %q", issue)
		}
	}
}

func TestValidatePromptFilenameRules(t *testing.T) {
	t.Run("caminho fora de .prompts", func(t *testing.T) {
		promptPath, systemPath := writePromptFiles(t, "docs/0001-change.md", validPrompt())
		mustPromptError(t, plan.ValidatePrompt(promptPath, systemPath).Errors, "prompt must use canonical path .prompts/NNNN-change.md: "+promptPath)
	})
	t.Run("nome sem o padrão NNNN-change", func(t *testing.T) {
		promptPath, systemPath := writePromptFiles(t, ".prompts/prompt.md", validPrompt())
		mustPromptError(t, plan.ValidatePrompt(promptPath, systemPath).Errors, "prompt must use canonical path")
	})
	t.Run("Work ID diferente do nome", func(t *testing.T) {
		promptPath, systemPath := writePromptFiles(t, ".prompts/0002-change.md", validPrompt())
		mustPromptError(t, plan.ValidatePrompt(promptPath, systemPath).Errors, "prompt filename Work ID 0002 does not match declaration 0001")
	})
	t.Run("caminho canônico não gera erro de nome", func(t *testing.T) {
		promptPath, systemPath := writePromptFiles(t, ".prompts/0001-change.md", validPrompt())
		if errors := plan.ValidatePrompt(promptPath, systemPath).Errors; len(errors) != 0 {
			t.Errorf("erros inesperados: %q", errors)
		}
	})
}

func runPromptMain(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = plan.ValidatePromptMain(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestValidatePromptMainUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"so-um.md"}, {"a.md", "b.md", "c.md"}} {
		code, stdout, stderr := runPromptMain(args...)
		if code != 2 {
			t.Errorf("args=%q: código=%d; want=2", args, code)
		}
		if stdout != "" {
			t.Errorf("args=%q: stdout deveria ficar vazio; got %q", args, stdout)
		}
		if want := "Usage: validate_prompt.js <prompt.md> <system-spec.md>\n"; stderr != want {
			t.Errorf("args=%q: stderr=%q; want=%q", args, stderr, want)
		}
	}
}

func TestValidatePromptMainPass(t *testing.T) {
	promptPath, systemPath := writePromptFiles(t, ".prompts/0001-change.md", validPrompt())
	code, stdout, stderr := runPromptMain(promptPath, systemPath)
	if code != 0 {
		t.Fatalf("código=%d; stderr=%q", code, stderr)
	}
	want := "PROMPT VALIDATION: PASS\nRequirements: 3\nScenarios: 1\nSuccess criteria: 2\n"
	if stdout != want {
		t.Errorf("stdout=%q; want=%q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr=%q", stderr)
	}
}

func TestValidatePromptMainFailureSingularAndPlural(t *testing.T) {
	t.Run("um erro usa o singular", func(t *testing.T) {
		content := strings.Replace(validPrompt(), "- **Gaps tocados:** nenhum.\n", "", 1)
		promptPath, systemPath := writePromptFiles(t, ".prompts/0001-change.md", content)
		code, stdout, stderr := runPromptMain(promptPath, systemPath)
		if code != 1 {
			t.Fatalf("código=%d; want=1", code)
		}
		if stdout != "" {
			t.Errorf("stdout=%q", stdout)
		}
		want := "PROMPT VALIDATION: FAIL (1 error)\n- Delta da system spec missing concrete field: Gaps tocados\n"
		if stderr != want {
			t.Errorf("stderr=%q; want=%q", stderr, want)
		}
	})
	t.Run("vários erros usam o plural", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nao-existe.md")
		_, systemPath := writePromptFiles(t, ".prompts/0001-change.md", validPrompt())
		code, _, stderr := runPromptMain(missing, systemPath)
		if code != 1 {
			t.Fatalf("código=%d; want=1", code)
		}
		if want := "PROMPT VALIDATION: FAIL (1 error)\n- file not found: " + missing + "\n"; stderr != want {
			t.Errorf("stderr=%q; want=%q", stderr, want)
		}
		content := strings.Replace(validPrompt(), "Pronto para planejamento", "Rascunho", 1)
		content = strings.Replace(content, "- **Gaps tocados:** nenhum.\n", "", 1)
		promptPath, systemPath := writePromptFiles(t, ".prompts/0001-change.md", content)
		code, _, stderr = runPromptMain(promptPath, systemPath)
		if code != 1 {
			t.Fatalf("código=%d; want=1", code)
		}
		if !strings.HasPrefix(stderr, "PROMPT VALIDATION: FAIL (2 errors)\n- ") {
			t.Errorf("stderr=%q", stderr)
		}
		if got := strings.Count(stderr, "\n- "); got != 2 {
			t.Errorf("itens de erro=%d; want=2", got)
		}
	})
}
