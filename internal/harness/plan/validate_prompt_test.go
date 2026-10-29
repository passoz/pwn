package plan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
)

const systemSpecFixture = `# SYSTEM SPEC: Contas

**Status:** Baseline validada
**Versão:** 1

- **ACT-001 — Pessoa cadastrada:** utiliza a própria conta.
- **CAP-001:** autenticar e recuperar acesso.
- **BR-001:** somente a pessoa autorizada altera sua credencial.
- **CON-001:** autenticação e recuperação de acesso.
- **ENT-001:** conta cadastrada.
`

const validPromptTemplate = `# PROMPT: Recuperação de senha

**Status:** Pronto para planejamento
**Work ID:** 0001
**System spec:** §.specs/system.md§
**Baseline:** versão 1, Baseline validada
**Origem:** §.sources/0001-request.md§

## Delta da system spec

- **Capacidades afetadas:** §CAP-001§.
- **Regras preservadas:** §BR-001§.
- **Regras alteradas:** nenhuma.
- **Contratos afetados:** §CON-001§.
- **Qualidades, entidades e integrações relacionadas:** §ENT-001§.
- **Gaps tocados:** nenhum.
- **Reconciliação esperada após implementação:** atualizar limites da recuperação em §CAP-001§ e §CON-001§.

## Problema e resultado

**Problema:** Pessoas que esquecem a senha não conseguem recuperar o acesso sem atendimento manual.

**Resultado esperado:** Uma pessoa cadastrada consegue solicitar e concluir a recuperação sem revelar se outro endereço possui conta.

## Contexto confirmado

- §README.md§: o produto já possui autenticação por endereço de e-mail.

## Atores e valor

- **Pessoa cadastrada:** recupera o acesso à própria conta.

## Escopo

### Inclui

- Solicitação e conclusão da recuperação de senha.

### Não inclui

- Alteração do método de autenticação existente.

## Cenários de usuário

### US-001 — Recuperar acesso (P1)

**Ator:** Pessoa cadastrada.

**Valor independente:** Recupera o acesso sem atendimento manual.

**Verificação independente:** Solicitar a recuperação e definir uma nova senha válida.

**Cenários de aceitação:**

1. **Given** uma conta cadastrada, **When** a pessoa conclui uma solicitação válida, **Then** a nova senha permite autenticação. (FR-001)
2. **Given** uma solicitação inválida, **When** a pessoa tenta concluir a recuperação, **Then** nenhuma senha é alterada. (FR-002)

## Contrato observável

- **Entradas:** endereço de e-mail, prova de recuperação e nova senha.
- **Saídas e efeitos:** confirmação neutra da solicitação e alteração da senha após prova válida.
- **Erros:** prova inválida ou expirada não altera a senha nem revela dados da conta.

## Requisitos

### Funcionais

- **FR-001:** O sistema deve permitir que uma pessoa cadastrada defina uma nova senha após apresentar uma prova de recuperação válida.
- **FR-002:** O sistema deve rejeitar uma prova inválida ou expirada sem alterar a senha atual da conta associada.

### Qualidade e restrições

- **QR-001:** A resposta da solicitação deve ser indistinguível para endereços cadastrados e não cadastrados.

## Casos de borda

- **EC-001:** Uma prova reutilizada deve ser rejeitada sem alterar novamente a senha. (FR-002)

## Critérios de sucesso

- **SC-001:** Uma recuperação válida permite autenticação com a nova senha e impede autenticação com a senha anterior. (FR-001)
- **SC-002:** Solicitações para endereços existentes e inexistentes apresentam a mesma resposta observável. (QR-001)

## Premissas

- **A-001:** O cadastro usa endereço de e-mail. **Impacto se falsa:** o identificador da solicitação precisa ser revisado.

## Componentes afetados

- §README.md§ — contrato de autenticação confirmado.
- Detalhe ainda desconhecido — descobrir no repositório durante §/make-todo§ sem presumir arquitetura.

## Rastreabilidade

| Requisito | Cobertura | Evidência esperada |
|-----------|-----------|--------------------|
| §FR-001§ | §US-001§, §SC-001§ | Nova senha autentica e senha anterior deixa de autenticar. |
| §FR-002§ | §US-001§, §EC-001§ | Prova inválida não altera a senha atual. |
| §QR-001§ | §SC-002§ | Respostas observáveis não revelam a existência da conta. |
`

func validPrompt() string {
	return strings.ReplaceAll(validPromptTemplate, "§", "`")
}

// validatePromptContent grava o prompt em .prompts/0001-change.md e a spec do
// sistema, e devolve o resultado da validação.
func validatePromptContent(t *testing.T, content string) plan.PromptValidation {
	t.Helper()
	dir := t.TempDir()
	promptPath := filepath.Join(dir, ".prompts", "0001-change.md")
	if err := os.MkdirAll(filepath.Dir(promptPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	systemPath := filepath.Join(dir, "system.md")
	if err := os.WriteFile(systemPath, []byte(systemSpecFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return plan.ValidatePrompt(promptPath, systemPath)
}

func TestAcceptsCompletePrompt(t *testing.T) {
	result := validatePromptContent(t, validPrompt())
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	want := plan.PromptValidationCounts{Requirements: 3, Scenarios: 1, SuccessCriteria: 2}
	if result.Counts == nil || *result.Counts != want {
		t.Fatalf("counts=%#v; want=%#v", result.Counts, want)
	}
}

func TestRejectsUnresolvedMarkersAndCheckboxes(t *testing.T) {
	content := strings.Replace(validPrompt(),
		"- Solicitação e conclusão da recuperação de senha.",
		"- [ ] TODO: Solicitação e conclusão da recuperação de senha.", 1)
	result := validatePromptContent(t, content)
	mustPromptError(t, result.Errors, "unresolved marker")
	mustPromptError(t, result.Errors, "checkboxes are not allowed")
}

func TestRejectsRequirementWithoutTraceability(t *testing.T) {
	content := strings.Replace(validPrompt(),
		"| `FR-002` | `US-001`, `EC-001` | Prova inválida não altera a senha atual. |\n", "", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "requirement missing from traceability table: FR-002")
}

func TestRequiresIndependentlyVerifiableStory(t *testing.T) {
	content := strings.Replace(validPrompt(),
		"**Verificação independente:** Solicitar a recuperação e definir uma nova senha válida.\n", "", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "US-001 missing concrete field: Verificação independente")
}

func TestRequiresEdgeCaseAndCriterionLinks(t *testing.T) {
	content := strings.Replace(validPrompt(), " (FR-002)\n\n## Critérios", "\n\n## Critérios", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "EC-001 must reference at least one FR-* or QR-* ID")
}

func TestRejectsTraceabilityWithoutCoverageOrSpecificEvidence(t *testing.T) {
	content := strings.Replace(validPrompt(),
		"| `FR-001` | `US-001`, `SC-001` | Nova senha autentica e senha anterior deixa de autenticar. |",
		"| `FR-001` | fluxo principal | Testes passam. |", 1)
	errors := validatePromptContent(t, content).Errors
	mustPromptError(t, errors, "traceability coverage needs")
	mustPromptError(t, errors, "traceability evidence is not specific enough")
}

func TestRejectsUnknownLocalIDs(t *testing.T) {
	content := strings.Replace(validPrompt(), "(FR-002)\n\n## Contrato", "(FR-999)\n\n## Contrato", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "reference to unknown ID: FR-999")
}

func TestRejectsSystemIDsAbsentFromBaseline(t *testing.T) {
	content := strings.Replace(validPrompt(), "`CAP-001`.", "`CAP-999`.", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "system reference not found in baseline: CAP-999")
}

func TestRequiresSystemSpecPath(t *testing.T) {
	dir := t.TempDir()
	promptPath := filepath.Join(dir, "prompt.md")
	if err := os.WriteFile(promptPath, []byte(validPrompt()), 0o644); err != nil {
		t.Fatal(err)
	}
	result := plan.ValidatePrompt(promptPath, "")
	mustPromptError(t, result.Errors, "system spec path is required")
}

func TestRejectsMissingNegativeScope(t *testing.T) {
	content := strings.Replace(validPrompt(), "- Alteração do método de autenticação existente.", "", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "### Não inclui must contain at least one concrete list item")
}

func TestRejectsVagueRequirementLanguage(t *testing.T) {
	content := strings.Replace(validPrompt(),
		"A resposta da solicitação deve ser indistinguível para endereços cadastrados e não cadastrados.",
		"A resposta da solicitação deve ser segura, robusta e adequada para todas as pessoas usuárias.", 1)
	mustPromptError(t, validatePromptContent(t, content).Errors, "QR-001 uses vague term")
}

func TestRequiresSequentialIDs(t *testing.T) {
	content := strings.ReplaceAll(validPrompt(), "FR-002", "FR-003")
	mustPromptError(t, validatePromptContent(t, content).Errors, "FR IDs must be sequential")
}

// TestValidatesRealPrompt0002 usa o prompt canônico do Work 0002 e a baseline do
// sistema como caso PASS.
func TestValidatesRealPrompt0002(t *testing.T) {
	root := repoRoot(t)
	result := plan.ValidatePrompt(
		filepath.Join(root, ".prompts", "0002-change.md"),
		filepath.Join(root, ".specs", "system.json"),
	)
	if len(result.Errors) != 0 {
		t.Fatalf("prompt 0002 deveria passar: %q", result.Errors)
	}
	want := plan.PromptValidationCounts{Requirements: 6, Scenarios: 1, SuccessCriteria: 2}
	if result.Counts == nil || *result.Counts != want {
		t.Fatalf("counts=%#v; want=%#v", result.Counts, want)
	}
}

func mustPromptError(t *testing.T, errors []string, substr string) {
	t.Helper()
	for _, issue := range errors {
		if strings.Contains(issue, substr) {
			return
		}
	}
	t.Fatalf("nenhum erro contém %q; errors=%q", substr, errors)
}
