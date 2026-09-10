import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { validatePrompt } from "../src/core/validate_prompt.js";

const SYSTEM_SPEC = `# SYSTEM SPEC: Contas

**Status:** Baseline validada
**Versão:** 1

- **ACT-001 — Pessoa cadastrada:** utiliza a própria conta.
- **CAP-001:** autenticar e recuperar acesso.
- **BR-001:** somente a pessoa autorizada altera sua credencial.
- **CON-001:** autenticação e recuperação de acesso.
- **ENT-001:** conta cadastrada.
`;

const VALID = `# PROMPT: Recuperação de senha

**Status:** Pronto para planejamento
**Work ID:** 0001
**System spec:** \`.specs/system.md\`
**Baseline:** versão 1, Baseline validada
**Origem:** \`.sources/0001-request.md\`

## Delta da system spec

- **Capacidades afetadas:** \`CAP-001\`.
- **Regras preservadas:** \`BR-001\`.
- **Regras alteradas:** nenhuma.
- **Contratos afetados:** \`CON-001\`.
- **Qualidades, entidades e integrações relacionadas:** \`ENT-001\`.
- **Gaps tocados:** nenhum.
- **Reconciliação esperada após implementação:** atualizar limites da recuperação em \`CAP-001\` e \`CON-001\`.

## Problema e resultado

**Problema:** Pessoas que esquecem a senha não conseguem recuperar o acesso sem atendimento manual.

**Resultado esperado:** Uma pessoa cadastrada consegue solicitar e concluir a recuperação sem revelar se outro endereço possui conta.

## Contexto confirmado

- \`README.md\`: o produto já possui autenticação por endereço de e-mail.

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

- \`README.md\` — contrato de autenticação confirmado.
- Detalhe ainda desconhecido — descobrir no repositório durante \`/make-todo\` sem presumir arquitetura.

## Rastreabilidade

| Requisito | Cobertura | Evidência esperada |
|-----------|-----------|--------------------|
| \`FR-001\` | \`US-001\`, \`SC-001\` | Nova senha autentica e senha anterior deixa de autenticar. |
| \`FR-002\` | \`US-001\`, \`EC-001\` | Prova inválida não altera a senha atual. |
| \`QR-001\` | \`SC-002\` | Respostas observáveis não revelam a existência da conta. |
`;

function validate(content: string) {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-prompt-"));
  const file = path.join(directory, ".prompts", "0001-change.md");
  const systemFile = path.join(directory, "system.md");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content, "utf8");
  writeFileSync(systemFile, SYSTEM_SPEC, "utf8");
  return validatePrompt(file, systemFile);
}

test("accepts a complete prompt traceable to the system specification", () => {
  const result = validate(VALID);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, { requirements: 3, scenarios: 1, successCriteria: 2 });
});

test("rejects unresolved markers and checkboxes", () => {
  const result = validate(VALID.replace(
    "- Solicitação e conclusão da recuperação de senha.",
    "- [ ] TODO: Solicitação e conclusão da recuperação de senha.",
  ));
  assert.ok(result.errors.some((error) => error.includes("unresolved marker")));
  assert.ok(result.errors.some((error) => error.includes("checkboxes are not allowed")));
});

test("rejects requirements without traceability", () => {
  const result = validate(VALID.replace(
    "| `FR-002` | `US-001`, `EC-001` | Prova inválida não altera a senha atual. |\n",
    "",
  ));
  assert.ok(result.errors.some((error) => error.includes("requirement missing from traceability table: FR-002")));
});

test("requires every user story to be independently verifiable", () => {
  const result = validate(VALID.replace("**Verificação independente:** Solicitar a recuperação e definir uma nova senha válida.\n", ""));
  assert.ok(result.errors.some((error) => error.includes("US-001 missing concrete field: Verificação independente")));
});

test("requires edge cases and success criteria to link to requirements", () => {
  const result = validate(VALID.replace(" (FR-002)\n\n## Critérios", "\n\n## Critérios"));
  assert.ok(result.errors.some((error) => error.includes("EC-001 must reference at least one FR-* or QR-* ID")));
});

test("rejects traceability without coverage IDs or specific evidence", () => {
  const result = validate(VALID.replace(
    "| `FR-001` | `US-001`, `SC-001` | Nova senha autentica e senha anterior deixa de autenticar. |",
    "| `FR-001` | fluxo principal | Testes passam. |",
  ));
  assert.ok(result.errors.some((error) => error.includes("traceability coverage needs")));
  assert.ok(result.errors.some((error) => error.includes("traceability evidence is not specific enough")));
});

test("rejects references to unknown local IDs", () => {
  const result = validate(VALID.replace("(FR-002)\n\n## Contrato", "(FR-999)\n\n## Contrato"));
  assert.ok(result.errors.some((error) => error.includes("reference to unknown ID: FR-999")));
});

test("rejects system IDs absent from the baseline", () => {
  const result = validate(VALID.replace("`CAP-001`.", "`CAP-999`."));
  assert.ok(result.errors.some((error) => error.includes("system reference not found in baseline: CAP-999")));
});

test("requires a system specification", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-prompt-no-system-"));
  const file = path.join(directory, "prompt.md");
  writeFileSync(file, VALID, "utf8");
  const result = validatePrompt(file);
  assert.ok(result.errors.some((error) => error.includes("system spec path is required")));
});

test("rejects missing negative scope", () => {
  const result = validate(VALID.replace("- Alteração do método de autenticação existente.", ""));
  assert.ok(result.errors.some((error) => error.includes("### Não inclui must contain at least one concrete list item")));
});

test("rejects vague requirement language", () => {
  const result = validate(VALID.replace(
    "A resposta da solicitação deve ser indistinguível para endereços cadastrados e não cadastrados.",
    "A resposta da solicitação deve ser segura, robusta e adequada para todas as pessoas usuárias.",
  ));
  assert.ok(result.errors.some((error) => error.includes("QR-001 uses vague term")));
});

test("requires sequential stable IDs", () => {
  const result = validate(VALID.replaceAll("FR-002", "FR-003"));
  assert.ok(result.errors.some((error) => error.includes("FR IDs must be sequential")));
});
