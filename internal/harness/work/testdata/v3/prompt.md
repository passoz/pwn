# PROMPT: Migração de Autenticação

**Status:** Pronto para planejamento
**Work ID:** 0004

## Problema e resultado

**Problema:** O subsistema de autenticação atual usa gerenciamento manual de sessões e limita a padronização da pilha.
**Resultado esperado:** A aplicação integra um motor de autenticação padronizado sobre Drizzle e SQLite.

## Atores e valor

- **Cliente:** realiza login mantendo o carrinho.
- **Administrador:** opera com privilégios completos.

## Escopo

### Inclui

- `src/auth/` — motor de autenticação.
- `tests/auth/` — regressão do fluxo.

### Não inclui

- Migração de dados históricos.

## Requisitos

### Funcionais

- **FR-001:** configurar a instância de autenticação com adapter Drizzle.
- **FR-002:** emitir e revogar sessões gerenciadas.

### Qualidade e restrições

- **QR-001:** manter compatibilidade com toda a suíte existente.

## Critérios de sucesso

- **SC-001:** login emite sessão válida (FR-001, FR-002).
