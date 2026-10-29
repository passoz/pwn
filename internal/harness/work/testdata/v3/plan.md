# Tasks: Migração de Autenticação

**Contract version:** 3
**Work ID:** 0004

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| jachegai-bun | `.` | `bun test` | `bun run check` | `bun run check` | `N/A` | `N/A` | `N/A` |

## Global gates
- [x] `bun test` — toda a regressão passa com exit 0.
- [x] `bun run check` — typecheck estrito com exit 0.

### [x] [4.1] Inicialização do Auth

**Requirement:** FR-001
**Depends on:** none
**Behavior:** inicializa o cliente de autenticação com adapter Drizzle sobre SQLite.
**Components:** jachegai-bun
**Files:** `src/auth/index.ts`, `tests/auth/init.test.ts`
**Implementation files:** `src/auth/index.ts`
**Test files:** `tests/auth/init.test.ts`

**RED:**
- `bun test tests/auth/init.test.ts` — exit 1 pela asserção de inicialização.

**Implementation:**
1. Configurar o adapter.
2. Exportar o singleton.

**ACs:**
- [x] `bun test tests/auth/init.test.ts` — a instância inicializa e expõe a API.

**Visual:** N/A
**Documentation:** N/A

### [x] [4.2] Sessões

**Requirement:** FR-002
**Depends on:** 4.1
**Behavior:** emite e revoga sessões com suporte a logout.
**Components:** jachegai-bun
**Files:** `src/auth/session.ts`, `tests/auth/session.test.ts`
**Implementation files:** `src/auth/session.ts`
**Test files:** `tests/auth/session.test.ts`

**RED:**
- `bun test tests/auth/session.test.ts` — exit 1 pela asserção de sessão.

**Implementation:**
1. Persistir sessão.

**ACs:**
- [x] `bun test tests/auth/session.test.ts` — sessão válida é emitida.

**Visual:** N/A
**Documentation:** N/A
