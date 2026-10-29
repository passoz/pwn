# Tasks: pwn-ledger

**Contract version:** 3
**Work ID:** 0001

## Execution contract

| Component | Purpose |
|-----------|---------|
| `core-domain` | Dominio e validacao dos lancamentos |
| `cli` | Interface de linha de comando |

## Global gates
- [ ] `bun test` — a suíte completa permanece verde

### [ ] [1.1] Dominio de lancamentos

**Requirement:** FR-001
**Depends on:** none
**Behavior:** Valida descricao, valor e tipo e calcula o saldo
**Components:** core-domain
**Files:** `src/ledger.ts`, `tests/ledger.test.ts`
**Implementation files:** `src/ledger.ts`
**Test files:** `tests/ledger.test.ts`

**RED:**
- `bun test tests/ledger.test.ts` — a assercao de saldo consolidado falha antes da implementacao

**Implementation:**
1. Implementar addEntry com validacao
2. Implementar computeBalance

**ACs:**
- [ ] `bun test tests/ledger.test.ts` — a suite focada do dominio passa
- [ ] `bun test tests/ledger.test.ts -t 'saldo consolidado'` — a assercao de saldo consolidado e observada

**Visual:** N/A
**Documentation:** N/A
