# Tasks: Reescrita do pwn em Go — Fase 0: referência de comportamento

**Contract version:** 3
**Work ID:** 0002

## Execution contract

| Component | Purpose |
|-----------|---------|
| `parity` | Executor diferencial, linha de base e vetores de referência |
| `governance` | Decisão normativa DEC-030 e rastreabilidade |

## Global gates
- [ ] `bun test tests/parity` — a suíte de paridade passa com exit 0.
- [ ] `bun run typecheck` — o typecheck estrito passa com exit 0.

### [ ] [1.1] Registrar DEC-030 e atualizar a restrição normativa

**Requirement:** FR-005
**Depends on:** none
**Behavior:** Substitui DEC-005 por DEC-030 em spec.json e .specs/system.json e registra a decisão em docs/archive/DECISIONS.md.
**Components:** governance
**Files:** `spec.json`, `.specs/system.json`, `docs/archive/DECISIONS.md`, `tests/parity/normative.test.ts`, `tests/parity/acceptance.test.ts`
**Implementation files:** `spec.json`, `.specs/system.json`, `docs/archive/DECISIONS.md`
**Test files:** `tests/parity/normative.test.ts`, `tests/parity/acceptance.test.ts`

**RED:**
- `bun test tests/parity/normative.test.ts` — o teste exige DEC-030 e falha antes da atualização normativa

**Implementation:**
1. Atualizar as restrições em spec.json e .specs/system.json
2. Registrar DEC-030 em docs/archive/DECISIONS.md

**ACs:**
- [ ] `bun test tests/parity/acceptance.test.ts` — DEC-030 substitui DEC-005 nos dois documentos normativos

**Visual:** N/A
**Documentation:** N/A

### [ ] [1.2] Capturar a linha de base e criar o executor diferencial

**Requirement:** FR-001
**Depends on:** 1.1
**Behavior:** Grava o resultado de bun run check e compara dois binários por código de saída, saída normalizada e árvore de arquivos, sem rede.
**Components:** parity
**Files:** `scripts/parity/capture-baseline.ts`, `scripts/parity/diff.ts`, `tests/parity/baseline.test.ts`, `testdata/parity/manifest.json`
**Implementation files:** `scripts/parity/capture-baseline.ts`, `scripts/parity/diff.ts`
**Test files:** `tests/parity/baseline.test.ts`

**RED:**
- `bun test tests/parity/baseline.test.ts` — o teste exige o relatório da linha de base e falha antes do capturador

**Implementation:**
1. Escrever o capturador e o executor diferencial
2. Gravar o manifesto e comparar duas execuções

**ACs:**
- [ ] `bun test tests/parity/baseline.test.ts` — a linha de base registra 470 testes e código de saída 0
- [ ] `bun scripts/parity/diff.ts --self-test` — o executor compara saída e árvore de arquivos

**Visual:** N/A
**Documentation:** N/A

### [ ] [1.3] Gerar os vetores de referência

**Requirement:** FR-003
**Depends on:** 1.2
**Behavior:** Gera vetores de JSON canônico, SHA-256, HMAC, Ed25519, recibo e markdown e os compara com a cópia gravada.
**Components:** parity
**Files:** `scripts/parity/golden.ts`, `tests/parity/golden.test.ts`, `testdata/parity/golden/`
**Implementation files:** `scripts/parity/golden.ts`
**Test files:** `tests/parity/golden.test.ts`

**RED:**
- `bun test tests/parity/golden.test.ts` — o teste exige os vetores e falha antes do gerador

**Implementation:**
1. Implementar o gerador dos vetores
2. Gravar os vetores e comparar a segunda execução

**ACs:**
- [ ] `bun scripts/parity/golden.ts --check` — os vetores de referência são estáveis

**Visual:** N/A
**Documentation:** N/A

### [ ] [1.4] Gerar o conjunto de conformidade do validador

**Requirement:** FR-004
**Depends on:** 1.1
**Behavior:** Gera casos válidos e inválidos com o Ajv para as 17 palavras-chave e grava o conjunto que o validador Go deve reproduzir.
**Components:** parity
**Files:** `scripts/parity/schema-corpus.ts`, `tests/parity/schema.test.ts`, `testdata/parity/schema/`
**Implementation files:** `scripts/parity/schema-corpus.ts`
**Test files:** `tests/parity/schema.test.ts`

**RED:**
- `bun test tests/parity/schema.test.ts` — o teste exige o conjunto e falha antes do gerador

**Implementation:**
1. Implementar o gerador do conjunto
2. Conferir a cobertura das 17 palavras-chave

**ACs:**
- [ ] `bun test tests/parity/schema.test.ts` — o conjunto cobre as 17 palavras-chave dos schemas

**Visual:** N/A
**Documentation:** N/A

### [ ] [1.5] Provar o pwn TypeScript dentro do sandbox do verificador

**Requirement:** FR-002
**Depends on:** 1.2
**Behavior:** Executa o pwn TypeScript e os testes diferenciais dentro do bwrap com a política do verificador e registra o resultado.
**Components:** parity
**Files:** `scripts/parity/sandbox-proof.ts`, `tests/parity/sandbox.test.ts`, `testdata/parity/sandbox.json`
**Implementation files:** `scripts/parity/sandbox-proof.ts`
**Test files:** `tests/parity/sandbox.test.ts`

**RED:**
- `bun test tests/parity/sandbox.test.ts` — o teste exige a prova no sandbox e falha antes do script

**Implementation:**
1. Implementar o script de prova
2. Rodar o pwn e os testes dentro do bwrap

**ACs:**
- [ ] `bun test tests/parity/sandbox.test.ts` — o pwn TypeScript roda dentro do sandbox sem rede

**Visual:** N/A
**Documentation:** N/A
