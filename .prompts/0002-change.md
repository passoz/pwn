# PROMPT: Reescrita do pwn em Go — Fase 0: referência de comportamento

**Status:** Pronto para planejamento
**Work ID:** 0002
**Origem:** `.sources/0002-pwn-go-rewrite.md`
**System spec:** `.specs/system.json`
**Baseline:** pwn `c81a18b`, status "Baseline parcial", 470 testes aprovados em 2026-10-28

## Delta da system spec

- **Capacidades afetadas:** CAP-001 e CAP-010.
- **Regras preservadas:** BR-001, BR-002, BR-006 e BR-008.
- **Regras alteradas:** DEC-005 passa a DEC-030; a implementação passa de TypeScript sobre Bun para Go.
- **Contratos afetados:** CON-001 e CON-002.
- **Qualidades, entidades e integrações relacionadas:** SQR-001, ENT-007 e INT-001.
- **Gaps tocados:** nenhum.
- **Reconciliação esperada após implementação:** `spec.json`, `.specs/system.json`, README e MANUAL passam a declarar Go.

## Problema e resultado

**Problema:** O pwn atual depende de Bun e TypeScript para executar a governança. Isso limita a distribuição a um ambiente de execução instalado.

**Resultado esperado:** Um plano executável de reescrita em Go, com uma referência de comportamento congelada e uma decisão normativa registrada.

## Contexto confirmado

O commit `c81a18b` tem 17.185 linhas em `src`, 41 suítes e 470 testes aprovados. O host tem Go 1.27.1, `bwrap` e `golangci-lint` 2.14.0. A branch de trabalho é `pwngo`.

## Atores e valor

ACT-001 define e aprova a reescrita. ACT-001 recebe um binário Go com paridade de comportamento.

## Escopo

### Inclui

- Registro da decisão DEC-030.
- Captura da linha de base de testes e de comandos.
- Criação do executor diferencial e dos vetores de referência.
- Prova do pwn TypeScript dentro do sandbox do verificador.

### Não inclui

- Implementação do binário Go.
- Alteração de schemas.
- Reescrita do editor visual.

## Cenários de usuário

### US-001 — Operador aprova a referência de comportamento (P1)

**Ator:** operador humano.

**Valor independente:** a reescrita começa com uma referência reproduzível.

**Verificação independente:** o executor diferencial compara o pwn atual com o pwn Go no mesmo cenário.

1. **Given** o commit `c81a18b` e a suíte Bun, **When** o operador executa a captura da linha de base, **Then** o relatório registra 470 testes aprovados e o código de saída 0 (FR-001)

## Contrato observável

- **Entradas:** o commit de referência, a suíte Bun e o plano aprovado.
- **Saídas e efeitos:** `.pwn/work/0002/`, `testdata/parity/` e o relatório da linha de base.
- **Erros:** uma falha de `bun run check` ou de `work specify` bloqueia a captura.

O Work 0002 gera `.pwn/work/0002/` e `testdata/parity/`. O comando `pwn work gate --all` passa. O comando `pwn validate --work 0002` passa.

## Requisitos

### Funcionais

- **FR-001:** A captura da linha de base deve registrar o resultado de `bun run check` com código de saída e contagem de testes.
- **FR-002:** O executor diferencial deve comparar código de saída, saída normalizada e árvore de arquivos entre os dois binários.
- **FR-003:** Os vetores de referência devem cobrir JSON canônico, SHA-256, HMAC, Ed25519, recibos e markdown do plano.
- **FR-004:** O conjunto de conformidade do validador deve cobrir as 17 palavras-chave usadas nos schemas.

### Qualidade e restrições

- **QR-001:** A captura deve ser determinística e não deve alterar a árvore do repositório.
- **QR-002:** O executor diferencial deve rodar sem rede.

## Casos de borda

- **EC-001:** Um comando com o separador `--` deve manter o comando do operador intacto; o executor compara o resultado com FR-002.

## Critérios de sucesso

- **SC-001:** O relatório da linha de base reproduz 470 testes e código 0; o operador confere o arquivo com FR-001.
- **SC-002:** O executor diferencial reproduz o pwn atual em todos os cenários; a saída normalizada e a árvore de arquivos coincidem com FR-002.

## Premissas

- **A-001:** O commit `c81a18b` permanece disponível durante a Fase 0.
- **A-002:** O verificador tem chave Ed25519 e `bwrap` disponíveis.

## Componentes afetados

- `.pwn/work/0002/`
- `testdata/parity/`
- `docs/archive/DECISIONS.md`
- `spec.json`
- `.specs/system.json`
- `.prompts/0002-change.md`
- `.sources/0002-pwn-go-rewrite.md`

## Rastreabilidade

| Requisito | Cobertura | Evidência |
|---|---|---|
| `FR-001` | US-001, SC-001 | O relatório registra o código de saída e a contagem de testes |
| `FR-002` | US-001, SC-002 | O executor compara a saída e a árvore de arquivos |
| `FR-003` | SC-001, SC-002 | Os vetores cobrem JSON, criptografia, recibo e markdown |
| `FR-004` | SC-001, SC-002 | O conjunto cobre as 17 palavras-chave dos schemas |
| `QR-001` | US-001, SC-001 | A captura roda duas vezes e compara o mesmo resultado |
| `QR-002` | SC-002 | O executor roda com a rede desligada no sandbox |
