---
description: Cria um prompt de mudança numerado, confiável e rastreável contra a system spec antes do planejamento técnico.
argument-hint: "[-h | descrição | fonte.md] [--work NNNN]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem ler a conversa, inspecionar o projeto, fazer perguntas ou salvar arquivos:

```text
Uso: /make-prompt [DESCRIÇÃO | FONTE.md] [--work NNNN]

Formas:
  /make-prompt "permitir recuperação de senha"  Reserva um Work ID, salva a origem e cria o prompt numerado.
  /make-prompt docs/pedido.md                    Trata o Markdown como fonte, nunca como destino.
  /make-prompt .sources/0007-issue.md --work 0007
                                                   Reutiliza uma reserva compatível.
  /make-prompt -h                                Exibe esta ajuda sem gerar arquivo.

System spec padrão: .specs/system.md
Saída: .prompts/NNNN-change.md
Próximo passo: /make-todo NNNN
```

## PRINCÍPIOS

1. Leia e valide a system spec antes de descrever seu delta.
2. Especifique WHAT/WHY; o HOW pertence a `/make-todo`.
3. Trate todo argumento `.md` como fonte. O usuário nunca escolhe o destino do prompt.
4. Todo novo trabalho recebe um Work ID de quatro dígitos, sequencial por repositório e nunca reutilizado.
5. `.work/NNNN.json` reserva e indexa o trabalho; `.sources/NNNN-*.md` preserva a entrada; `.prompts/NNNN-change.md` é o prompt normativo.
6. Reutilize `--work NNNN` somente quando o manifesto existir, estiver compatível e o destino ainda não existir.
7. Descubra fatos no repositório antes de perguntar e não invente contratos, caminhos ou comandos.
8. Não copie secrets nem prescreva instalação, deploy, publish ou ação destrutiva.

## 1. Reservar ou carregar o trabalho

Resolva `skill_dir` como o diretório absoluto desta skill e `scripts_dir=SKILL_DIR/scripts`.

### Novo trabalho

Se `--work` não foi informado:

1. determine se a entrada é texto, arquivo existente dentro do repositório ou pedido da conversa;
2. para arquivo, use `node "$scripts_dir/work_artifacts.js" reserve --origin-type request --source CAMINHO`;
3. para texto ou conversa, reserve com `node "$scripts_dir/work_artifacts.js" reserve --origin-type local`, salve a entrada exatamente em `.sources/NNNN-request.md` e atualize o manifesto para `prompt_pending`;
4. preserve stdout e o Work ID real retornado;
5. criação exclusiva falha em colisão e nunca sobrescreve um artefato.

### Trabalho reservado

Com `--work NNNN`:

1. exija exatamente quatro dígitos;
2. leia `.work/NNNN.json`;
3. confirme que source, prompt e plan canônicos pertencem ao mesmo NNNN;
4. use a fonte indicada no manifesto ou a fonte explícita compatível;
5. se `.prompts/NNNN-change.md` já existir, não sobrescreva; retomar exige pedido explícito para atualizar esse arquivo.

O próximo Work ID considera manifestos, sources, prompts e planos existentes. Uma reserva abandonada permanece ocupada.

## 2. System spec governante

1. Use `.specs/system.md`, salvo caminho governante explicitamente confirmado.
2. Se ausente, pare: `System spec ausente. Crie a baseline com /make-spec antes de gerar o prompt.`
3. Valide-a com o validador da skill `system-specification`.
4. Exit diferente de `0` bloqueia a geração.
5. Baseline parcial permite a mudança somente dentro da cobertura confirmada; mudança que toca gap material exige reconciliação primeiro.

## 3. Descoberta brownfield

Leia somente o necessário:

- `AGENTS.md` e instruções locais;
- system spec e IDs afetados;
- README, contratos, glossário e documentação relevante;
- código, testes, schemas e configuração que comprovam o comportamento atual;
- CI apenas quando impõe restrição observável.

Não leia `.env`, credenciais ou artefatos sem relação com o pedido. Um caminho citado precisa existir, salvo se a própria mudança exigir sua criação.

## 4. Conteúdo obrigatório

Produza `.prompts/NNNN-change.md` com esta forma, preenchida com fatos concretos:

```markdown
# PROMPT: Nome direto da mudança

**Status:** Pronto para planejamento
**Work ID:** NNNN
**System spec:** `.specs/system.md`
**Baseline:** versão e status observados
**Origem:** `.sources/NNNN-request.md` ou `.sources/NNNN-issue.md`

## Delta da system spec

- **Capacidades afetadas:** IDs reais.
- **Regras preservadas:** IDs reais.
- **Regras alteradas:** nenhuma ou IDs e delta objetivo.
- **Contratos afetados:** IDs reais.
- **Qualidades, entidades e integrações relacionadas:** IDs reais ou nenhuma.
- **Gaps tocados:** nenhum ou gaps reais.
- **Reconciliação esperada após implementação:** delta sistêmico esperado.

## Problema e resultado

**Problema:** problema atual sem antecipar implementação.

**Resultado esperado:** comportamento observável que resolve o problema.

## Contexto confirmado

- `caminho/real`: fato confirmado.

## Atores e valor

- **Ator:** necessidade e valor recebido.

## Escopo

### Inclui

- Item concreto.

### Não inclui

- Exclusão concreta.

## Cenários de usuário

### US-001 — Título (P1)

**Ator:** ator real.

**Valor independente:** valor entregue.

**Verificação independente:** comportamento verificável.

**Cenários de aceitação:**

1. **Given** estado, **When** ação, **Then** resultado. (FR-001)

## Contrato observável

- **Entradas:** ações ou dados.
- **Saídas e efeitos:** resultados observáveis.
- **Erros:** condições e ausência de efeito indevido.

## Requisitos

### Funcionais

- **FR-001:** obrigação funcional verificável.

### Qualidade e restrições

- Restrição confirmada ou nenhuma restrição adicional.

## Casos de borda

- **EC-001:** limite e resultado. (FR-001)

## Critérios de sucesso

- **SC-001:** resultado verificável. (FR-001)

## Premissas

- Nenhuma premissa material; ou premissa com impacto se falsa.

## Componentes afetados

- `caminho/real` — fronteira confirmada.

## Rastreabilidade

| Requisito | Cobertura | Evidência esperada |
|-----------|-----------|--------------------|
| `FR-001` | `US-001`, `SC-001` | Evidência observável específica. |
```

Mantenha todas as headings obrigatórias aceitas por `validate_prompt.js`. Requisitos usam `FR-*`/`QR-*`, cenários `US-*`, bordas `EC-*`, sucesso `SC-*` e premissas `A-*`. Não use checkboxes, marcadores abertos, detalhes técnicos inventados ou linguagem não verificável.

## 5. Salvar e validar

1. Salve somente em `.prompts/NNNN-change.md`.
2. Confirme que `**Work ID:** NNNN`, origem, nome do arquivo e manifesto coincidem.
3. Execute:

```bash
node "$scripts_dir/validate_prompt.js" ".prompts/NNNN-change.md" CAMINHO_DA_SYSTEM_SPEC
```

4. Corrija apenas erros relatados, no máximo 3 execuções.
5. Após PASS, atualize `.work/NNNN.json` para `plan_pending`.
6. Nunca declare PASS sem observar exit `0`.

Em sucesso, responda somente:

```text
Work ID: NNNN
Source snapshot: .sources/NNNN-*.md
Prompt salvo em: .prompts/NNNN-change.md
Validação do prompt contra a system spec: PASS
Próximo passo: /make-todo NNNN
```
