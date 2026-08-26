---
description: Define um objetivo de alto nível, analisa a base de código, cria o plano de tarefas e executa de forma autônoma até a conclusão
argument-hint: "[-h | descrição da meta]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem investigar ou alterar o projeto:

```text
Uso: /goal [DESCRIÇÃO_DA_META]

Formas:
  /goal "entregar autenticação completa"   Planeja e executa a meta informada.
  /goal                                    Usa uma meta clara da conversa ou pergunta.
  /goal -h                                 Exibe esta ajuda sem executar a meta.
```


Você atuará em modo **Goal-Driven Autonomy** (foco em cumprir o objetivo final de ponta a ponta).

Seu objetivo é: **$@**

Se nenhum objetivo explícito foi passado como parâmetro, pergunte ou identifique o objetivo a partir do histórico recente da conversa.

---

## Passo 1: Discovery & Investigação da Base de Código

1. **Examine o projeto:**
   - Verifique a estrutura de diretórios, arquivo de configuração, stack usada e testes existentes.
   - Identifique pontos de extensão, arquivos que serão tocados e possíveis impactos.
2. **Confirme os requisitos e a stack:**
   - Respeite rigorosamente as regras da stack do projeto e as convenções existentes.

---

## Passo 2: Construir o Plano de Execução (`.todo/goal.md`)

Crie ou atualize o arquivo `.todo/goal.md` com a seguinte estrutura:

```markdown
# Goal: <Título do Objetivo>

> **Objetivo:** <Descrição clara da meta final>
> **Status:** Em Progresso ⏳

---

## Plano de Tarefas

### [1.0] Discovery & Configuração
- [x] Analisar codebase e dependências

### [2.0] <Fase 1 - Nome>
- [ ] [2.1] <Primeira sub-tarefa>
  - **AC:** <Critério de aceitação testável>
- [ ] [2.2] <Segunda sub-tarefa>
  - **AC:** <Critério de aceitação testável>

### [3.0] <Fase 2 - Validação & Testes>
- [ ] [3.1] Criar e executar testes unitários e de integração
  - **AC:** Todos os testes passam sem falhas
- [ ] [3.2] Executar validação final e regressão
  - **AC:** Build compila limpo e `go test ./...` / suíte passa
```

---

## Passo 3: Execução Autônoma Passo a Passo

Execute o plano de forma incremental seguindo este ciclo para **CADA** tarefa:

1. **Implementação:** Escreva ou modifique o código seguindo as melhores práticas e padrões do projeto.
2. **Teste & Validação:**
   - Rode os testes relevantes para a alteração feita.
   - Corrija qualquer erro de compilação ou falha de teste imediatamente antes de prosseguir.
3. **Atualização do Progresso:**
   - Marque a tarefa como concluída `[x]` no arquivo `.todo/goal.md`.
   - Avance autonomamente para a próxima sub-tarefa.

---

## Passo 4: Conclusão & Entregáveis

Ao finalizar todas as etapas:
1. Rode os testes completos/suíte de validação (`go test ./...`, linter, build ou equivalente do projeto).
2. Verifique se nenhum bug de regressão foi introduzido.
3. Apresente um resumo claro ao usuário contendo:
   - **Status final do objetivo:** Concluído ✅
   - **Resumo dos artefatos criados/alterados**
   - **Comandos executados e resultado dos testes**
