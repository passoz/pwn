---
description: Executa tasks de um plano explicitamente selecionado com TDD e evidência namespaced por Work ID.
argument-hint: "[-h | NNNN | caminho | legacy] [ID | intervalo | all]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente:

```text
Uso: /make-task PLANO [ID | INTERVALO | all]

Formas:
  /make-task 0007 1.2
  /make-task 0007 1.1-1.4
  /make-task .todo/0007-tasks.md all
  /make-task legacy 1.2

O plano é obrigatório. Ordem: BASELINE → RED → GREEN → REFACTOR → ACs → Visual → Documentation → Gates locais → Regressão.
```

## PROTOCOLO

1. Resolva o alvo com `work_artifacts.js resolve`; nunca escolha plano único, recente ou padrão.
2. Valide o plano e o grafo completo antes de executar.
3. Execute uma task integralmente antes da seguinte.
4. RED precisa falhar pela assertion nova; GREEN exige teste congelado e diff de produção.
5. Comandos, exit codes e outputs sanitizados sustentam todo PASS.
6. Na terceira falha, marque `[!]` com motivo e pare o fluxo afetado.
7. Não execute instalação não declarada, deploy, alteração remota, comando destrutivo ou secret. Instalação registrada em `Dependency installations` e validada contra a Spec governante é pré-requisito autorizado da task.

## 1. Alvo e fila

- `PLANO`: `NNNN`, `.todo/NNNN-tasks.md` ou `legacy`.
- seleção ausente após o plano equivale a `all` somente quando o plano já foi explicitado.
- ID executa uma task; intervalo executa IDs inclusivos; `all` executa `[ ]` em ordem.
- pule `[x]`; reporte `[!]`.

Resolva `scripts_dir` e execute:

```bash
node "$scripts_dir/work_artifacts.js" resolve PLANO \
  && node "$scripts_dir/validate_tasks.js" CAMINHO_CANONICO \
  && node "$scripts_dir/validate_work_graph.js" . \
  && test -f "$scripts_dir/task_evidence.js"
```

Para plano numerado, preserve `work_id=NNNN`. Para `legacy`, use o namespace `legacy` somente nas instruções de compatibilidade e não misture evidências com planos numerados.

## 2. Dependências

- local `1.2`: precisa estar `[x]` e passar `task_evidence.js verify --work NNNN --task 1.2`;
- qualificada `0006/1.2`: resolva o plano externo, exija `[x]` e evidência atual em `.todo/evidence/0006/`;
- dependência bloqueada impede a task;
- ciclos ou referência ausente bloqueiam antes de alterar código.

## 3. Evidência

Para Work numerado, use exclusivamente:

```text
.todo/evidence/NNNN/
.todo/diagnostics/NNNN/
.todo/screenshots/NNNN/
.todo/attestations/NNNN/
```

Nunca escreva evidência de NNNN na raiz legada. Logs sanitizam passwords, tokens, cookies, API keys, `Authorization` e valores de `.env`.

### Dependências declaradas

Antes do BASELINE, execute cada comando de `Dependency installations` somente após `validate_tasks.js` confirmar que o pacote consta na Spec governante. Registre comando, exit code e output sanitizado no namespace da task. A declaração autoriza apenas o comando exato registrado; não autoriza `sudo`, download canalizado para shell, instalação global, deploy, publish ou pacote adicional.

A ausência do campo significa que nenhuma instalação está autorizada. Falha de uma instalação declarada é Categoria A; necessidade de pacote não declarado é Categoria D.

### BASELINE

```bash
node "$scripts_dir/task_evidence.js" baseline --work NNNN --task ID \
  --implementation CAMINHOS --tests CAMINHOS
```

Exige Git e caminhos declarados sem mudanças preexistentes. Não use commit, stash, reset ou clean para fabricar baseline.

### RED

1. Altere somente o menor teste real.
2. Não altere produção antes do RED.
3. Registre:

```bash
node "$scripts_dir/task_evidence.js" red --work NNNN --task ID \
  --expect TEXTO_EXCLUSIVO -- COMANDO_RED
```

#### RED inválido — falha de toolchain ou ambiente

Um RED **inválido** é aquele cujo output contém apenas erros de toolchain ou ambiente sem que nenhuma assertion do teste tenha executado. Exemplos de falha incidental rejeitada:

- `cannot find main module` — o Go não encontrou `go.mod`; nenhum teste rodou.
- `no such file or directory` — o arquivo de implementação não existe; o compilador parou antes dos testes.
- `cannot find module` / `module not found` — dependência ausente; nenhuma assertion exercitada.

O script `task_evidence.js red` rejeita esses padrões com exit 1 e mensagem diagnóstica. O validador `validate_tasks.js` rejeita em planos v3 descrições de RED que enunciem esses padrões como mecanismo principal.

#### Tarefa greenfield e RED por assertion

Em tarefas **greenfield** (arquivo de implementação ainda não existe), a técnica correta para obter RED por assertion é:

1. No baseline, crie o arquivo de implementação com conteúdo mínimo compilável mas **incorreto** (ex: função retornando zero, constante errada, módulo com caminho errado).
2. Escreva o teste que falha porque o valor retornado é incorreto — a assertion dispara, não o toolchain.
3. No GREEN, corrija a implementação; o mutation check reverte para o estado incorreto e confirma que a assertion volta a falhar.

Isso garante que o RED exerce a assertion e que o mutation check prova o vínculo entre implementação e comportamento.


1. Implemente somente o comportamento declarado.
2. Execute:

```bash
node "$scripts_dir/task_evidence.js" green --work NNNN --task ID -- COMANDO_RED
```

Teste alterado depois do RED, ausência de diff, comando diferente ou mutation check falho invalidam GREEN.

### REFACTOR, ACs, visual e documentação

- refatore somente duplicação/nome criado nesta task;
- execute cada AC contra o SUT real;
- UI `REQUIRED` exige rota, selector, Playwright, desktop/mobile e inspeção visual;
- documentação `REQUIRED` exige audience, files, sections, sources e evidence real;
- reexecute checks afetados por correção.

### Gates locais e regressão

Execute lint/build não `N/A` e regressão dos componentes afetados. Gates globais são responsabilidade de `make-all` ou verificação do plano, não de cada `/make-task ID` isolado.

## 4. Conclusão da implementação

Antes de `[x]`:

```bash
node "$scripts_dir/task_evidence.js" verify --work NNNN --task ID
```

Confirme RED/GREEN atuais, ACs, visual, docs, gates locais, regressão e ausência de processo órfão. Somente então marque `[x]`.

`[x]` significa implementação concluída pela etapa `/make-task`; ainda não significa aceitação independente. `/make-ac` precisa rodar em sessão separada para produzir o candidato verificável.

## 5. Bloqueio e recuperação

Após uma falha, classifique-a antes de tentar corrigir. Até três tentativas por task.

### Categoria A — Processo/Ambiente

**Sintomas:** porta ocupada, timeout de build, processo órfão, lock de arquivo, diretório ausente, ferramenta não encontrada no PATH, instalação declarada na Spec ainda não executada ou falha transitória dessa instalação.

**Permitido:** matar processo órfão, remover lock temporário, criar diretório, executar/repetir o comando exato de `Dependency installations`, retry do comando. Não altera código nem testes nem amplia a lista de pacotes.

### Categoria B — Implementação/Teste

**Sintomas:** assertion falha no GREEN, AC não passa, lint/build quebra pelo código novo.

**Permitido:** corrigir código dentro dos `Implementation files` declarados. Se teste mudar, refazer BASELINE → RED → GREEN completo.

### Categoria C — Plano/Escopo

**Sintomas:** arquivo não declarado necessário, AC impossível de satisfazer, dependência faltando.

**Permitido:** ajustar metadados da task (Files, Implementation files, Test files, Depends on) e **revalidar** o plano com `validate_tasks.js` e `validate_work_graph.js`. Não pode violar atomicidade nem criar tasks novas.

### Categoria D — Segurança/Decisão

**Sintomas:** `sudo`, instalação ausente de `Dependency installations` ou cujo pacote não consta na Spec governante, deploy, secret, decisão de produto ambígua.

**Ação:** bloqueio terminal imediato (não consome tentativas).

Após três tentativas (ou bloqueio terminal), use motivo concreto e evidência namespaced:

```markdown
### [!] [1.3] Título — BLOCKED (categoria): motivo; evidência: `.todo/evidence/NNNN/1.3-*.log`
```

Bloqueio de uma task impede dependentes; planos independentes não são bloqueados por suposição.

## 6. Relatório

Reporte status por ID, ACs, visual, docs, checks locais e evidência. Não declare sucesso total quando houver `[!]`, evidência stale ou dependência insatisfeita.
