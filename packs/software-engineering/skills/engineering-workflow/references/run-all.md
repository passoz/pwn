---
description: Executa e audita unattended todas as tasks selecionadas de um plano explícito, uma por vez.
argument-hint: "[-h | PLANO] [ID | intervalo | all]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente:

```text
Uso: /make-all PLANO [ID | INTERVALO | all]

Formas:
  /make-all 0007 all
  /make-all 0007 1.2
  /make-all .todo/0007-tasks.md 1.1-1.4
  /make-all legacy all

Plano explícito obrigatório. Para cada task: /make-task → sessão nova de /make-ac.
Modo unattended: nunca aguarda prompt, confirmação, editor ou processo sem timeout.
```

## OBJETIVO

Carregue `execute-task.md` e `audit-acceptance.md`. Para cada ID elegível, aplique integralmente `/make-task`, depois `/make-ac` em sessão lógica nova e independente. Não chame slash commands recursivamente.

Regras de orquestração:

- gates globais ficam para o fim do plano;
- bloqueio terminal aciona recuperação limitada;
- tasks e planos independentes podem continuar quando suas dependências passam;
- segurança, RED/GREEN, evidência, escopo e critérios não são relaxados;
- execução parcial nunca vira sucesso total.

## 1. Política unattended

- não faça perguntas nem espere input;
- não abra editor, pager, REPL, wizard, watch ou servidor não gerenciado;
- feche stdin e use timeout finito;
- prefira `unattended_exec.js` para comandos arbitrários do projeto;
- encerre somente processos iniciados por este supervisor;
- não autoriza instalação não declarada, deploy, publish, alteração remota, ação destrutiva, secrets ou `sudo`; `Dependency installations` validado contra a Spec já integra o contrato da task e pode rodar sem prompt;
- decisão material ou ação proibida vira bloqueio terminal sem pergunta.

## 2. Resolver e validar

Exija `PLANO` como primeiro argumento. Resolva com `work_artifacts.js`, então execute:

```bash
node "$scripts_dir/validate_tasks.js" CAMINHO_CANONICO \
  && node "$scripts_dir/validate_work_graph.js" . \
  && test -f "$scripts_dir/task_evidence.js" \
  && test -f "$scripts_dir/project_status.js" \
  && test -f "$scripts_dir/unattended_exec.js"
```

Crie apenas os namespaces do Work selecionado:

```text
.todo/evidence/NNNN/
.todo/diagnostics/NNNN/
.todo/screenshots/NNNN/
.todo/attestations/NNNN/
```

Registre seleção, IDs, revisão do contrato e checkpoints em `.todo/diagnostics/NNNN/make-all-state.md`, sem secrets.

## 3. Fila e dependências

- ID, intervalo ou `all` aplica-se somente ao plano explicitado;
- task `[x]` com verify atual pode ser retomada como implementada, mas ainda exige candidato de AC quando ausente;
- task `[!]` entra em recuperação;
- dependência local ou `NNNN/ID` precisa estar `[x]` com evidência atual;
- dependência terminalmente bloqueada faz a task dependente ser pulada;
- preserve ordem do arquivo.

## 4. Loop por task

### Implementação

Aplique `execute-task.md` ao ID:

```text
BASELINE → RED → GREEN → REFACTOR → ACs → Visual → Documentation → Gates locais → Regressão → verify → [x]
```

Não rode gates globais.

### Auditoria independente

Depois, aplique `audit-acceptance.md` em nova sessão lógica ao mesmo ID:

```text
Integridade → ACs → Visual → Documentation → Gates locais → Regressão → candidate
```

O par termina somente quando:

- marker `[x]`;
- verify retorna exit `0`;
- todos os itens são PASS ou `N/A` legítimo;
- `.todo/attestations/NNNN/ID-candidate.json` existe e corresponde ao conteúdo atual;
- nenhum processo do par permanece ativo.

### Checkpoint

Atualize o journal e execute:

```bash
node "$scripts_dir/project_status.js" NNNN --json
```

## 5. Recuperação

Até três ciclos por task. A cada falha:

1. preserve output sanitizado e causa raiz;
2. classifique a falha em uma das categorias abaixo;
3. aplique **somente** as ações permitidas para aquela categoria;
4. retome do primeiro estágio invalidado;
5. não edite evidência nem marker para fabricar PASS;
6. mesma falha sem progresso em dois ciclos encerra antecipadamente;
7. falha de Segurança/Decisão bloqueia imediatamente, sem tentativa.

### Categoria A — Processo/Ambiente

**Sintomas:** porta ocupada, timeout de build, processo órfão, lock de arquivo, variável de ambiente ausente (não secret), permissão de arquivo local, diretório inexistente, ferramenta do projeto não encontrada no PATH, dependência declarada na Spec ainda não instalada ou falha transitória do comando declarado.

**Ações permitidas (sem alterar código nem testes):**

- matar processo órfão iniciado por este supervisor;
- remover lock files temporários do build (`.lock`, `.cache`, `node_modules/.cache`);
- criar diretório ausente quando o plano ou o projeto o exigem;
- reexecutar o mesmo comando com retry (até 2 vezes) após intervalo;
- ajustar variável de ambiente **não sensível** que o projeto documenta (ex: `NODE_ENV=test`);
- executar ou repetir somente o comando exato registrado em `Dependency installations`, após validação de que todos os pacotes constam na Spec governante.

**Proibido:** instalar pacote não declarado, ampliar ou improvisar o comando autorizado, alterar `.env`, criar portas ou serviços, alterar código-fonte ou testes.

### Categoria B — Implementação/Teste

**Sintomas:** assertion falha no GREEN, AC falha após implementação, lint/build falha por código novo, regressão introduzida pela mudança.

**Ações permitidas:**

- corrigir código **exclusivamente** dentro dos `Implementation files` declarados na task;
- se o teste precisar mudar, **obrigatoriamente** refazer o ciclo completo BASELINE → RED → GREEN;
- reexecutar verify, ACs e regressão afetados;
- não alargar `Implementation files` nem `Test files` (isso é Categoria C).

**Proibido:** alterar o teste sem refazer RED→GREEN, comentar/skipar assertion, adicionar mock do SUT, mudar arquivos fora do escopo declarado.

### Categoria C — Plano/Escopo

**Sintomas:** `Implementation files` insuficientes (precisa de arquivo não declarado), AC impossível de satisfazer com o escopo atual, RED não atingível sem alterar a atomização, dependência faltando.

**Ações permitidas:**

- ajustar metadados da task no `.todo/NNNN-tasks.md`: adicionar arquivo em `Files`/`Implementation files`/`Test files`, corrigir comando de AC, adicionar dependência;
- **revalidar obrigatoriamente** o plano inteiro após qualquer ajuste:

```bash
node "$scripts_dir/validate_tasks.js" CAMINHO_CANONICO \
  && node "$scripts_dir/validate_work_graph.js" .
```

- se a revalidação falhar, a correção é inválida e conta como tentativa consumida;
- ajustes não podem violar atomicidade (máx. 3 `Implementation files`, 1 RED, 2 passos de implementação, 3 ACs);
- se a task precisar ser dividida ou o requisito mudar, isso é **bloqueio terminal** — o supervisor não re-planeja.

**Proibido:** criar tasks novas, mudar `Requirement`, alterar o título/escopo da task, remover ACs para facilitar o PASS.

### Categoria D — Segurança/Decisão

**Sintomas:** necessidade de `sudo`, deploy, publish, instalação ausente de `Dependency installations` ou cujo pacote não consta na Spec governante, secret/API key, decisão de produto ambígua, escolha de arquitetura não coberta pela Spec.

**Ação:** bloqueio terminal imediato na **primeira ocorrência** (não consome as 3 tentativas).

```markdown
### [!] [1.3] Título — BLOCKED (segurança): requer `npm install` não autorizado; evidência: `.todo/evidence/NNNN/1.3-red.log`
```

**Proibido:** tentar contornar, pedir confirmação (modo unattended), inventar alternativa que mude o escopo.

### Regra de cascata

Tasks dependentes de uma task bloqueada (qualquer categoria) são **puladas**, não bloqueadas — o marker permanece `[ ]`, não `[!]`. tasks independentes no mesmo plano continuam normalmente. A task pulada pode ser retomada em invocação futura quando a dependência for resolvida.

## 6. Gates globais

Quando todas as tasks do plano estiverem concluídas e auditadas, execute Global gates uma vez. Falha global:

- não reabre automaticamente tasks aprovadas;
- não recebe correção invisível;
- precisa gerar task explícita de remediação no mesmo `.todo/NNNN-tasks.md` antes de nova implementação;
- mantém o plano em verificação bloqueada.

## 7. Convergência e relatório

Execute `project_status.js NNNN --json`. A invocação só passa quando todos os IDs selecionados possuem marker `[x]`, verify atual, candidato de AC atual e processos encerrados; para `all`, gates globais também precisam passar ou ser `N/A`.

Reporte uma única conclusão:

```markdown
## make-all NNNN

| Task | make-task | make-ac | Candidate | Recovery | Final |
|------|-----------|---------|-----------|----------|-------|
| 1.1 | PASS | PASS | PASS | 0 | VERIFIED |

Global gates: PASS | FAIL | BLOCKED | N/A
Processos remanescentes: nenhum | lista
Pendências: nenhuma | lista
```

Com pendência, termine `⛔ EXECUÇÃO AUTÔNOMA ENCERRADA COM PENDÊNCIAS`. Sem pendência, termine `✅ MAKE-ALL CONCLUÍDO`.
