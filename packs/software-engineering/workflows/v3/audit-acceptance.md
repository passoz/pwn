---
description: Audita em sessão independente um plano explicitamente selecionado e emite candidato mecânico de aceitação.
argument-hint: "[-h | PLANO] [ID | intervalo | all] [--review-only]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente:

```text
Uso: /make-ac PLANO [ID | INTERVALO | all] [--review-only]

Formas:
  /make-ac 0007 1.2
  /make-ac 0007 all
  /make-ac .todo/0007-tasks.md 1.1-1.4
  /make-ac legacy 1.2 --review-only

O plano é obrigatório. A auditoria usa sessão nova, não o histórico conversacional da implementação.
```

## PROTOCOLO

1. Resolva `PLANO` explicitamente; nunca escolha `.todo/tasks.md` ou o plano mais recente por padrão.
2. Anuncie mode, source canônica, Work ID e IDs alvo.
3. Valide plano e grafo.
4. Faça diagnóstico completo antes de corrigir.
5. Ordem: Integridade → ACs → Visual → Documentation → Gates locais → Regressão.
6. Gates globais rodam somente para `all` quando todas as tasks do plano estiverem concluídas.
7. Na terceira falha, reporte bloqueio com a categoria (A–D) descrita em `execute-task.md`; não amplie escopo.
8. Falha de Segurança/Decisão (Categoria D) bloqueia imediatamente, sem consumir tentativas.
9. Nunca execute instalação nova durante a auditoria, deploy, alteração remota, ação destrutiva ou secret. `Dependency installations` validado pertence à preparação de `/make-task`; se ainda estiver pendente, classifique conforme `execute-task.md` em vez de ampliar o ambiente na auditoria.

## 1. Preparação

Execute:

```bash
node "$scripts_dir/work_artifacts.js" resolve PLANO \
  && node "$scripts_dir/validate_tasks.js" CAMINHO_CANONICO \
  && node "$scripts_dir/validate_work_graph.js" .
```

Use evidência e diagnósticos em `.todo/evidence/NNNN/` e `.todo/diagnostics/NNNN/`.

## 2. Diagnóstico

Para cada task:

### Integridade

- **Auditoria de Negócios:** cruze o diff da implementação com as diretivas de arquitetura/sistema e o Requisito original. A lógica implementa as regras reais ou apenas burla os testes (ex: hardcodes para satisfazer assertions vacuas)?
- compare Behavior, Implementation, arquivos declarados e diff;
- exija produção real para feature/bugfix;
- rejeite assertion tautológica, skip, erro ignorado, fixture autorreferente ou mock do SUT;
- execute:

```bash
node "$scripts_dir/task_evidence.js" verify --work NNNN --task ID
```

- marker `[x]` sem verify atual é FAIL;
- evidência escrita manualmente não prova execução.

### ACs

- **Auditoria Lógica:** Antes de apenas rodar os comandos, verifique o que o AC pede em linguagem humana. Se os comandos passarem mas a implementação visivelmente violar a intenção do critério ou do Spec, marque como FAIL.
- Execute cada comando do contrato e confira exit/output/SUT real.

### Visual, documentação, checks locais e regressão

Aplique exatamente as classificações do plano. HTTP 200 não comprova UI. Documento divergente ou example falho recebe FAIL. Ferramenta configurada e ausente recebe BLOCKED.

Mostre o painel completo antes das correções:

```markdown
### [NNNN/1.1] Título
- Integrity: PASS | FAIL | BLOCKED
- AC-1: PASS | FAIL | BLOCKED
- Visual: N/A | PASS | FAIL | BLOCKED
- Documentation: N/A | PASS | FAIL | BLOCKED
- Gates locais: PASS | FAIL | BLOCKED
- Regressão: PASS | FAIL | BLOCKED
```

Com `--review-only`, pare após o painel e não altere arquivos.

## 3. Correção mínima

No modo normal, corrija apenas FAIL dentro de Implementation files, Test files e documentação já declarados. Teste alterado exige novo BASELINE → RED → GREEN namespaced. Reexecute itens posteriores afetados. Cada item admite três tentativas.

`/make-ac` não altera marker para `[x]`; esse estado pertence a `/make-task`. Pode recomendar `[!]` quando o bloqueio for terminal.

## 4. Candidato de aceitação

Registre cada check observado pelo runner, sem escrever logs manualmente:

```bash
node "$scripts_dir/task_evidence.js" check --work NNNN --task ID \
  --name AC-1 -- COMANDO_DO_AC
node "$scripts_dir/task_evidence.js" check --work NNNN --task ID \
  --name REGRESSION -- COMANDO_DE_REGRESSAO
```

Use `AC-N`, `VISUAL`, `DOCUMENTATION`, `LOCAL-GATES` e `REGRESSION` conforme o plano. Itens `N/A` não são registrados como PASS. Quando Integridade, todos os ACs, Visual, Documentation, gates locais e regressão forem PASS ou `N/A` legítimo, execute:

```bash
node "$scripts_dir/task_evidence.js" candidate --work NNNN --task ID
```

O runner recusa o candidato se faltar AC, visual/documentação obrigatória ou regressão observada, ou se um log registrado tiver mudado. Depois grava:

```text
.todo/attestations/NNNN/ID-candidate.json
```

O candidato:

- contém Work ID, task ID, hash do plano, snapshots de implementação/testes e digest das evidências;
- é verificável pela suíte fora de qualquer orquestrador;
- não é assinatura de confiança e não dá acesso a chave externa;
- fica stale se o conteúdo auditado mudar;
- pode ser observado e posteriormente assinado por um supervisor externo sem repetir a sessão de agente.

## 5. Gates globais e plano agregado

Somente alvo `all` executa Global gates uma vez, após todas as tasks passarem. Falha global não recebe correção invisível: registre-a e crie uma task de remediação explícita no plano antes de novo ciclo. Quando todos passam, um consumidor pode produzir atestado agregado; a suíte não assina em nome de sistemas externos.

## 6. Resultado

Reporte Integrity, ACs, Visual, Documentation, checks locais, regressão, gates globais e caminho do candidato. Todo PASS aponta para comando, exit e evidência. Pendência termina com `⛔ PENDÊNCIAS EXIGEM INTERVENÇÃO`.
