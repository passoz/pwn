---
description: Converte uma fonte em `.todo/NNNN-tasks.md` determinístico, atomizado e explicitamente selecionável.
argument-hint: "[-h | NNNN | fonte | instrução] [--work NNNN]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente:

```text
Uso: /make-todo [NNNN | FONTE | INSTRUÇÃO] [--work NNNN]

Formas:
  /make-todo 0007                         Usa `.prompts/0007-change.md` e cria `.todo/0007-tasks.md`.
  /make-todo .prompts/0007-change.md      Resolve o Work ID pelo caminho canônico.
  /make-todo "corrigir consulta"          Reserva um Work ID e planeja a fonte textual.
  /make-todo -h                           Exibe esta ajuda.

Saída: .todo/NNNN-tasks.md
Contrato atual: v3
Execução posterior exige alvo explícito.
```

## PROTOCOLO

1. Todo plano novo usa Work ID de quatro dígitos e contrato v3.
2. O destino é sempre `.todo/NNNN-tasks.md`; argumento `.md` é fonte, nunca destino.
3. Use `.work/NNNN.json` para resolver source, prompt e plan.
4. Se não houver Work ID, reserve-o com `work_artifacts.js`; nunca calcule ou grave o número manualmente.
5. Descubra componentes e comandos reais; não invente scripts, flags, portas ou selectors.
6. Atomize: uma task, um requisito primário, um comportamento, um RED e no máximo três arquivos de implementação.
7. Dependências locais usam `1.2`; dependências de outro plano do mesmo repositório usam `NNNN/1.2`.
8. Nenhuma dependência pode atravessar repositórios.
9. Não deixe marcadores abertos nem comandos perigosos; instalação de dependência só é permitida pelo contrato explícito abaixo quando a própria Spec governante declarar o pacote.

## 1. Selecionar fonte e Work ID

Resolva `scripts_dir` relativo à skill.

- Alvo `NNNN`: leia `.work/NNNN.json` e use `.prompts/NNNN-change.md`.
- Caminho `.prompts/NNNN-change.md`: exija manifesto e declaração do mesmo NNNN.
- Outra fonte existente ou texto: reserve novo trabalho com `work_artifacts.js`, preserve a origem em `.sources/NNNN-*`, produza primeiro `.prompts/NNNN-change.md` conforme `/make-prompt` e só então planeje.
- `--work NNNN`: reutiliza somente reserva compatível.
- Sem argumento: não escolha o prompt mais recente; peça alvo explícito ou use a intenção inequívoca da conversa para reservar novo trabalho.

Nunca sobrescreva `.todo/NNNN-tasks.md`. Estado `planned`, `active`, `blocked`, `completed` ou `abandoned` exige ação explícita de sucessão ou retomada.

## 2. Descobrir componentes e comandos

Inspecione arquivos versionados, ignorando dependências e builds. Para cada componente, procure comandos nesta ordem:

1. `AGENTS.md` aplicável;
2. `Makefile`;
3. scripts do manifesto;
4. CI;
5. README;
6. fallback nativo inequívoco;
7. ausência remanescente exige pergunta ou bloqueio.

Lint, build, coverage, segurança, dev e health são `N/A` quando ausentes. Não invente nem instale ferramentas auxiliares. Dependências do produto declaradas pela Spec podem ser planejadas no contrato explícito abaixo. Coverage só bloqueia quando existe threshold configurado.

## 3. Formato do plano

```markdown
# Tasks: nome concreto
**Contract version:** 3
**Work ID:** NNNN

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| componente-real | `.` | `comando real` | `N/A` | `comando real` | `N/A` | `N/A` | `N/A` |

## Global gates
N/A

### [ ] [1.1] Título específico

**Requirement:** FR-001
**Depends on:** none
**Dependency installations:**
- `comando exato de instalação` — declared in `.specs/system.md`.
**Behavior:** um comportamento observável extraído diretamente da Spec/Prompt.
**Components:** componente-real
**Files:** caminhos reais.
**Implementation files:** até três caminhos de produção.
**Test files:** caminhos de teste separados.

**RED:**
- `comando focado real` — exit não zero pela assertion nova no SUT real. O comando DEVE provar o cenário de falha correspondente aos Critérios de Aceite do Prompt.

**Implementation:**
1. Alteração mínima que implementa o comportamento.

**ACs:**
- [ ] `comando concreto` — exercita o SUT real e termina com exit 0. Os ACs aqui planejados DEVEM traduzir com exatidão os cenários Given/When/Then (US-NNN/SC-NNN) do Prompt.

**Visual:** N/A

**Documentation:** N/A
```

Omita `Dependency installations` quando não houver instalação. Quando houver, cada linha deve conter um comando exato de instalação e o caminho da Spec governante. A Spec declara os nomes canônicos em uma linha `**Dependencies:**` (ou `**Dependências:**`) com cada pacote em código inline, por exemplo `**Dependencies:** \`fastify\`, \`@fastify/cors\``. O validador só libera o comando quando todos os pacotes nomeados aparecem nessa declaração; a declaração não libera `sudo`, download canalizado para shell, deploy, publish nem outras ações inseguras.

Use `Visual: REQUIRED` somente com route, selector, Playwright e expected reais. Use `Documentation: REQUIRED` para mudanças públicas ou operacionais quando houver destino canônico, incluindo Audience, Files, Sections, Sources e Evidence executável.

## 4. Atomização e dependências

Uma task:

- possui um `FR-*`, `QR-*`, `EC-*`, `SC-*` ou `SOURCE-*` primário exclusivo;
- entrega um resultado observável;
- possui um único RED;
- tem no máximo 2 passos de implementação e 3 ACs;
- pode ser concluída, revertida e auditada isoladamente;
- não é uma camada técnica sem valor próprio.

`Depends on` aceita:

- `none`;
- IDs locais anteriores, como `1.1`;
- IDs qualificados, como `0006/2.1`.

Após salvar, `validate_work_graph.js` confirma existência e ausência de ciclos entre planos. A conclusão de uma dependência externa exige marker `[x]` e evidência atual do plano referenciado durante execução.

## 5. Segurança

Rejeite comandos com `sudo`, `eval`, download canalizado para shell, instalação não declarada, deploy, publish, alteração remota, reset/clean destrutivo, rollback de migration, remoção destrutiva ou exposição de secrets. Instalação de dependência do produto é permitida somente quando estiver explicitamente declarada em `Dependency installations` e o pacote constar na Spec governante; necessidade não comprovada continua sendo bloqueio explícito. Não invente aprovação.

## 6. Salvamento e validação

1. Salve `.todo/NNNN-tasks.md` com contrato v3 e Work ID correspondente.
2. Execute:

```bash
node "$scripts_dir/validate_tasks.js" ".todo/NNNN-tasks.md" \
  && node "$scripts_dir/validate_work_graph.js" . \
  && test -f "$scripts_dir/task_evidence.js"
```

3. Corrija somente erros relatados, no máximo 3 vezes.
4. Após PASS, atualize `.work/NNNN.json` para `planned`.
5. Nunca declare PASS sem observar exit `0` de ambos os validadores.

Em sucesso:

```text
Work ID: NNNN
Tasks salvas em: .todo/NNNN-tasks.md
Contrato de tasks: v3
Validação estrutural e do grafo: PASS
Próximo passo: /make-task NNNN all
```

## 7. Compatibilidade legada

`.todo/tasks.md` continua executável apenas pelo alvo `legacy`. Novos planos nunca usam esse nome. Migração de layout é previewável e explícita:

```bash
node "$scripts_dir/work_artifacts.js" migrate-legacy
node "$scripts_dir/work_artifacts.js" migrate-legacy --write
```

Migração de contrato para v3 exige Work ID explícito no `validate_tasks.js`. Nenhuma migração acontece durante execução.
