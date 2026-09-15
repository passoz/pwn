# 📖 Manual Completo do Piwerness (`pwn`)

> **Guia Técnico de Arquitetura, Governança Contratual e Execução de Agentes**  
> *Versão do Harness: 1.0 (Bun / TypeScript)*

---

## 📑 Sumário

1. [Introdução & Filosofia](#1-introdução--filosofia)
2. [Arquitetura Normativa em JSON (DEC-029)](#2-arquitetura-normativa-em-json-dec-029)
3. [Contract Engine v4 & As 7 Dimensões Contratuais](#3-contract-engine-v4--as-7-dimensões-contratuais)
4. [Níveis de Risco (L0–L4) e Estratégias de Validação](#4-níveis-de-risco-l0l4-e-estratégias-de-validação)
5. [Guarda Mecânica de Escrita (Diff Guard)](#5-guarda-mecânica-de-escrita-diff-guard)
6. [Portões Determinísticos (Gates)](#6-portões-determinísticos-gates)
7. [Roteamento Econômico por Papéis & Escalação](#7-roteamento-econômico-por-papéis--escalação)
8. [Sandboxes em Git Worktree](#8-sandboxes-em-git-worktree)
9. [Fila Assíncrona de Revisão Humana (AFK)](#9-fila-assíncrona-de-revisão-humana-afk)
10. [Materializador Multialvo (Pi, OpenCode, omp)](#10-materializador-multialvo-pi-opencode-omp)
11. [Editor Visual Standalone (`pwn-gui`)](#11-editor-visual-standalone-pwn-gui)
12. [Telemetria de Métricas & Teach Skills](#12-telemetria-de-métricas--teach-skills)
13. [Referência de Comandos do CLI](#13-referência-de-comandos-do-cli)
14. [Tutorial Passo a Passo: Criando um Work Greenfield](#14-tutorial-passo-a-passo-criando-um-work-greenfield)

---

## 1. Introdução & Filosofia

O **Piwerness** (`pwn`) foi projetado para resolver o maior problema de agentes autônomos de desenvolvimento de software: **a degradação silenciosa e o desvio de escopo (scope drift)**.

Diferente de assistentes convencionais baseados unicamente em instruções genéricas em Markdown, o Piwerness opera sob o princípio de **Governança por Contratos Nativos**. Toda decisão de arquitetura, tarefa atômica e modificação no código-fonte deve ser respaldada por um contrato auditável e verificada deterministicamente por código TypeScript nativo.

### Princípios Fundamentais:
1. **Contratos antes da Execução:** Nenhum código é modificado sem um contrato congelado V4.
2. **Determinismo em Gates:** Transições de estágio de produto/engenharia não dependem da opinião do LLM; dependem da checagem mecânica dos artefatos.
3. **Escrita Restrita (Allowlist-First):** O executor de IA só pode alterar arquivos listados na `write_allow` do contrato.
4. **Isolamento Total:** Execuções ocorrem em Git Worktrees descartáveis.
5. **Roteamento Proporcional ao Risco:** Tarefas simples usam modelos locais/econômicos (`cheap`); tarefas complexas ou com falhas sobem para modelos de alto raciocínio (`strong`).

---

## 2. Arquitetura Normativa em JSON (DEC-029)

Conforme estabelecido pela **DEC-029**, todos os documentos que regem o comportamento do harness e o fluxo do projeto são **arquivos JSON estritamente validados contra JSON Schemas** localizados em `schemas/`:

| Artefato | Localização Padrão | Schema Corresponde | Função |
|---|---|---|---|
| **Pipeline** | `packs/core/pipeline-core.json` | `schemas/pipeline.schema.json` | Define estágios do fluxo e gates exigidos |
| **Especificação do Sistema** | `.specs/system.json` | `schemas/system.schema.json` | Grava atores, capacidades e regras do sistema |
| **Plano de Tarefas** | `todo.json` | `schemas/tasks.schema.json` | Armazena o plano de execução e progresso |
| **Decisão de Produto (PRD)** | `.piwerness/work/<id>/prd.json` | `schemas/prd.schema.json` | Declara requisitos aceitos e não alvos |
| **Evidências de Auditoria** | `.piwerness/work/<id>/evidence.json` | `schemas/evidence.schema.json` | Registra logs e provas de execução |

### Validação dos Documentos:
Você pode validar a integridade de todos os documentos normativos do repositório a qualquer momento com:
```bash
bun bin/pwn.js validate
```

---

## 3. Contract Engine v4 & As 7 Dimensões Contratuais

Cada tarefa executada pelo Piwerness possui um **Task Contract V4**. O contrato estrutura 7 dimensões essenciais para garantir que a IA execute exatamente o que foi solicitado:

1. **Behavioral Contract (`behavioral_contract`):**
   - Cenários em formato Given/When/Then.
   - Declara o comportamento esperado e casos de borda.
2. **Change Contract (`change_contract`):**
   - Define a estratégia de validação (`tdd-strict`, `contract-first`, `regression-guarded`, `visual-contract`).
   - Define o tipo de mudança (`additive`, `refactor`, `breaking`, `fix`).
3. **Architecture Contract (`architecture_contract`):**
   - Componentes afetados, dependências permitidas e proibidas.
   - Padrões arquiteturais obrigatórios.
4. **Acceptance Contract (`acceptance_contract`):**
   - Comandos de validação (ex: `bun test`).
   - Critérios de aceite quantitativos e qualitativos.
5. **Scope Contract (`scope_contract`):**
   - `write_allow`: Padrões Glob de arquivos permitidos para edição (ex: `src/**`, `tests/**`).
   - `write_deny`: Padrões Glob de arquivos proibidos (ex: `.git/**`, `package.json`).
   - `out_of_scope`: Descrição textual do que não deve ser tocado.
6. **Budget Contract (`budget_contract`):**
   - Limite de tentativas (`max_attempts`, padrão: 3).
   - Limite de duração em minutos (`max_duration_minutes`).
   - Teto orçamentário em USD (`max_cost_usd`).
7. **Escalation Contract (`escalation_contract`):**
   - Ação em caso de violação de escrita (`on_write_violation`: `block_and_escalate`).
   - Ação em caso de estouro de orçamento (`on_budget_exceeded`: `escalate_to_strong_agent`).
   - Ação em caso de falha de tentativas (`on_attempt_failed`: `retry_with_strong`).

### Gerando a Cápsula de Contexto:
Para visualizar o resumo formatado do contrato V4 congelado para uma tarefa:
```bash
bun bin/pwn.js task capsule T-001 0001
```

---

## 4. Níveis de Risco (L0–L4) e Estratégias de Validação

O Piwerness classifica as tarefas em 5 níveis formais de risco:

- **L0 (Trivial):** Ajustes de documentação, comentários ou typos. Validação por lint/parse.
- **L1 (Low Risk):** Adição de funções puras ou novas habilidades com cobertura de testes unitários isolados.
- **L2 (Medium Risk):** Alteração de lógica de negócios existente, refatorações internas ou novos subcomandos CLI. Requer suíte de testes de regressão.
- **L3 (High Risk):** Alterações de API, schemas, interações com sistema de arquivos ou integrações de módulos. Requer aprovação estrita em gates de Spec/Plan.
- **L4 (Critical Risk):** Alteração de invariantes de segurança, migrações de dados, ações destrutivas ou mudanças na raiz do harness. **Exige suspensão imediata e aprovação na Fila Humana AFK (`queue/review/`)**.

---

## 5. Guarda Mecânica de Escrita (Diff Guard)

O **Diff Guard** (`src/core/contract-guard.ts`) é o mecanismo de segurança que intercepta as alterações feitas pelo executor.

### Funcionamento:
1. Após a execução de uma tarefa, o Diff Guard lê os arquivos modificados (`git diff --name-only`).
2. Para cada arquivo modificado:
   - Verifica se o caminho corresponde a algum padrão em `write_deny`. Se sim ➔ **Violação Crítica (`write_deny`)**.
   - Verifica se o caminho corresponde a algum padrão em `write_allow`. Se não ➔ **Violação (`not_in_write_allow`)**.
3. Em caso de violação:
   - A execução é imediatamente **bloqueada**.
   - O estado do arquivo é revertido no sandbox.
   - O incidente é registrado nas métricas e a tarefa é enviada para a fila de escalação/revisão.

---

## 6. Portões Determinísticos (Gates)

Os portões (*gates*) são funções TypeScript nativas em `src/core/gates.ts` que validam se um Work possui todos os artefatos necessários antes de avançar para a próxima fase.

### Portões Disponíveis:
- **`GATE-DISC-REQ`:** Valida se `discovery.json` e `requirements.json` existem no Work e se todos os requisitos possuem critérios de aceite testáveis.
- **`GATE-REQ-PRD`:** Valida se `prd.json` está preenchido e vincula explicitamente os requisitos aceitos (`accepted_requirements`).
- **`GATE-PRD-SPEC`:** Valida se a especificação técnica `spec.json` existe e se cada capacidade possui regras de negócio mapeadas (`rules`).
- **`GATE-SPEC-PLAN`:** Valida se `plan.json` foi derivado da spec e se contém tarefas atomizadas.
- **`GATE-PLAN-CONTRACT`:** Valida se todas as tarefas do plano possuem contratos V4 congelados (`contract_id`).

### Enforcement no caminho de execução (fail-closed):

A cadeia determinística **não é opcional no runtime**: por padrão, `pwn work run` avalia os 5 gates **em ordem** sobre os artefatos do Work antes de executar qualquer comando. Qualquer gate com `result: "blocked"` (incluindo artefato ausente — ex: `spec.json` ou `plan.json`) **bloqueia a execução com exit 1**. A única forma de contornar os *gates* é a flag explícita `--no-gate`, uma decisão de operador humano para risco aceito, registrada na saída.

Além dos gates, `pwn work run` executa o comando **sob contrato**: carrega os contratos V4 congelados,
aplica a política de shell (allowlist dos comandos de aceitação), cria um **Git Worktree sandbox**,
roda o comando mediado pela Tool API, verifica o **Diff Guard** sobre os arquivos modificados e
registra telemetria. O escape do sandbox é `--no-isolation` (executa no diretório de trabalho, com
política ainda ativa); não há escape para a política de shell.

```bash
# Default: gates + sandbox + diff guard
bun bin/pwn.js work run --work 0001 --timeout-seconds 600 -- bun test

# Pula os gates (governança), mas mantém o enforcement
bun bin/pwn.js work run --no-gate --work 0001 --timeout-seconds 600 -- bun test

# Pula o sandbox (executa no diretório de trabalho), política continua ativa
bun bin/pwn.js work run --no-isolation --work 0001 --timeout-seconds 600 -- bun test
```

### Executando um Gate:
```bash
bun bin/pwn.js work gate GATE-DISC-REQ --work 0001
```

Retorno JSON do Gate:
```json
{
  "gate": "GATE-DISC-REQ",
  "work_id": "0001",
  "result": "pass",
  "summary": { "covered": 5, "gaps": 0, "conflicts": 0, "ambiguities": 0 },
  "findings": []
}
```

---

## 7. Roteamento Econômico por Papéis & Escalação

 O Piwerness reduz custos de LLM utilizando um sistema de **Roteamento por Papéis** (`src/core/router.ts`):

- **`cheap` (Agente Local / Econômico):** Utilizado por padrão para execução de código e tarefas atômicas (ex: `qwen3.5:27b`).
- **`strong` (Agente de Alto Raciocínio):** Utilizado para arquitetura, resolução de conflitos em gates ou quando o agente `cheap` falha (ex: `claude-3-7-sonnet`).
- **`plan` (Planner):** Papel dedicado à decomposição de specs em tarefas atomizadas.
- **`review` (Auditor):** Papel dedicado à verificação final de PRD e auditoria de contratos.

### Regras de Escalação Automática:
Se um agente `cheap` estiver executando uma tarefa e:
1. Cometer uma **violação de escrita** (Diff Guard) ➔ Escala imediatamente para `strong`.
2. Violar um **invariante de contrato** ➔ Escala imediatamente para `strong`.
3. Esgotar o **limite de tentativas** (`max_attempts`) ➔ Escala para `strong`.

---

## 8. Sandboxes em Git Worktree

Para evitar que execuções mal sucedidas de agentes corrompam a árvore de trabalho principal ou deixem arquivos pela metade, o Piwerness utiliza o **Git Worktree Sandbox** (`src/core/sandbox.ts`).

### Ciclo de Vida:
1. Ao iniciar a execução de uma run (`RUN-xxx`), o Piwerness invoca `createGitWorktreeSandbox('RUN-xxx')`.
2. Um diretório isolado é criado em `.piwerness/sandboxes/RUN-xxx/` associado a uma branch temporária `pwn-sandbox-RUN-xxx`.
3. O agente executa todas as edições e rodadas de testes dentro deste diretório isolado.
4. Se o teste e a validação do contrato passarem com sucesso, o commit é integrado ao branch principal.
5. Em seguida, `cleanupGitWorktreeSandbox` remove limpo a worktree e a branch temporária.

---

## 9. Fila Assíncrona de Revisão Humana (AFK)

Quando o Piwerness é executado em modo não supervisionado (AFK - *Away From Keyboard*), tarefas de risco **L4** ou tarefas que falharam após escalação são pausadas e enviadas para a **Fila de Revisão Humana** (`src/core/queue.ts`).

- **Diretório da Fila:** `queue/review/<run-id>.json`
- **Sinal de suspensão:** a run sai com **exit code `3`** (não `0`), para que loops AFK não tratem
  "não executou, aguarda humano" como sucesso. O manifest do Work **não** é sincronizado nesse caso.

### Interagindo com a Fila via CLI:

1. **Listar tarefas em aguardo:**
   ```bash
   bun bin/pwn.js queue list
   ```
2. **Aprovar uma tarefa suspensa:**
   ```bash
   bun bin/pwn.js queue approve RUN-001
   ```
3. **Rejeitar uma tarefa suspensa:**
   ```bash
   bun bin/pwn.js queue reject RUN-001
   ```

---

## 10. Materializador Multialvo (Pi, OpenCode, omp)

O Piwerness é agnóstico de runtime de IA. O **Target Materializer** (`src/core/target-materializer.ts`) utiliza uma **Matriz de Capacidades** para transformar as especificações do Piwerness nos formatos nativos de cada ferramenta, sem perda silenciosa:

| Target | Nome | System Prompt | Sub-agentes | Tool Calling | Contratos V4 | Sandboxes | Formato Gerado |
|---|---|---|---|---|---|---|---|
| **`pi`** | Pi Agent Harness | ✓ | ✓ | ✓ | ✓ | ✓ | `AGENTS.md` |
| **`opencode`** | OpenCode Interpreter | ✓ | ✓ | ✓ | ✓ | ✓ | `AGENTS.md`, `opencode.jsonc` |
| **`omp`** | omp CLI Assistant | ✓ | ✗ | ✗ | ✗ | ✗ | `omp.json` *(com degradação graciosa)* |
| **`raw`** | Raw Model API | ✓ | ✗ | ✗ | ✗ | ✗ | `prompt.txt` |

### Comandos de Target:
```bash
# Exibir matriz de capacidades
bun bin/pwn.js target list

# Materializar artefatos para OpenCode
bun bin/pwn.js target materialize --target opencode
```

---

## 11. Editor Visual Standalone (`pwn-gui`)

O **pwn-gui** é o utilitário web visual do Piwerness para inspeção e edição gráfica de pipelines:

- **Localização:** `tools/pipeline-editor/index.html`
- **Sem Dependências de Servidor:** Funciona abrindo diretamente no navegador (`file://`).

### Principais Recursos:
- **Grafo Visual de Estágios:** Visualização de etapas com badges de portões (`🔒 GATE-DISC-REQ`) e papéis de agentes.
- **Live Code Editor:** Edição dual-pane em tempo real de especificações JSON.
- **Validação de Schema:** Indicação instantânea de conformidade com `schemas/pipeline.schema.json`.
- **Exportação:** Botão para carregar exemplo e exportar o pipeline finalizado em `.json`.

---

## 12. Telemetria de Métricas & Teach Skills

### Métricas de Execução (`src/core/metrics.ts`):
Cada run grava uma linha em `.piwerness/metrics.jsonl`, com tokens de entrada/saída, custo estimado
em USD, duração, tentativas, taxa de sucesso e o campo `isolated` — `true` para execuções em Git
Worktree sandbox e `false` para escapes com `--no-isolation`, permitindo auditar depois quais runs
rodaram sem isolamento.

### Sugestões de Otimização de Routing:
O comando `pwn metrics optimize` analisa o histórico e gera sugestões consultivas (sem alterar arquivos automaticamente):
```bash
bun bin/pwn.js metrics optimize
```
*Exemplo de saída:*
> `[Sugestão #1] Papel Atual: strong (<modelos reais do histórico>) -> Recomendado: cheap`  
> `Motivo: 5 execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para 'cheap'.`  
> `Economia Estimada: 65%` (heurística declarativa, não medida)

### Teach Skills (`src/core/learnings.ts`):
Guarda aprendizados e convenções descobertas durante execuções locais em `.piwerness/learnings.json` (gitignored), permitindo a consolidação contínua de lições de engenharia.

---

## 13. Referência de Comandos do CLI

### `pwn validate [--work <work-id>]`
Valida os documentos normativos do projeto contra os JSON Schemas formais (ajv).
Com `--work NNNN`, valida apenas aquele Work; sem argumento, valida todos os Works presentes em
`.piwerness/work/`. Em um repositório sem Works, cai no fallback que valida o conjunto normativo core
(`spec.json`, `todo.json`, `.specs/system.json`, `packs/core/pipeline-core.json`) — o mesmo alvo de
`pwn self-check`.

> Um argumento posicional (ex.: `pwn validate spec.json`) **não** é interpretado como caminho.

### `pwn work init [work-id]`
Inicializa a estrutura de artefatos de um novo Work em `.piwerness/work/<work-id>/`. Se `<work-id>` for omitido, o Piwerness calcula e atribui **automaticamente o próximo ID sequencial** (ex: `0001`, `0002`, `0003`...).

### `pwn work gate <gate-id> [--work <work-id>]`
Executa a validação determinística de um portão (`GATE-DISC-REQ`, `GATE-REQ-PRD`, `GATE-PRD-SPEC`, `GATE-SPEC-PLAN`, `GATE-PLAN-CONTRACT`). Se `--work` for omitido, utiliza **automaticamente o último Work ID ativo**.

### `pwn work specify [prompt.md] [system-spec.md]`
Valida um prompt de mudança (`.prompts/NNNN-change.md`) contra a especificação do sistema via
`validate_prompt`. Exige os dois argumentos posicionais.

### `pwn work scaffold --title "<titulo>" [--work NNNN] [--source spec.md] [--risk Lx] [--dir PATH] [--force]`
Cria um Work novo com a cadeia **completa e válida**: `discovery.json`, `requirements.json`,
`prd.json` (schema), `spec.json`, `plan.json` (schema, task `1.1`), `CTR-001.json` (contrato V4
congelado), `traceability-matrix.json` e o markdown derivado `.todo/NNNN-tasks.md`. Os valores são
um **esqueleto** que o operador deve detalhar; o comando imprime exatamente o que revisar.

### `pwn work import [--work NNNN | --all] [--dir PATH] [--gate-chain] [--force] [--risk Lx|auto]`
Converte Works de um projeto que ainda usa o **layout v3** (`.work/NNNN.json`, `.todo/NNNN-tasks.md`,
`.prompts/`, `.sources/`, `.specs/system.md`) para o layout canônico `.piwerness/work/NNNN/`:
`plan.json` (round-trip byte-a-byte com o markdown v3), `CTR-*.json` derivados de RED/ACs/Files reais
e, com `--gate-chain`, também `discovery/requirements/prd/spec/traceability`. **Nunca** altera os
artefatos v3. Sem `--force`, não sobrescreve artefatos já importados.

`--risk auto` classifica o risco **por task** a partir das próprias declarações (título, behavior,
arquivos, RED e ACs):
- **L3** — superfícies sensíveis: auth/sessão/credencial, pagamento/estorno, webhook/HMAC,
  CORS/CSRF/rate limit, privacidade/LGPD, middleware de autorização, cripto.
- **L1** — apenas documentação/README/formatação.
- **L2** — todo o resto.

**L4 nunca é atribuído automaticamente** — ele suspende a execução para revisão humana, o que
precisa ser decisão deliberada do operador. O comando imprime o mapa `task→risco` e
`task→capability` para revisão.

### `pwn work contract [--work <work-id>]`
Valida os **contratos V4 congelados** do Work: carrega `plan.json`, resolve o `contract_id` de cada
task e verifica `.piwerness/work/<id>/CTR-*.json` (versão 4.0, `risk.level`, `write_allow` não vazio e
`acceptance_contract.commands` não vazio — a política de shell é fail-closed). Sai com `0` (PASS) ou
`1` (FAIL), listando cada task.

### `pwn work run [--work <work-id>] [--task <task-id>] [--no-gate] [--no-isolation] -- <comando>...`
Executa o Work sob contrato via `run-orchestrator` (não há mais wrapper `unattended_exec.js`):
carrega os contratos V4 congelados, aplica a política de shell (allowlist derivada dos comandos de
aceitação), cria um Git Worktree sandbox, media a execução pela Tool API, roda o **Diff Guard** sobre
os arquivos modificados e grava telemetria.

**Códigos de saída:** `0` sucesso · `1` falha (gate, contrato, política ou diff guard) ·
`3` **suspenso para revisão humana** (risco L4, enfileirado em `queue/review/` sem executar).

**Enforcement por default (fail-closed):** antes de executar qualquer comando, o `work run` avalia a **cadeia determinística completa de 5 gates** (`GATE-DISC-REQ` → `GATE-REQ-PRD` → `GATE-PRD-SPEC` → `GATE-SPEC-PLAN` → `GATE-PLAN-CONTRACT`) sobre os artefatos de `.piwerness/work/<work-id>/`. Se qualquer gate retornar `blocked` (incluindo artefato ausente — ex: `spec.json` ou `plan.json`), a execução **é bloqueada com exit 1**. Modelos baratos não podem pular essa validação por decisão própria.

- `--work <work-id>`: Work a validar/executar (default: último Work ID ativo).
- `--task <task-id>`: identifica a task no relatório de falha.
- `--no-gate`: **contorna a cadeia de gates** (governança documental). O enforcement (sandbox, política, diff guard) continua ativo. Decisão explícita de humano/operador para risco aceito.
- `--no-isolation`: **contorna o sandbox** (executa no diretório de trabalho). A política de shell continua ativa e o escape fica registrado em `metrics.jsonl` (campo `isolated: false`). Use apenas quando o worktree não se aplica (ex: projeto sem git).
- `--no-sync`: **não sincroniza** o manifest v3 `.work/NNNN.json` com o estado do panorama. Por padrão o `work run` atualiza o `state`/`updated_at` desse manifest; use `--no-sync` quando o `.work/` pertencer a outra ferramenta e não deva ser reescrito.

> O Diff Guard ignora os artefatos que o próprio harness injeta no worktree (`node_modules` e
> `bunfig.toml`); escrever em `node_modules` não é uma escrita do agente, mas continua fora do
> `write_allow`.

```bash
# Executa apenas se a cadeia de 5 gates aprovar
bun bin/pwn.js work run --work 0001 --timeout-seconds 600 -- bun test

# Execução sem a cadeia de gates (decisão explícita de operador)
bun bin/pwn.js work run --no-gate --work 0001 --timeout-seconds 600 -- bun test
```

### `pwn work audit [verify|check|candidate] [--work <work-id>] [--task <task-id>] ...`
Audita evidências e aceitação TDD via `task_evidence.js`. Sem ação explícita, assume `verify`. As ações válidas são `baseline`, `red`, `green`, `verify`, `check` e `candidate` (passadas adiante); qualquer outra opção na posição de ação é rejeitada pelo validador com mensagem clara.

```bash
# Verifica evidência da task 1.1 do Work 0001
bun bin/pwn.js work audit --work 0001 --task 1.1
```

### `pwn task capsule <task-id> [work-id]`
Exibe a cápsula de contexto formatada com limites de escrita, cenários e orçamento da tarefa. Se `work-id` for omitido, utiliza **automaticamente o último Work ID ativo**.

### `pwn queue [list|approve|reject] [run-id]`
Gerencia a fila de revisão humana assíncrona.

### `pwn target [list|materialize] [--target <name>]`
Exibe a matriz de capacidades dos runtimes ou materializa artefatos no diretório target.

### `pwn metrics [list|optimize]`
Exibe estatísticas de consumo de tokens/custo ou gera sugestões de otimização de routing.

### `pwn skill`, `pwn pack`
(Removidos — o desacoplamento do `ai-engineering-skills` eliminou as skills/prompts do port e todo o
`packs/software-engineering`; o único artefato restante em `packs/` é o pipeline normativo
`core/pipeline-core.json`, validado por `pwn self-check`.)

---

## 14. Tutorial Passo a Passo: Criando um Work Greenfield

Abaixo está o fluxo para iniciar uma nova funcionalidade no Piwerness, que pode ser feito de forma automática via script ou passo a passo via CLI:

### Opção A: Modo Automatizado (Via Script Greenfield)
Execute o script informando apenas o título ou ideia da funcionalidade (o Work ID é auto-incrementado).
Ele cria a cadeia completa e válida e aprova os 5 gates:
```bash
./scripts/prepare-greenfield-work.sh "Sistema de Notificações em Tempo Real"
# Contra outro projeto: PWN_DIR=../meu-projeto ./scripts/prepare-greenfield-work.sh "Nova feature"
```

### Opção A2: Modo Direto pelo CLI
Equivalente ao script, sem o encadeamento de gates:
```bash
bun bin/pwn.js work scaffold --title "Sistema de Notificações em Tempo Real" --risk L2
bun bin/pwn.js work contract --work 0002
```
> O scaffold gera um **esqueleto** (task `1.1` com placeholders). Detalhe o `plan.json` e regenere o
> markdown com `pwn work plan --work 0002 --force` antes de implementar.

### Opção A3: Importar um projeto no layout v3
Se o projeto ainda usa `.work/`, `.todo/`, `.prompts/`, `.sources/` e `.specs/system.md`, traduza os
Works existentes para o layout canônico (sem tocar nos arquivos v3):
```bash
bun bin/pwn.js work import --all --gate-chain
```

### Opção B: Modo Passo a Passo via CLI

#### Passo 1: Inicializar a Estrutura do Work (Auto-Incrementado)
```bash
bun bin/pwn.js work init
```
O comando criará automaticamente a pasta sequencial (ex: `.piwerness/work/0002/`) com os arquivos iniciais:
- `discovery.json`
- `requirements.json`
- `prd.json`
- `traceability-matrix.json`

> `work init` cria apenas os templates. Para já obter também `spec.json`, `plan.json`,
> `CTR-001.json` e o markdown derivado (cadeia válida de ponta a ponta), use
> `pwn work scaffold` (Opção A2).

#### Passo 2: Preencher Requisitos e Rodar o Primeiro Gate
Edite `.piwerness/work/0002/requirements.json` adicionando seus requisitos e critérios de aceite. Em seguida, valide o portão (se omitido, `--work` usa o último Work ID):
```bash
bun bin/pwn.js work gate GATE-DISC-REQ
```

#### Passo 3: Consolidar o PRD e Rodar o Segundo Gate
Vincule os requisitos aceitos em `.piwerness/work/0002/prd.json` e execute:
```bash
bun bin/pwn.js work gate GATE-REQ-PRD
```

#### Passo 4: Consolidar PRD em Spec e Plano (Gates 3–5)
Com o PRD aprovado, gere a especificação técnica (`spec.json`) e o plano de tarefas com contratos (`plan.json`), validando cada transição:

```bash
bun bin/pwn.js work gate GATE-PRD-SPEC
bun bin/pwn.js work gate GATE-SPEC-PLAN
bun bin/pwn.js work gate GATE-PLAN-CONTRACT
```

#### Passo 5: Materializar Runtimes e Executar
Materialize a configuração do seu runtime de preferência (ex: OpenCode ou Pi):

```bash
bun bin/pwn.js target materialize --target opencode
```

Toda execução via `pwn work run` é **fail-closed**: sem `--no-gate`, o CLI reavalia a cadeia completa dos 5 gates sobre os artefatos e recusa (exit 1) qualquer Work com transição não aprovada ou artefato ausente. O `--no-gate` é o único escape e fica explícito na saída:

```bash
bun bin/pwn.js work run --work 0002 --timeout-seconds 600 -- bun test          # exige a cadeia aprovada
bun bin/pwn.js work run --no-gate --work 0002 --timeout-seconds 600 -- bun test # escape explícito (humano)
```

Pronto! Seu agente executará sob isolamento de Git Worktree, com Diff Guard monitorando cada alteração e total rastreabilidade.
