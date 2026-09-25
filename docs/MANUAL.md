# 📖 Manual Completo do PWN — Policy Work Norms (`pwn`)

> **Guia Técnico de Arquitetura, Governança Contratual e Execução de Agentes**  
> *Versão do Harness: v0.1.0 (Bun / TypeScript)*

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
15. [Limites Conhecidos](#15-limites-conhecidos)

---

## 1. Introdução & Filosofia

O **PWN** (`pwn`) foi projetado para resolver o maior problema de agentes autônomos de desenvolvimento de software: **a degradação silenciosa e o desvio de escopo (scope drift)**.

Diferente de assistentes convencionais baseados unicamente em instruções genéricas em Markdown, o PWN opera sob o princípio de **Governança por Contratos Nativos**. Toda decisão de arquitetura, tarefa atômica e modificação no código-fonte deve ser respaldada por um contrato auditável e verificada deterministicamente por código TypeScript nativo.

### Princípios Fundamentais:
1. **Contratos antes da Execução:** Nenhum código é modificado sem um contrato congelado V4.
2. **Determinismo em Gates:** Transições de estágio de produto/engenharia não dependem da opinião do LLM; dependem da checagem mecânica dos artefatos.
3. **Escrita Restrita (Allowlist-First):** O executor de IA só pode alterar arquivos listados na `write_allow` do contrato.
4. **Isolamento Total:** Execuções ocorrem em Git Worktrees descartáveis.
5. **Roteamento Proporcional ao Risco:** Tarefas simples usam modelos locais/econômicos (`cheap`); tarefas complexas ou com falhas sobem para modelos de alto raciocínio (`strong`).
6. **Tudo tem teto declarado:** limites explícitos nos schemas (enum de `complexity`, `maxItems` de ACs/steps/componentes) forçam decomposição em vez de permitir artefatos monolíticos.
7. **Relatório completo, não primeiro erro:** verificação devolve *todos* os findings numa passada (`gate --all`, `--dry-run`, `audit` incompleto) — o gargalo é o ciclo humano, não o compute.
8. **"Incompleto" ≠ "errado":** exit code `2` (falta evidência) é distinto de `1` (violação), para automação AFK não confundir os dois.
9. **Pine a versão, não o atalho:** cache e atestação carregam `harness_version`/`gate_version`; evidência produzida sob outra versão nunca é aceita em silêncio.
10. **Valide o validador:** `self-check --mutate` quebra artefatos de propósito para provar que os gates realmente bloqueiam (ver `docs/LIMITES.md`).

---

## 2. Arquitetura Normativa em JSON (DEC-029)

Conforme estabelecido pela **DEC-029**, todos os documentos que regem o comportamento do harness e o fluxo do projeto são **arquivos JSON estritamente validados contra JSON Schemas** localizados em `schemas/`:

| Artefato | Localização Padrão | Schema Corresponde | Função |
|---|---|---|---|
| **Pipeline** | `packs/core/pipeline-core.json` | `schemas/pipeline.schema.json` | Define estágios do fluxo e gates exigidos |
| **Especificação do Sistema** | `.specs/system.json` | `schemas/system.schema.json` | Grava atores, capacidades e regras do sistema |
| **Plano de Tarefas** | `todo.json` | `schemas/tasks.schema.json` | Armazena o plano de execução e progresso |
| **Decisão de Produto (PRD)** | `.pwn/work/<id>/prd.json` | `schemas/prd.schema.json` | Declara requisitos aceitos e não alvos |
| **Evidências de Auditoria** | `.pwn/work/<id>/evidence.json` | `schemas/evidence.schema.json` | Registra logs e provas de execução |
| **Política do Projeto** (opcional) | `.pwn/policy.json` | `schemas/policy.schema.json` | Keywords de risco, thresholds e allowlists de shell/rede |

> **Política é dado, não código.** Constantes de decisão (keywords de risco, thresholds, allowlist de shell, domínios de rede) podem viver em `.pwn/policy.json` — revisável e diffável — em vez de espalhadas pelo motor. O arquivo é **opcional**: ausente ou inválido, valem os defaults embutidos e o comportamento é idêntico ao anterior. Alterar política passa a ser um diff pequeno, não um patch em três arquivos.

### Validação dos Documentos:
Você pode validar a integridade de todos os documentos normativos do repositório a qualquer momento com:
```bash
bun bin/pwn.js validate
```

### Leis embutidas e pinagem (drift)

Os schemas são **embutidos no bundle** (`import` de JSON em `src/core/validator.ts`): sob
`bun src/cli.ts` o import é resolvido do disco a cada execução; sob `bun build --compile` a
cópia congelada viaja dentro do binário. Em nenhum dos dois casos o caminho do módulo entra na
decisão — o mesmo binário, movido para outro diretório e sem `schemas/` ao lado, continua
validando contra as mesmas leis.

`schemas/` (e um `schemas/` ao lado do executável, quando existir) passa a ser apenas cópia
**revisável e diffável**. Se divergir da cópia embutida, todo comando aborta com
`leis embutidas divergem de schemas/ no disco` (exit `1`): a cópia embutida é a que vale.
Adotar uma edição de lei exige reconstruir o harness — não existe caminho em que editar
`schemas/*.json` afrouxe o enforcement em silêncio. Documento que declara um `$schema` que o
verificador não carrega é **reprovado**, nunca aceito por falta de schema.

---

## 3. Contract Engine v4 & As 7 Dimensões Contratuais

Cada tarefa executada pelo PWN possui um **Task Contract V4**. O contrato estrutura 7 dimensões essenciais para garantir que a IA execute exatamente o que foi solicitado:

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

O PWN classifica as tarefas em 5 níveis formais de risco:

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
- **`GATE-SPEC-PLAN`:** Valida se `plan.json` foi derivado da spec e se contém tarefas atomizadas. Inclui também a **validação de atomicidade** (`validateTaskAtomicity`), que emite findings *advisory* (`low`/`medium` — nunca bloqueiam) quando uma task referencia mais de uma capability, cobre mais de um componente, toca mais de 6 arquivos de implementação, ou descreve mais de 3 comportamentos independentes.
- **`GATE-PLAN-CONTRACT`:** Valida se todas as tarefas do plano possuem contratos V4 congelados (`contract_id`).

### Relatório completo em vez do primeiro erro:

`pwn work gate --all` avalia os **5 gates numa única passada** e agrupa todos os findings por gate, seguidos de um resumo (`GATE-X: pass|pass_with_notes|blocked (N findings)`). Exit `1` se qualquer gate estiver bloqueado. O objetivo é trocar N ciclos de "corrigir → rodar → descobrir o próximo problema" por um único ciclo com a lista completa.

```bash
bun bin/pwn.js work gate --all --work 0001
```

### Cache de veredicto de gate (Certificado Assinado por HMAC):

Cada gate calcula hashes (`shortHash`) dos seus inputs. O resultado é cacheado em `.pwn/gate-cache/<GATE>-<chave>.json`, envelopado em formato **v2** com `gate_version`, `harness_version`, `laws_sha256` (hash determinístico de todas as leis embutidas) e assinado com **HMAC-SHA256**.

A chave de assinatura é lida de `PWN_VERIFIER_KEY` (em CI/ambiente protegido) ou do arquivo com permissão restrita `0600` em `.pwn/.verifier_key`. Qualquer adulteração manual em disco (ex: tentar alterar `result: "blocked"` para `"pass"`) quebra o HMAC e faz o cache ser **imediatamente rejeitado**, forçando a reavaliação limpa do gate. Da mesma forma, se qualquer schema embutido mudar, o `laws_sha256` invalida caches antigos.

```bash
bun bin/pwn.js work gate GATE-DISC-REQ --work 0001   # 1ª: avalia e assina; 2ª: (cache verificado)
bun bin/pwn.js work gate GATE-DISC-REQ --work 0001 --no-cache
bun bin/pwn.js work gate --clear-cache
```

### Pré-voo de execução:

`pwn work run --dry-run` roda os 5 gates e valida os contratos V4 de cada task (`risk.level`, `write_allow` não vazio, `acceptance_contract.commands` não vazio), listando **todos** os impedimentos — sem criar sandbox, sem executar comando. Exit `1` se houver qualquer impedimento.

```bash
bun bin/pwn.js work run --dry-run --work 0001 -- bun test
```

### Cobertura agregada do Work:

`pwn work status --coverage` deriva, dos próprios artefatos, quantos requisitos estão aceitos, quantas capabilities têm regras, quantas tasks têm contrato congelado e critérios de aceite. Exit `0` quando não há lacunas, `1` caso contrário.

```bash
bun bin/pwn.js work status --coverage --work 0001
```

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

 O PWN reduz custos de LLM utilizando um sistema de **Roteamento por Papéis** (`src/core/router.ts`):

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

## 8. Sandboxes em Git Worktree + Isolamento OS (Bubblewrap)

Para evitar que execuções mal sucedidas ou adversariais de agentes corrompam o repositório principal, escapem para o sistema operacional ou façam exfiltração de dados via rede, o PWN combina dois níveis estritos de contenção:

1. **Isolamento de Árvore (Git Worktree):** O código é clonado para `.pwn/sandboxes/RUN-xxx/` numa branch dedicada `pwn-sandbox-RUN-xxx`. Edições de arquivos e testes ocorrem apenas nessa árvore descartável.
2. **Isolamento de Kernel (Bubblewrap / `bwrap`):** Todos os subprocessos invocados pelo agente são envelopados via `bwrap` (quando disponível no host Linux):
   - **Filesystem Read-Only:** Todo o SO (`/`) é montado em `--ro-bind` somente-leitura. Tentativas de escrever fora da sandbox (ex: `open('../escape.txt', 'w')`) falham com `Read-only file system` no nível do kernel.
   - **Isolamento de Rede:** Subprocessos rodam com `--unshare-net` (rede desconectada), exceto se expressamente autorizados pela política declarativa de rede.
   - **Namespace de Processos:** Rodam sob `--unshare-pid`, sem visão nem capacidade de sinalizar (`kill`, `ptrace`) processos do sistema.

### Ciclo de Vida:
1. Ao iniciar a execução de uma run (`RUN-xxx`), o PWN invoca `createGitWorktreeSandbox('RUN-xxx')`.
2. Um diretório isolado é criado em `.pwn/sandboxes/RUN-xxx/` associado à branch temporária.
3. O agente executa todas as edições e subprocessos confinados na bolha da sandbox.
4. Se o teste e a validação do contrato passarem com sucesso, o commit é integrado ao branch principal.
5. Em seguida, `cleanupGitWorktreeSandbox` remove a worktree e a branch temporária.


## 9. Fila Assíncrona de Revisão Humana (AFK)

Quando o PWN é executado em modo não supervisionado (AFK - *Away From Keyboard*), tarefas de risco **L4** ou tarefas que falharam após escalação são pausadas e enviadas para a **Fila de Revisão Humana** (`src/core/queue.ts`).

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

O PWN é agnóstico de runtime de IA. O **Target Materializer** (`src/core/target-materializer.ts`) utiliza uma **Matriz de Capacidades** para transformar as especificações do PWN nos formatos nativos de cada ferramenta, sem perda silenciosa:

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

O **pwn-gui** é o utilitário web visual do PWN para inspeção e edição gráfica de pipelines:

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
Cada run grava uma linha em `.pwn/metrics.jsonl`, com tokens de entrada/saída, custo estimado
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
Guarda aprendizados e convenções descobertas durante execuções locais em `.pwn/learnings.json` (gitignored), permitindo a consolidação contínua de lições de engenharia.

---

## 13. Referência de Comandos do CLI

### `pwn validate [--work <work-id>]`
Valida os documentos normativos do projeto contra os JSON Schemas formais (ajv).
Com `--work NNNN`, valida apenas aquele Work; sem argumento, valida todos os Works presentes em
`.pwn/work/`. Em um repositório sem Works, cai no fallback que valida o conjunto normativo core
(`spec.json`, `todo.json`, `.specs/system.json`, `packs/core/pipeline-core.json`) — o mesmo alvo de
`pwn self-check`.

> Um argumento posicional (ex.: `pwn validate spec.json`) **não** é interpretado como caminho.

### `pwn work init [work-id]`
Inicializa a estrutura de artefatos de um novo Work em `.pwn/work/<work-id>/`. Se `<work-id>` for omitido, o PWN calcula e atribui **automaticamente o próximo ID sequencial** (ex: `0001`, `0002`, `0003`...).

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
`.prompts/`, `.sources/`, `.specs/system.md`) para o layout canônico `.pwn/work/NNNN/`:
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
task e verifica `.pwn/work/<id>/CTR-*.json` (versão 4.0, `risk.level`, `write_allow` não vazio e
`acceptance_contract.commands` não vazio — a política de shell é fail-closed). Sai com `0` (PASS) ou
`1` (FAIL), listando cada task.

### `pwn work run [--work <work-id>] [--task <task-id>] [--no-gate] [--no-isolation] -- <comando>...`
Executa o Work sob contrato via `run-orchestrator` (não há mais wrapper `unattended_exec.js`):
carrega os contratos V4 congelados, aplica a política de shell (allowlist derivada dos comandos de
aceitação), cria um Git Worktree sandbox, media a execução pela Tool API, roda o **Diff Guard** sobre
os arquivos modificados e grava telemetria.

**Códigos de saída:** `0` sucesso · `1` falha (gate, contrato, política ou diff guard) ·
`3` **suspenso para revisão humana** (risco L4, enfileirado em `queue/review/` sem executar).

**Enforcement por default (fail-closed):** antes de executar qualquer comando, o `work run` avalia a **cadeia determinística completa de 5 gates** (`GATE-DISC-REQ` → `GATE-REQ-PRD` → `GATE-PRD-SPEC` → `GATE-SPEC-PLAN` → `GATE-PLAN-CONTRACT`) sobre os artefatos de `.pwn/work/<work-id>/`. Se qualquer gate retornar `blocked` (incluindo artefato ausente — ex: `spec.json` ou `plan.json`), a execução **é bloqueada com exit 1**. Modelos baratos não podem pular essa validação por decisão própria.

- `--work <work-id>`: Work a validar/executar (default: último Work ID ativo).
- `--task <task-id>`: identifica a task no relatório de falha.
- `--no-gate`: **contorna a cadeia de gates** (governança documental). O enforcement (sandbox, política, diff guard) continua ativo. Decisão explícita de humano/operador para risco aceito.
- `--no-isolation`: **contorna o sandbox** (executa no diretório de trabalho). A política de shell continua ativa e o escape fica registrado em `metrics.jsonl` (campo `isolated: false`). Use apenas quando o worktree não se aplica (ex: projeto sem git).
- `--no-sync`: **não sincroniza** o manifest v3 `.work/NNNN.json` com o estado do panorama. Por padrão o `work run` atualiza o `state`/`updated_at` desse manifest; use `--no-sync` quando o `.work/` pertencer a outra ferramenta e não deva ser reescrito.

> O Diff Guard ignora **os artefatos que o próprio harness acabou de injetar** no worktree
> (`node_modules` linkado e `bunfig.toml` copiado), identificados pela assinatura do que foi
> criado — não pelo nome. Substituir o artefato (trocar o link por um arquivo, apontar o link
> para outro lugar) devolve o caminho ao inventário. Um `bunfig.toml` versionado no
> repositório não é injetado, então alterá-lo é reportado mesmo estando em `write_allow`.
>
> Renomeações são reportadas pelo **destino e pela origem**: mover um arquivo para fora do
> escopo é escrita fora do escopo, e omitir a origem esconderia a remoção. Escrever em
> `node_modules` continua fora do `write_allow`.

```bash
# Executa apenas se a cadeia de 5 gates aprovar
bun bin/pwn.js work run --work 0001 --timeout-seconds 600 -- bun test

# Execução sem a cadeia de gates (decisão explícita de operador)
bun bin/pwn.js work run --no-gate --work 0001 --timeout-seconds 600 -- bun test
```

### `pwn work audit [verify|check|candidate] [--work <work-id>] [--task <task-id>] -- <comando>...`
Audita evidências e aceitação TDD via `task_evidence.js`. Sem ação explícita, assume `verify`. As ações válidas são `baseline`, `red`, `green`, `verify`, `check` e `candidate` (passadas adiante); qualquer outra opção na posição de ação é rejeitada pelo validador com mensagem clara.

**O comando após `--` é obrigatório em `red`, `green`, `verify`, `check` e `candidate`.** O comando RED persistido em `.todo/evidence/<work>/state/<task>.json` é tratado como **conferência cruzada**, nunca como fonte do que será executado: o estado é um artefato versionado do repositório, e executá-lo sem confirmação do operador permitiria execução arbitrária de código a partir de um repositório hostil. Se o comando da CLI divergir do gravado, a auditoria é **violação** (`1`) e nada é executado.

**Códigos de saída por classe** (para que automação não confunda os estados):

| Código | Classe | Exemplos |
|---|---|---|
| `0` | Sucesso | RED/GREEN/verify capturados; atestação gerada |
| `1` | **Violação** | implementação alterada antes do RED; teste mudou após o GREEN; `verification invalidated`; comando divergente do RED; mutation check falhou; `--expect` não literal |
| `2` | **Incompleto** | falta baseline/RED/GREEN; AC/REGRESSION ainda não observados; plano ausente |

O código `2` imprime a lista **completa** do que falta (não para no primeiro item), o que permite corrigir tudo numa rodada.

**`--expect-literal`:** exige que o texto passado em `--expect` apareça **literalmente** em algum arquivo de `state.test_files`. Sem a flag, a validação continua sendo a comparação por substring no output (comportamento histórico).

```bash
# Verifica evidência da task 1.1 do Work 0001
bun bin/pwn.js work audit --work 0001 --task 1.1 -- node tests/calc.test.mjs

# RED com a asserção amarrada ao arquivo de teste congelado
bun bin/pwn.js work audit red --work 0001 --task 1.1 --expect "SUM-MISMATCH" --expect-literal -- node tests/calc.test.mjs

# GREEN e atestação (mesmo comando do RED)
bun bin/pwn.js work audit green --work 0001 --task 1.1 -- node tests/calc.test.mjs
bun bin/pwn.js work audit candidate --work 0001 --task 1.1 -- node tests/calc.test.mjs
```

**Atestação versionada:** o `candidate` grava `version: 2` com `harness_version` e `gate_version` (além dos campos já existentes). `readAttestation(filePath)` lê o arquivo e informa `compatible` — atestações `v1` continuam legíveis, e uma `v2` sem `harness_version` é marcada incompatível em vez de aceita em silêncio.

### `pwn self-check [--mutate [--work <work-id>]]`
Valida os documentos normativos do framework. Com `--mutate`, roda **mutation testing dos próprios gates**: copia um Work para um diretório temporário, quebra um artefato de propósito e verifica se o gate correspondente passa de `pass` para `blocked`. O relatório é explícito sobre gates que **não** bloqueiam (advisory) — é assim que se descobre um gate decorativo. Exit `1` quando uma mutação que deveria ser detectada não é; o Work real nunca é modificado.

```bash
bun bin/pwn.js self-check --mutate
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

Abaixo está o fluxo para iniciar uma nova funcionalidade no PWN, que pode ser feito de forma automática via script ou passo a passo via CLI:

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
O comando criará automaticamente a pasta sequencial (ex: `.pwn/work/0002/`) com os arquivos iniciais:
- `discovery.json`
- `requirements.json`
- `prd.json`
- `traceability-matrix.json`

> `work init` cria apenas os templates. Para já obter também `spec.json`, `plan.json`,
> `CTR-001.json` e o markdown derivado (cadeia válida de ponta a ponta), use
> `pwn work scaffold` (Opção A2).

#### Passo 2: Preencher Requisitos e Rodar o Primeiro Gate
Edite `.pwn/work/0002/requirements.json` adicionando seus requisitos e critérios de aceite. Em seguida, valide o portão (se omitido, `--work` usa o último Work ID):
```bash
bun bin/pwn.js work gate GATE-DISC-REQ
```

#### Passo 3: Consolidar o PRD e Rodar o Segundo Gate
Vincule os requisitos aceitos em `.pwn/work/0002/prd.json` e execute:
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

---

## 15. Limites Conhecidos

O harness é **honesto sobre o que não garante**. O documento completo, com evidência em código (arquivo:linha) e a alternativa recomendada para cada caso, está em **[LIMITES.md](LIMITES.md)**. Para detalhes de testes de segurança adversarial e histórico de auditoria de enforcement, consulte também o **[Plano de Teste de Segurança](SECURITY-TEST-PLAN.md)** e a **[Revisão da Fase 1 de Enforcement](REVIEW-FASE-1-ENFORCEMENT.md)**.

Resumo dos limites estruturais:

| Limite | O que isso significa na prática |
|---|---|
| Gates validam **presença e vínculo de ID**, não intenção | Um ID fabricado ou uma capability só com título passa; o gate não lê o texto para conferir se a capability implementa o requisito |
| Diff Guard valida **caminho**, não conteúdo | Escrever código incorreto dentro do `write_allow` não é detectado |
| `--expect` é comparado por **substring** (por padrão) | Use `--expect-literal` para amarrar a asserção ao arquivo de teste congelado |
| Sandbox é isolamento de **árvore Git**, não de SO | Um subprocesso pode escapar do worktree (`tests/security-adv.test.ts` registra isso) |
| Não há verificação de **qualidade semântica** de código | Nenhum gate julga se o código está correto, legível ou bem projetado |
| `pwn validate` valida **schema**, não verdade | Um `prd.json` sintaticamente válido pode descrever um produto incoerente |

**Como detectar gates decorativos:** `pwn self-check --mutate` quebra artefatos de propósito e verifica se o gate correspondente realmente bloqueia. Um gate que aceita a mutação aparece no relatório como `NÃO DETECTADO (advisory)`.
