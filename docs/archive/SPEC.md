# Technical Specification: PWN — Contract-Governed Agent Harness

**Document Status:** Approved for Planning
**Version:** 1.2
**Author:** passoz
**Date:** 2026-08-25
**Last Updated:** 2026-08-26
**Decision review:** 28 decisões resolvidas
**Scope freeze:** requisitos e decisões desta versão estão fechados; mudanças posteriores exigem nova decisão versionada.

---

## Executive Summary

**Problema:** O usuário já possui um ecossistema maduro de engenharia assistida por IA (Pi, OpenCode, omp, `ai-engineering-skills` e extensions), mas os recursos de harness e governança estão espalhados entre runtimes, diretórios globais, links simbólicos e repositórios separados. O TDD estrito dá previsibilidade a modelos baratos, porém aplica cerimônia e custo mesmo quando um contrato executável mais leve seria suficiente. Não existe um framework unificado que limite o espaço de decisão dos executores, imponha escopo e orçamento mecanicamente, selecione validação proporcional ao risco e escale para modelos fortes ou humanos somente quando necessário.

**Solução:** PWN é um framework CLI-first (`pwn`) para governança de agentes por contratos executáveis. Modelos fortes definem intenção, riscos e limites; modelos baratos ou locais executam tarefas reduzidas; validadores determinísticos verificam o resultado; políticas declarativas decidem quando escalar. O framework compõe **Profiles**, **Skills**, **Rules**, **Contracts**, **Risk Policies**, **Pipelines**, **Sub-agents**, **Hooks**, **Evidence** e **Metrics**. Pi, OpenCode e omp são targets primários. O `ai-engineering-skills` é portado para este repositório como o pack oficial `software-engineering`, sem remover ou alterar automaticamente o repositório original.

**Impacto:** O usuário passa a ter um harness proprietário CLI-first que:
- reduz custo usando modelos fortes nos pontos de decisão e modelos baratos na execução limitada;
- preserva o workflow v3 estrito do `ai-engineering-skills` para Works que exigem TDD;
- adiciona contratos de comportamento, mudança, arquitetura, aceitação, escopo, orçamento e escalação;
- seleciona `tdd-strict`, `contract-first`, `regression-guarded` ou `visual-contract` conforme risco declarado;
- permite composição declarativa de sub-agents com modelos, tools e budgets diferentes;
- materializa nativamente para Pi, OpenCode e omp, incluindo sub-agents;
- suporta execução AFK com worktree, fila, evidência e review humano;
- mede custo, tokens, duração, tentativas, escalações e pass rate;
- governa também o que antecede a execução — Discovery, PRD, spec e plano viram artefatos rastreáveis com gates, aprovação e evidência;
- nunca depende de webapp — é arquivo, CLI e pipe.

---

## 1. Background

### Contexto — As quatro camadas do harness

A transcrição define quatro camadas progressivas:

| Camada | O que é | Quem controla | Exemplo atual |
|--------|---------|---------------|---------------|
| **1 — Cérebro** | Modelo LLM puro | Provider (Anthropic, OpenAI, etc.) | API call direto |
| **2 — Harness do Modelo** | Shell que envolve o modelo com prompt, tools, subagents | Vendor (Cloud Code, Codex, Pi) | Pi runtime, Claude Code |
| **3 — Editor/IDE** | Ambiente visual com arquivos, terminal | Runtime + IDE | VS Code + Cloud Code extension |
| **4 — Harness Proprietário** | Seu sistema: orquestrador, skills, rules, MCPs, hooks, memória | **Você** | Lion Claw, OpenClaw, Hermes |

**PWN opera na camada 4.** Ele não substitui o Pi, Cloud Code ou qualquer runtime — ele senta em cima deles e fornece a infraestrutura para o harness proprietário.

### O que o usuário já tem

```
~/.pi/agent/SYSTEM.md          → Rules globais do Pi (camada 2)
~/.pi/agent/settings.json      → Config do Pi (modelo, provider, packages)
~/.pi/agent/extensions/        → Extensions TypeScript (hooks no runtime)
~/.pi/agent/prompts/           → Adapters /make-*, /goal, /crud, etc.
~/.agents/skills/              → Skills compartilhadas (links → ai-engineering-skills)
~/dev/ai-engineering-skills/   → Repositório de skills + scripts determinísticos
~/dev/pi-global/               → Extensions e config compartilhada do Pi
```

**O que falta:** um framework que unifique profile, routing de modelo, composição de sub-agents, pipelines de processo, e métricas — tudo declarativo e versionável — sem ser um webapp.

### Conceitos-chave incorporados

1. **Teach Skills** — Skills com estado que entrevistam o usuário e aprendem.
2. **Agentes AFK** — Execução em sandbox isolado com fila de tarefas e review humano.
3. **Revise o sistema, não o código** — Corrija rules, skills, contratos e processos, não patches ad hoc.
4. **Agent Experience** — Código e contratos legíveis para humanos também reduzem ambiguidade para agentes.
5. **Processo → Entrega → Métricas → Otimização** — Ciclo contínuo de melhoria do harness.
6. **Modelo forte decide; modelo barato executa** — Capacidade cara é reservada para especificação, risco, exceções e auditoria.
7. **Quanto mais fraco o modelo, mais rígido o protocolo** — Escopo, contexto, tools, budget e tentativas diminuem com a capacidade do executor.
8. **TDD é uma estratégia, não a única trava** — A previsibilidade vem do conjunto de contratos executáveis e evidências.

---

## 2. Princípios de Design

### 2.1 CLI-first, não webapp

PWN é operado via CLI e arquivos. Nenhum servidor web, banco de dados ou interface gráfica é requerido. Toda configuração é um arquivo legível em um editor de texto. Pipes e composição Unix são cidadãos de primeira classe.

### 2.2 Runtime-agnostic

PWN não é um fork do Pi, não é um plugin do Pi, e não compete com o Pi. Ele gera artefatos (system prompts, configs, skill manifests) que são consumidos pelos três runtimes primários:
- **Pi** (via SYSTEM.md, extensions, prompts, skills) — target completo
- **OpenCode** (via AGENTS.md, opencode.jsonc, agents, skills, prompts) — target completo com sub-agents
- **omp** (via config.yml, agents/*.md, model roles) — target completo com sub-agents nativos
- Outros runtimes podem usar o target `raw` (system-prompt.txt + tools.json)

### 2.3 Declarativo sobre imperativo

Perfis, skills, regras e pipelines são descritos em formato declarativo. **Decisão:** YAML para dados estruturados (profiles, pipelines, sub-agents, configs), Markdown para conteúdo textual (rules, prompts, skills). O critério é simples: se tem dados estruturados, é `.yaml`; se é texto para o LLM ler, é `.md`. O framework interpreta e materializa — não requer que o usuário escreva scripts para cada composição.

### 2.4 Composição sobre monólito

Cada primitiva (skill, rule, hook, pipeline, sub-agent) é uma unidade independente que pode ser composta. Não há um "mega-config" — há composição de peças.

### 2.5 Versionável e diffável

Configuração, regras, prompts e aprendizados destilados cabem em um repositório Git. Estado bruto de sessões e dados potencialmente sensíveis são gitignored. Nada depende de banco ou API remota.

### 2.6 Determinismo do processo

O pipeline YAML é o orquestrador. O caminho feliz, os sub-agents, as condições, os limites de iteração e os checkpoints humanos são declarados antes da execução; nenhum LLM decide livremente a topologia do processo no MVP. Roteamento por LLM fica fora do escopo inicial e só poderá ser introduzido depois, como extensão explícita e mensurável.

### 2.7 Profile por projeto

Cada projeto usa um profile geral, resolvido automaticamente de `.pwn/profile.yaml` sobre o profile global. Especializações de backend, frontend, revisão ou correção pertencem aos sub-agents selecionados pelos steps do pipeline; o operador não precisa trocar de profile durante uma execução fullstack.

### 2.8 Contratos antes de liberdade

Todo executor recebe uma ordem de serviço congelada com comportamento, limites de mudança, invariantes arquiteturais, critérios de aceitação, itens fora de escopo, budget e gatilhos de escalação. Prompts orientam; validadores impõem. Escrita fora do contrato é bloqueio mecânico, não recomendação textual.

### 2.9 Validação proporcional ao risco

TDD estrito permanece disponível e obrigatório para risco alto ou crítico. Tarefas comuns podem usar contratos comportamentais congelados, checks focados e regressão sem exigir RED unitário em toda mudança. A estratégia de validação é declarada antes da execução e não pode ser rebaixada pelo executor.

### 2.10 Independência entre porta e origem

O `ai-engineering-skills` original permanece um repositório independente e operacional. PWN recebe uma cópia portada com proveniência registrada e evolui sua própria linhagem. Não há symlink, submodule, sincronização bidirecional automática nem expectativa de que mudanças feitas aqui sejam devolvidas à origem. Atualizações futuras da origem são operações explícitas de comparação e port, nunca merge silencioso.

### 2.11 Separação entre intenção de produto e instrução técnica

Discovery e PRD registram a intenção, as regras de negócio e as decisões de produto; a spec técnica traduz isso em comportamento entregável. Uma camada não substitui a outra, e nenhuma delas pode ser inventada pelo executor.

### 2.12 Rastreabilidade ponta a ponta

Requisitos e decisões aprovadas possuem IDs estáveis ligados a seções da spec, tasks, contratos e evidências. A cadeia permite responder objetivamente “o que justifica esta task” e “qual requisito ainda não foi planejado”.

### 2.13 Validação de transformações com contexto isolado

Cada transformação relevante (Discovery → Requirements → PRD → Spec → Plano → Contratos) passa por revisão com contexto isolado e por validação determinística quando aplicável. Revisão semântica por LLM não é prova isolada.

### 2.14 Resolução explícita de ambiguidades materiais

Caminhos não felizes e ambiguidades são questionados de forma cética. Toda resolução é registrada como decisão, risco aceito ou item adiado — nunca reescrita silenciosa de escopo.

---

## 3. Arquitetura

### 3.1 Estrutura do repositório PWN

```text
pwn/
├── packages/
│   ├── cli/                         # Executável pwn
│   ├── core/                        # Profiles, pipelines, queue e artifacts
│   ├── contracts/                   # Schemas, risk e policy engine
│   ├── evidence/                    # Checks, snapshots e candidates
│   ├── metrics/                     # Usage, custo e análise
│   ├── runtime-pi/                  # Adapter headless e materializer Pi
│   ├── runtime-opencode/            # Adapter headless e materializer OpenCode
│   └── runtime-omp/                 # Adapter headless e materializer omp
├── packs/
│   └── software-engineering/
│       ├── PORTED_FROM.md            # Origem, commit e data do port
│       ├── skills/                  # Cópia portada das skills existentes
│       ├── workflows/               # Porta v3 sob namespace pwn-* + workflows v4
│       ├── validators/              # Validadores v3 e v4
│       ├── evidence/                # Ferramentas de evidência e status
│       ├── adapters/                # Aliases compatíveis por runtime
│       ├── docs/
│       └── tests/
├── extensions/
│   ├── pi/
│   ├── opencode/
│   └── omp/
├── schemas/
│   ├── pipeline.schema.json
│   ├── task-contract-v4.schema.json
│   └── metrics.schema.json
├── tests/
└── SPEC.md
```

### 3.2 Diretório operacional

```text
~/.pwn/                         # ou $PWN_HOME
├── config.yaml                       # Config global (defaults, paths)
├── profiles/
│   ├── default.yaml                  # Profile ativo
│   ├── code-backend.yaml             # Profile para backend
│   ├── code-frontend.yaml            # Profile para frontend
│   └── content-creator.yaml          # Profile não-código
├── skills/
│   ├── registry.yaml                 # Registro de skills disponíveis
│   ├── local/                        # Skills criadas pelo usuário
│   │   ├── my-teach-skill/
│   │   │   ├── skill.yaml            # Manifesto
│   │   │   ├── prompt.md             # Prompt principal
│   │   │   ├── learnings.yaml        # Aprendizados destilados e versionados
│   │   │   └── state/               # Estado bruto gitignored (teach skills)
│   │   └── ...
│   └── linked/                       # Symlinks para skills externas
│       └── engineering-workflow -> ~/.agents/skills/engineering-workflow
├── rules/
│   ├── global.md                     # Rules que valem sempre
│   ├── security.md                   # Regras de segurança operacional
│   ├── code-quality.md               # Regras de qualidade de código
│   └── per-project/
│       └── pwn.md              # Rules específicas de um projeto
├── sub-agents/
│   ├── backend-dev.yaml              # Sub-agent para backend
│   ├── frontend-dev.yaml             # Sub-agent para frontend
│   ├── reviewer.yaml                 # Sub-agent para code review
│   └── bug-fixer.yaml                # Sub-agent barato para bugs
├── pipelines/
│   ├── contract-governed-dev.yaml    # Spec → contracts → cheap patch → verify → accept
│   ├── architecture-review.yaml      # Pipeline: análise → recomendação
│   ├── security-hardening.yaml       # Pipeline: scan → fix → verify
│   └── content-lesson.yaml           # Pipeline: research → interview → generate
├── hooks/
│   ├── pre-task.sh                   # Antes de cada task
│   ├── post-task.sh                  # Depois de cada task
│   ├── on-error.sh                   # Em caso de erro
│   └── on-complete.sh                # Ao completar pipeline
├── memory/
│   ├── graph/                        # Knowledge graph local (Obsidian-compatible .md)
│   │   ├── index.yaml
│   │   └── nodes/
│   ├── sessions/                     # Histórico de sessões relevantes
│   └── learnings.yaml                # Lições aprendidas automaticamente
├── metrics/
│   ├── runs/                         # Log de cada execução
│   │   └── 2026-08-25T14-30-00.yaml
│   └── summary.yaml                  # Métricas agregadas
├── queue/                            # Fila de tarefas AFK
│   ├── pending/
│   ├── running/
│   ├── review/                       # Aguardando review humano
│   └── done/
└── targets/                          # Materialização por runtime
    ├── pi/                           # SYSTEM.md, settings, prompts, extensions
    ├── opencode/                     # AGENTS.md, opencode.jsonc, agents, skills, prompts
    ├── omp/                          # config.yml, system prompt e agents/*.md
    └── raw/                          # system-prompt.txt, tools e sub-agents JSON
```

### 3.3 Diagrama de camadas

```
┌─────────────────────────────────────────────────────────────┐
│                     PWN CLI (`pwn`)                    │
│  profile | skill | rule | pipeline | agent | queue | metrics │
│  target  | validate                                          │
└─────────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│          CONTRACT + COMPOSITION ENGINE                    │
│                                                          │
│  Contract ─┬── risk, validation e acceptance             │
│            ├── write/scope/architecture boundaries       │
│            ├── budget e escalation policy                │
│  Profile ──┼── model routing e skill/rule selection      │
│            └── sub-agent e hook binding                  │
│                                                          │
│  Pipeline ── Step[] ── contract + agent + validation     │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│              TARGET MATERIALIZER                         │
│                                                          │
│  Lê profile + skills + rules + sub-agents                │
│  Gera artefatos nativos do runtime alvo:                 │
│    Pi:       SYSTEM.md + prompts + extensions + skills   │
│    OpenCode: AGENTS.md + opencode.jsonc + agents/skills  │
│    omp:      config.yml + system prompt + agents/*.md    │
│    Raw:      system-prompt.txt + tools/sub-agents JSON   │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│               RUNTIME (camada 2)                         │
│                                                          │
│  Pi / OpenCode / omp (primários) / Agent SDK (raw)       │
│                                                          │
│  Consome os artefatos gerados e executa                  │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Primitivas

### 4.1 Contract

Contract é a ordem de serviço executável entregue a um agent. Ele restringe decisões antes da execução e combina sete dimensões:

| Contrato | Responsabilidade |
|----------|------------------|
| **Behavioral** | Comportamentos e cenários observáveis esperados. |
| **Change** | Arquivos permitidos/proibidos, limites de diff e superfície de escrita. |
| **Architecture** | Invariantes estruturais que não podem ser violados. |
| **Acceptance** | Provas e comandos necessários para concluir a task. |
| **Scope** | Itens explicitamente fora da tarefa, mesmo dentro de arquivos permitidos. |
| **Budget** | Limites de tokens, custo, duração e tentativas. |
| **Escalation** | Eventos que interrompem o executor e promovem a decisão. |

```yaml
contract_version: 4
work_id: "0037"
task_id: "2.1"

risk:
  level: L1
  reasons:
    - localized endpoint behavior
    - no schema or authentication impact

routing:
  executor_role: cheap
  reviewer_role: cheap
  strong_review: on_escalation
  human_review: false

budget:
  max_tokens: 30000
  max_cost_usd: 0.20
  max_duration: 15m
  max_attempts: 2

behavior:
  objective: Add pagination to GET /users
  invariants:
    - default page is 1
    - default limit is 20
    - maximum limit is 100
    - response remains backward compatible

change_boundary:
  write_allow:
    - src/routes/users.ts
    - src/services/users.ts
    - tests/users-pagination.test.ts
  write_deny:
    - migrations/**
    - src/auth/**
  max_changed_files: 3
  max_added_lines: 200

architecture:
  rules:
    - do not add a new abstraction
    - preserve the existing repository boundary

out_of_scope:
  - database schema changes
  - authentication changes
  - unrelated refactors

validation:
  strategy: contract-first
  commands:
    - bun test tests/users-pagination.test.ts
    - bun run typecheck
    - bun run lint

escalation:
  triggers:
    - required file outside write_allow
    - architecture contract conflict
    - two failed implementation attempts
    - inconclusive acceptance command
    - budget exhausted
```

A allowlist de escrita é verificada pelo diff e pelas tool calls. Expansão de leitura pode ser solicitada e registrada; expansão de escrita exige revisão e revalidação do contrato.

O Contract descreve uma task específica. Acima dele, o pack `software-engineering` define um **contrato de governança do Work** (risco global, invariantes e limites máximos) que é congelado antes do plano; os contratos por task são derivados e congelados depois da atomização. Os dois níveis não duplicam campos normativos (ver seção 10.8).

### 4.2 Risk Policy

Risk Policy classifica a tarefa por impacto e determina o mínimo de executor, validação e review. O nível sempre inclui razões concretas.

| Nível | Exemplos | Executor | Estratégia mínima | Review |
|-------|----------|----------|-------------------|--------|
| **L0** | docs, rename, config localizada | grátis/local | regression-guarded | checks automáticos |
| **L1** | CRUD e glue code simples | barato | contract-first ou regression-guarded | barato |
| **L2** | fluxo comum de negócio, integração | barato | contract-first | forte |
| **L3** | auth, migration, concorrência, dinheiro | forte | tdd-strict | forte; humano conforme policy |
| **L4** | jurídico, pagamento, segurança crítica | forte | tdd-strict reforçado | forte + humano obrigatório |

A policy pode promover risco automaticamente diante de sinais declarados, mas nunca rebaixá-lo sem revisão do contrato.

### 4.3 Validation Strategy

Cada task seleciona exatamente uma estratégia antes da execução:

- **`tdd-strict`** — BASELINE → RED por assertion → GREEN com teste congelado → mutation → ACs → regressão.
- **`contract-first`** — contrato e cenários congelados → patch → checks focados → ACs → regressão.
- **`regression-guarded`** — baseline → patch limitado → lint/build/typecheck aplicáveis → regressão existente → diff audit.
- **`visual-contract`** — expectativas visuais → execução real → screenshot → inspeção visual direta → regressão.

Quando uma Work altera interface e usa `visual-contract`, a estratégia deve declarar: fonte da verdade visual e sua versão; telas/componentes e estados cobertos; viewport, tema e dados determinísticos; comportamentos ligados a estados de UI (carregamento, streaming, erro, vazio, colapso); expectativas de acessibilidade observáveis quando aplicáveis; screenshots obrigatórios e inspeção humana direta; e política para diferenças permitidas versus divergências bloqueantes (ver seção 10.13).

A ausência de harness ou gate produz limitação explícita ou `N/A` legítimo; nunca autoriza inventar ferramenta ou declarar prova inexistente.

### 4.4 Profile

Um profile é a unidade de contexto geral de um projeto. Ele declara identidade, modelo default, skills/rules/hooks disponíveis e sub-agents permitidos. O pipeline declarativo, e não um LLM orquestrador, seleciona o sub-agent de cada step.

```yaml
# profiles/code-backend.yaml
name: code-backend
description: Profile para desenvolvimento backend com Go

identity:
  role: "Senior Go backend engineer"
  personality: concise, test-driven, security-aware

model:
  default: cx/gpt-5.6-terra
  fallback: ag/claude-sonnet-4-6
  cheap: qwen3.5:27b          # Para tasks triviais

skills:
  - engineering-workflow       # Link existente em ~/.agents/skills/
  - go-test
  - sqlc
  - sql-migration
  - auth

rules:
  - global                     # rules/global.md
  - security                   # rules/security.md
  - code-quality               # rules/code-quality.md

sub-agents:
  - backend-dev                # sub-agents/backend-dev.yaml
  - reviewer                   # sub-agents/reviewer.yaml
  - bug-fixer                  # sub-agents/bug-fixer.yaml

hooks:
  - pre-task
  - post-task
  - on-error

memory:
  type: graph                  # graph | session | none
  path: memory/graph/
```

### 4.5 Skill

Skills são unidades de conhecimento ativável. PWN é compatível com o formato Agent Skills existente (SKILL.md + references/) e adiciona extensões para teach skills e skills com estado.

```yaml
# skills/local/api-design-interview/skill.yaml
name: api-design-interview
type: teach                    # teach | reference | workflow | tool
description: >
  Entrevista o usuário para definir o design de uma API.
  Faz perguntas progressivas, pesquisa padrões e gera spec.

triggers:
  - "design an API"
  - "create API spec"
  - /api-design

prompt: prompt.md              # Prompt principal da skill

state:
  persist: true                # Persistir estado entre sessões
  schema:
    interview_answers: object
    generated_spec: string
    iteration: integer

steps:
  - ask: "Qual o domínio do negócio dessa API?"
  - ask: "Quais são as entidades principais?"
  - ask: "Quem são os consumidores?"
  - research:
      sources: [openapi-best-practices, rest-guidelines]
  - generate:
      template: api-spec-template.md
      output: "{{project}}/specs/api-design.md"
```

#### Compatibilidade com skills existentes

Skills em `~/.agents/skills/` que seguem o formato SKILL.md são automaticamente importáveis:

```bash
pwn skill link engineering-workflow ~/.agents/skills/engineering-workflow
# ou auto-discovery:
pwn skill discover ~/.agents/skills/
```

### 4.6 Rule

Rules são restrições e padrões expressos em Markdown que são compostos no system prompt final. Cada rule file é concatenado, sem deduplicação ou reescrita automática, na ordem definida pelo profile. `pwn validate` estima o tamanho final e emite warning quando o system prompt ultrapassa o budget de tokens configurado; o framework nunca remove regras silenciosamente.

```markdown
<!-- rules/code-quality.md -->
# Code Quality Rules

### Naming
- Use nomes descritivos; evite abreviações obscuras.
- Funções fazem UMA coisa. Se faz mais, extraia.

### Testing
- Todo comportamento novo tem teste RED antes de GREEN.
- Nunca altere teste e implementação no mesmo commit.

### Architecture
- Boundaries explícitas entre camadas.
- Dependency injection sobre singletons globais.
- Erros são tratados, nunca ignorados silenciosamente.
```

**Diferença de skills:** Rules são passivas (sempre injetadas no prompt). Skills são ativas (invocadas quando relevantes).

### 4.7 Sub-agent

Sub-agents são agentes especializados com configuração própria (modelo, tools, prompt, skills). Cada step do pipeline declara explicitamente qual sub-agent executa a ação.

```yaml
# sub-agents/backend-dev.yaml
name: backend-dev
description: Desenvolve código backend em Go

model: cx/gpt-5.6-terra       # Modelo forte para código complexo

system_prompt: |
  Você é um desenvolvedor backend Go sênior.
  Foco em código limpo, testável e seguro.
  Nunca gere código sem testes.
  Siga as convenções do projeto (AGENTS.md).

skills:
  - go-test
  - sqlc
  - sql-migration

tools:
  - read
  - write
  - edit
  - bash

rules:
  - code-quality
  - security

limits:
  max_tokens_per_turn: 32000
  max_turns: 20
  budget_usd: 2.00             # Teto de custo para este sub-agent
```

```yaml
# sub-agents/bug-fixer.yaml
name: bug-fixer
description: Correção de bugs simples com modelo econômico

model: qwen3.5:27b             # Modelo local, zero custo

system_prompt: |
  Você corrige bugs específicos. Não refatore.
  Não mude arquitetura. Fix mínimo.

tools:
  - read
  - edit
  - bash

limits:
  max_turns: 5
```

### 4.8 Pipeline

Pipelines são processos multi-step onde cada step usa um contrato e pode selecionar um sub-agent/model role diferente. A linha de produção canônica de engenharia do pack `software-engineering` é `intake → discovery → requirements → PRD → technical decisions → spec → spec validation → skeptical enrichment → work-governance → plan → plan validation → task-contract → execution → verify → escalate → accept → learn`. O core não impõe essa topologia a domínios que não precisam dela; uma correção isolada pode iniciar em `work-governance` ou em uma task já especificada, desde que a policy registre as etapas dispensadas.

```yaml
# pipelines/contract-governed-dev.yaml
name: contract-governed-dev
description: >
  Pipeline de engenharia: discovery → PRD → spec → gates → work-governance →
  plan → task-contracts → cheap patch → verify → escalate → accept

triggers:
  - "develop feature"
  - /develop

input:
  - feature_description: string    # O que construir
  - project_path: path             # Onde construir

steps:
  - id: spec
    agent: spec-writer
    action: "Gere uma spec técnica detalhada para: {{feature_description}}"
    skill: technical-specification
    output: spec_document
    review: true                   # Pausa para review humano

  - id: spec-validate
    type: gate
    gate: GATE-PRD-SPEC
    input:
      prd: "{{prd_document}}"
      spec: "{{spec_document}}"
    output: spec_findings

  - id: enrich
    agent: spec-enricher
    role: strong
    action: "Questione ambiguidades e caminhos não felizes sem alterar escopo"
    input: "{{spec_document}}"
    output: enrichment
    review: true

  - id: work-governance
    agent: contract-planner
    role: strong
    action: "Congele risco global, invariantes e limites máximos do Work"
    input: "{{spec_document}}"
    output: work_governance
    review: true

  - id: plan
    agent: planner
    role: strong
    action: "Atomize tasks a partir da spec, sem duplicar campos normativos"
    skill: engineering-workflow
    input: "{{work_governance}}"
    output: task_plan

  - id: plan-validate
    type: gate
    gate: GATE-SPEC-PLAN
    input:
      spec: "{{spec_document}}"
      governance: "{{work_governance}}"
      plan: "{{task_plan}}"
    output: plan_findings

  - id: contract-freeze
    type: gate
    gate: GATE-PLAN-CONTRACT
    action: "Derive e congele um contrato por task planejada"
    input: "{{task_plan}}"
    output: task_contracts

  - id: execute
    foreach: "{{task_plan.tasks}}"
    agent: task-executor
    role: "{{task.routing.executor_role}}"
    action: "Execute somente o context capsule da task"
    input: "{{task.context_capsule}}"
    output: patch
    sandbox: worktree

  - id: verify
    type: deterministic
    action: "Aplique change contract e validation strategy"
    input: "{{patch}}"
    output: verification

  - id: escalate
    condition: "{{verification.requires_escalation}}"
    agent: escalation-reviewer
    role: strong
    input:
      contract: "{{task.contract}}"
      patch: "{{patch}}"
      evidence: "{{verification}}"
    output: escalation_decision

  - id: accept
    agent: acceptance-auditor
    role: "{{task.routing.reviewer_role}}"
    input:
      contract: "{{task.contract}}"
      patch: "{{patch}}"
      evidence: "{{verification}}"
    output: acceptance_candidate

on_complete:
  - hook: on-complete
  - metrics: collect

on_error:
  - hook: on-error
  - notify: "Pipeline falhou no step {{current_step}}"
```

Steps com `type: gate` executam as revisões/validadores de planejamento (seção 10.9) e bloqueiam o avanço quando há finding material não resolvido; eles não invocam um executor.

O executor oferece dois modos complementares:

- `pwn pipeline dry-run <name>` resolve profile, inputs, sub-agents, modelos, rules, tools, worktree e checkpoints sem invocar um runtime;
- `pwn pipeline run <name>` invoca programaticamente o runtime configurado para cada step em modo não interativo, captura seu output e o fornece ao step seguinte.

No target Pi, a invocação usa o CLI comprovado (`pi --print`) com `--model`, `--system-prompt`/`--append-system-prompt`, `--tools`, `--extension`, `--skill`, `--session-dir` e demais flags explícitas materializadas para o step. OpenCode usa `opencode run`; omp usa `omp --print`. Cada adapter de runtime é isolado e validado contra a versão instalada.

### 4.9 Hook

Hooks são scripts executados em eventos do ciclo de vida. Semelhante às extensions do Pi, mas declarados no PWN e independentes de runtime.

```bash
#!/bin/bash
# hooks/pre-task.sh
# Executado antes de cada task de um pipeline

# Cria checkpoint git automático
git stash create > /dev/null 2>&1 && echo "checkpoint created"

# Log
echo "[$(date -Iseconds)] PRE-TASK: step=$PWN_STEP agent=$PWN_AGENT" >> ~/.pwn/metrics/hooks.log
```

```bash
#!/bin/bash
# hooks/post-task.sh

# Coleta métricas
echo "[$(date -Iseconds)] POST-TASK: step=$PWN_STEP tokens=$PWN_TOKENS_USED cost=$PWN_COST_USD duration=$PWN_DURATION_SEC" >> ~/.pwn/metrics/hooks.log
```

Variáveis de ambiente injetadas em hooks:

| Var | Descrição |
|-----|-----------|
| `PWN_STEP` | ID do step atual |
| `PWN_AGENT` | Nome do sub-agent |
| `PWN_MODEL` | Modelo sendo usado |
| `PWN_TOKENS_USED` | Tokens consumidos no step |
| `PWN_COST_USD` | Custo estimado em USD |
| `PWN_DURATION_SEC` | Duração em segundos |
| `PWN_PROFILE` | Profile ativo |
| `PWN_PIPELINE` | Pipeline sendo executado |
| `PWN_PROJECT` | Caminho do projeto |

Uma extension dedicada do Pi, `pwn-metrics.ts`, coleta `usage` em eventos de turno e escreve um contrato JSONL estável consumido pelo PWN. Os adapters de OpenCode e omp expõem o mesmo contrato interno a partir dos mecanismos de sessão/estatísticas de cada runtime. A indisponibilidade de uma métrica produz `N/A`, nunca um valor inventado.

### 4.10 Memory

Memory é o sistema de persistência de conhecimento do harness. Suporta dois backends:

**Graph (Obsidian-compatible):** Notas Markdown linkadas que formam um knowledge graph.

```yaml
# memory/graph/index.yaml
nodes:
  - id: project-arch
    file: nodes/project-architecture.md
    tags: [architecture, decisions]
    links: [tech-stack, deployment]

  - id: tech-stack
    file: nodes/tech-stack.md
    tags: [stack, go, postgres]
    links: [project-arch]

  - id: learnings-qwen
    file: nodes/qwen-local-learnings.md
    tags: [model, optimization, qwen]
    links: []
```

**Session:** Histórico de sessões relevantes selecionadas pelo usuário ou automaticamente por relevância.

O estado bruto de teach skills fica em `state/`, é gitignored e pode conter respostas, iterações e contexto volátil. Aprendizados destilados e revisados são promovidos para `learnings.yaml`, que é versionado e portável. Dados sensíveis nunca são promovidos automaticamente.

### 4.11 Queue (AFK Execution)

O sistema de fila permite execução "away from keyboard" com review humano. O sandbox default é um Git worktree dedicado por run; quando o projeto não é um repositório Git ou worktree não está disponível, o adapter pode usar checkpoint local explícito como fallback. Docker não faz parte do sandbox default e fica como extensão futura.

Ao concluir um step com `review: true`, o executor serializa a run com outputs e `paused_at_step`, move a tarefa para `queue/review/`, notifica o operador e encerra sem bloquear stdin. `pwn queue review` permite aprovar, rejeitar ou solicitar correção e então retoma a mesma run do checkpoint. Não há autoaprovação por timeout no escopo inicial.

```
queue/
├── pending/
│   └── 001-implement-auth.yaml       # Tarefa aguardando execução
├── running/
│   └── 002-fix-pagination.yaml       # Em execução
├── review/
│   └── 003-add-caching.yaml          # Executado, aguardando review humano  
└── done/
    └── 004-update-docs.yaml          # Concluído e aprovado
```

```yaml
# queue/pending/001-implement-auth.yaml
id: "001"
description: "Implementar autenticação JWT"
profile: code-backend
pipeline: contract-governed-dev
work_id: "0037"
risk: L3
validation_strategy: tdd-strict
budget:
  max_cost_usd: 2.00
  max_duration: 45m
input:
  feature_description: "Autenticação JWT com refresh tokens"
  project_path: ~/dev/my-api
created_at: 2026-08-25T14:30:00Z
sandbox: worktree
review_required: true
```

### 4.12 Metrics

Toda execução produz um registro de métricas.

```yaml
# metrics/runs/2026-08-25T14-30-00.yaml
run_id: "2026-08-25T14-30-00"
work_id: "0037"
profile: code-backend
pipeline: contract-governed-dev
project: ~/dev/my-api
risk: L2
validation_strategy: contract-first
runtime: pi
started_at: 2026-08-25T14:30:00Z
finished_at: 2026-08-25T16:45:00Z
duration_sec: 8100
status: completed

steps:
  - id: spec
    agent: spec-writer
    model: cx/gpt-5.6-terra
    tokens_in: 2400
    tokens_out: 8500
    cost_usd: 0.18
    duration_sec: 45
    result: success

  - id: execute
    agent: task-executor
    model_role: cheap
    model: qwen3.5:27b
    tokens_in: 28000
    tokens_out: 42000
    cost_usd: 0.00
    duration_sec: 4200
    attempts: 2
    budget_exhausted: false
    write_contract_violations: 0
    result: success
    sub_tasks: 8
    sub_tasks_passed: 8

  - id: review
    agent: reviewer
    model: ag/claude-sonnet-4-6
    tokens_in: 45000
    tokens_out: 5000
    cost_usd: 0.85
    duration_sec: 120
    result: success
    issues_found: 2
    issues_resolved: 2

totals:
  tokens_in: 75400
  tokens_out: 55500
  cost_usd: 1.03
  attempts: 4
  escalations: 1
  escalation_reasons:
    - inconclusive_validation
  human_reviews: 1
```

```yaml
# metrics/summary.yaml
last_updated: 2026-08-25T17:00:00Z

by_profile:
  code-backend:
    runs: 47
    total_cost_usd: 156.30
    avg_cost_per_run_usd: 3.33
    avg_duration_min: 95
    avg_loops: 11
    pass_rate: 0.89

  content-creator:
    runs: 23
    total_cost_usd: 12.50
    avg_cost_per_run_usd: 0.54
    avg_duration_min: 15
    avg_loops: 3
    pass_rate: 0.96

by_model:
  cx/gpt-5.6-terra:
    calls: 234
    total_cost_usd: 98.00
    avg_quality: 0.91

  qwen3.5:27b:
    calls: 156
    total_cost_usd: 0.00
    avg_quality: 0.73

optimization_hints:
  - "bug-fixer com qwen3.5:27b tem pass_rate 0.95 em tasks simples. Considere expandir para tasks de dificuldade média."
  - "reviewer com claude-sonnet-4-6 é 40% mais barato que gpt-5.6 com mesma qualidade de review."
```

---

## 5. CLI — `pwn`

### 5.1 Comandos principais

```
pwn                                   # Status geral
pwn init                              # Inicializa ~/.pwn/ com estrutura base
pwn init --project                    # Inicializa .pwn/ no projeto (overrides locais)

# Profiles
pwn profile list                      # Lista profiles disponíveis
pwn profile show <name>               # Mostra detalhes de um profile
pwn profile use <name>                # Ativa um profile como default
pwn profile create <name>             # Cria profile interativamente
pwn profile edit <name>               # Abre no $EDITOR

# Skills
pwn skill list                        # Lista skills (locais + linked)
pwn skill discover <path>             # Auto-descobre skills em um diretório
pwn skill link <name> <path>          # Liga skill externa
pwn skill create <name>               # Cria skill local (scaffolding)
pwn skill create <name> --type teach  # Cria teach skill com estado
pwn skill show <name>                 # Mostra detalhes
pwn skill state <name>                # Mostra estado de teach skill
pwn skill reset <name>                # Reset estado de teach skill (com confirmação)

# Rules
pwn rule list                         # Lista rules
pwn rule create <name>                # Cria rule file
pwn rule edit <name>                  # Abre no $EDITOR
pwn rule show <name>                  # Mostra conteúdo

# Sub-agents
pwn agent list                        # Lista sub-agents configurados
pwn agent show <name>                 # Mostra configuração
pwn agent create <name>               # Cria sub-agent interativamente
pwn agent edit <name>                 # Abre no $EDITOR
pwn agent test <name> <prompt>        # Testa sub-agent com prompt isolado

# Pipelines
pwn pipeline list                     # Lista pipelines
pwn pipeline show <name>              # Mostra steps do pipeline
pwn pipeline create <name>            # Cria pipeline interativamente
pwn pipeline edit <name>              # Abre no $EDITOR
pwn pipeline gui [name]               # Abre visualizador/editor gráfico (file://)
pwn pipeline dry-run <name> [input]   # Simula execução sem chamar LLM
pwn pipeline run <name> [input]       # Executa pipeline

# Queue (AFK)
pwn queue add <pipeline> [input]      # Adiciona tarefa à fila
pwn queue list                        # Lista tarefas (pending, running, review, done)
pwn queue status                      # Status detalhado
pwn queue review                      # Processa tarefas em /review/
pwn queue run                         # Processa próxima tarefa pending
pwn queue run --all                   # Processa todas as pendentes sequencialmente
pwn queue cancel <id>                 # Cancela tarefa

# Metrics
pwn metrics                           # Mostra resumo
pwn metrics run <run_id>              # Detalhe de uma execução
pwn metrics compare <profile1> <profile2>  # Compara profiles/modelos
pwn metrics optimize                  # Sugere otimizações baseado no histórico

# Work governance (pack software-engineering)
pwn work intake <source>              # Registra o pedido bruto e sua fonte
pwn work discover <work>              # Converte o pedido em entendimento verificável
pwn work requirements <work>          # Torna uso e regras observáveis
pwn work prd <work>                   # Consolida a decisão de produto
pwn work decision <work>              # Registra decisão técnica com alternativas
pwn work specify <source>             # Cria/reconcilia spec e contrato da mudança
pwn work contract <work>              # Congela a governança e o risco do Work
pwn work plan <work>                  # Atomiza tasks
pwn work validate requirements <work> # Gate Discovery → Requirements
pwn work validate spec <work>         # Gate PRD → Spec
pwn work enrich <work>                # Enriquecimento cético da spec
pwn work validate plan <work>         # Gate Spec → Plan
pwn work approve <work> <artifact>    # Registra aprovação explícita
pwn work findings <work> [--stage]    # Lista findings dos gates
pwn work trace <work> <id>            # Rastreia requisito/decisão/task
pwn work coverage <work>              # Matriz de rastreabilidade/cobertura
pwn work progress <work>              # Estado e evidência de execução
pwn work dry-run <work>               # Mostra routing, capsules, checks e orçamento
pwn work run <work>                   # Executa tasks e políticas de escalação
pwn work audit <work>                 # Auditoria independente
pwn work status [work]                # Estado, evidência, custo e bloqueios
pwn task capsule <work/task>          # Exibe contexto mínimo do executor
pwn task run <work/task>              # Executa uma task específica

# Packs
pwn pack list                         # Lista packs internos
pwn pack provenance <name>            # Mostra origem e linhagem do port
pwn pack diff <name> --source <path>  # Compara pack com uma origem explícita

# Target materializer
pwn target pi                         # Gera artefatos para Pi
pwn target opencode                   # Gera artefatos para OpenCode
pwn target omp                        # Gera artefatos para omp
pwn target raw                        # Gera system-prompt.txt + tools.json genérico
pwn target diff <runtime>             # Mostra diff entre config atual e materializado

# Validation
pwn validate                          # Valida toda a configuração
pwn validate profile <name>           # Valida um profile específico
pwn validate pipeline <name>          # Valida um pipeline
```

### 5.2 Project-level overrides

Um projeto pode ter um diretório `.pwn/` local que sobrepõe configs globais:

```
my-project/
├── .pwn/
│   ├── profile.yaml           # Override de profile para este projeto
│   ├── rules/
│   │   └── project.md         # Rules específicas do projeto
│   └── skills/
│       └── domain-specific/   # Skill específica do domínio
└── ...
```

Resolução de precedência:
1. `.pwn/` do projeto (mais alta)
2. `~/.pwn/` global
3. packs internos explicitamente habilitados
4. skills externas linkadas

Conflito de nome entre origens bloqueia a materialização até que o profile qualifique a skill ou rule pelo pack/origem.

---

## 6. Target Materializer — Detalhe

O materializer é a ponte entre o PWN (camada 4) e os runtimes (camada 2). Ele lê o profile ativo com todos os seus componentes e gera artefatos nativos.

### 6.1 Target: Pi

```bash
pwn target pi
```

Produz:

| Artefato gerado | Fonte no PWN |
|------------------|--------------------|
| `targets/pi/SYSTEM.md` | Composição de: identity + rules (na ordem do profile) |
| `targets/pi/prompts/*.md` | Skills com triggers que mapeiam para /adapters |
| `targets/pi/extensions/*.ts` | Hooks convertidos para extensions do Pi |
| `targets/pi/settings.json` | model.default → defaultModel, model provider → defaultProvider |

O usuário pode então:
```bash
# Copiar manualmente
cp -r ~/.pwn/targets/pi/* ~/.pi/agent/

# Ou via link
pwn target pi --link    # Cria symlinks
pwn target pi --apply   # Copia e faz backup do anterior
```

No Pi, sub-agents permanecem sob controle do pipeline: cada step inicia uma execução headless isolada do Pi com prompt, modelo, tools, skills e limits materializados para aquele sub-agent.

### 6.2 Target: OpenCode

```bash
pwn target opencode
```

Produz:

| Artefato gerado | Fonte no PWN |
|------------------|--------------------|
| `targets/opencode/AGENTS.md` | Identity + rules concatenadas |
| `targets/opencode/opencode.jsonc` | Modelo, permissions, plugins, agents e skill paths |
| `targets/opencode/skills/<agent>/SKILL.md` | Prompt rico e skills de cada sub-agent |
| `targets/opencode/prompts/*.md` | Adapters materializáveis |

Sub-agents são registrados em `agent: {}` com `mode: "subagent"`, descrição e permissions. Como o contrato nativo observado é mais limitado que o do PWN, o prompt rico de cada agent é materializado como skill associada, sem omitir silenciosamente campos não representáveis.

### 6.3 Target: omp

```bash
pwn target omp
```

Produz:

| Artefato gerado | Fonte no PWN |
|------------------|--------------------|
| `targets/omp/config.yml` | Modelo default e model roles (`smol`, `slow`, `plan`, `task`) |
| `targets/omp/system-prompt.md` | Identity + rules concatenadas |
| `targets/omp/agents/*.md` | Sub-agents com frontmatter, tools, model role, spawns, output schema e prompt |

A materialização de sub-agents para omp é a tradução nativa mais completa. O executor usa `--config`, `--system-prompt`/`--append-system-prompt` e os agents materializados.

### 6.4 Target: Raw

```bash
pwn target raw
```

Produz:

| Artefato gerado | Descrição |
|-----------------|-----------|
| `targets/raw/system-prompt.txt` | System prompt completo, pronto para API call |
| `targets/raw/tools.json` | Definição de tools em formato OpenAI-compatible |
| `targets/raw/sub-agents.json` | Mapa de sub-agents com seus prompts e modelos |

Útil para quem constrói seu runtime com Agent SDK.

### 6.5 Capability matrix e materialização sem perda silenciosa

Cada adapter materializa apenas capacidades realmente suportadas pelo runtime/versão observada. Uma capability matrix por runtime registra o status de cada capacidade e como ela foi verificada:

```yaml
runtime: pi
observed_version: "<versão observada>"
capabilities:
  print_mode:
    status: verified | unsupported | unknown
  system_prompt_override:
    status: verified | unsupported | unknown
  skills:
    status: verified | unsupported | unknown
  extension_loading:
    status: verified | unsupported | unknown
  isolated_session_directory:
    status: verified | unsupported | unknown
  structured_usage_metrics:
    status: verified | unsupported | unknown
  subagent_execution:
    status: verified | unsupported | unknown
    mode: emulated | native | null
verification:
  command_or_fixture: "caminho para teste de contrato"
  executed_at: "timestamp"
```

Regras:

1. A materialização falha ou degrada de forma explícita quando um campo do profile/contrato não for representável pelo target.
2. Nenhum campo de segurança, escopo, budget ou aceitação é descartado silenciosamente na tradução.
3. O `dry-run` mostra quais capacidades foram verificadas, emuladas, não suportadas ou desconhecidas.
4. Testes de contrato do adapter confirmam a invocação contra a versão instalada ou uma fixture estável antes de afirmar suporte completo.
5. Compatibilidade é versionada; “funciona em Pi/OpenCode/omp” é amplo demais sem faixa/versionamento observado.

---

## 7. Teach Skills — Detalhe

Teach skills são o diferencial mencionado na transcrição: skills que entrevistam o usuário, acumulam contexto e melhoram outputs progressivamente.

### 7.1 Lifecycle

```
1. TRIGGER → Usuário invoca a skill
2. INTERVIEW → Skill faz perguntas sequenciais
3. RESEARCH → Skill pesquisa fontes configuradas (opcional)
4. GENERATE → Skill produz output baseado nas respostas
5. REVIEW → Usuário avalia output
6. LEARN → Skill persiste feedback no state
7. ITERATE → Próxima invocação usa state acumulado
```

### 7.2 State persistence

```yaml
# skills/local/api-design-interview/state/session-001.yaml
session_id: "001"
started_at: 2026-08-25T10:00:00Z
iteration: 3

answers:
  domain: "e-commerce"
  entities: ["Product", "Order", "Customer", "Payment"]
  consumers: ["mobile app", "admin dashboard"]
  auth: "JWT com refresh tokens"
  pagination: "cursor-based"

feedback:
  - iteration: 1
    comment: "Spec muito genérica, precisa de exemplos concretos"
    resolved: true
  - iteration: 2
    comment: "Faltou tratar erros de validação nos endpoints"
    resolved: true

learnings:
  - "Usuário prefere exemplos curl nos endpoints"
  - "Sempre incluir rate limiting desde a primeira versão"
  - "Usar snake_case nos campos JSON, não camelCase"
```

---

## 8. Modelo de Otimização — Ciclo de Métricas

A "fase 4" da transcrição: medir, analisar, otimizar, repetir.

### 8.1 O que é medido

| Métrica | Granularidade | Uso |
|---------|---------------|-----|
| `tokens_in` / `tokens_out` | Por step, task, run e role | Custo |
| `cost_usd` | Por task aceita, Work, modelo e runtime | ROI |
| `duration_sec` | Por step, task e run | Eficiência |
| `attempts` | Por task/modelo | Adequação do executor e do contrato |
| `pass_rate` | Por risk, strategy, agent, modelo e runtime | Qualidade e routing |
| `escalations` / motivo | Por task e policy | Custo evitado ou classificação insuficiente |
| `budget_exhausted` | Por task | Calibração de budget |
| `write_contract_violations` | Por task/modelo | Disciplina do executor |
| `human_reviews` | Por risk e run | Nível real de autonomia |
| `errors` | Por stage e categoria | Debugging e melhoria do processo |

Além das métricas de economia, o harness mede a qualidade do processo de planejamento e a rastreabilidade dos artefatos:

| Métrica | Granularidade | Pergunta respondida |
|---------|---------------|---------------------|
| `requirements_coverage_rate` | Work/versão | Quantos requisitos aprovados chegaram a uma task e evidência? |
| `untraced_change_count` | Work/task | Quantas mudanças não possuem requisito/decisão de origem? |
| `gate_findings_by_stage` | etapa/agent | Em que transformação surgem mais lacunas ou conflitos? |
| `spec_rework_rounds` | spec/Work | Quantas revisões foram necessárias até a aprovação? |
| `question_resolution_time` | finding material | Onde a decisão humana bloqueia o fluxo e por quê? |
| `post_acceptance_defects` | Work/release | Que defeitos escaparam da aceitação e a qual requisito/spec/task se ligam? |
| `acceptance_scenario_pass_rate` | risco/estratégia | A estratégia escolhida evidencia cenários suficientes? |
| `visual_regression_findings` | superfície/UI | Quais estados visuais mais divergem do handoff? |
| `plan_churn_after_execution` | plano/Work | O planejamento foi instável ou o executor expandiu o escopo? |
| `human_override_rate` | policy/agent | Onde a automação recomenda decisões que o operador rejeita? |

### 8.2 Otimização automática

`pwn metrics optimize` analisa o histórico e produz recomendações:

```
Análise baseada em 47 runs do profile 'code-backend':

1. MODELO: bug-fixer usa cx/gpt-5.6-terra ($1.20/run avg) mas tasks de bug-fix
   têm pass_rate de 0.98. O modelo qwen3.5:27b tem pass_rate 0.95 para tasks
   similares com custo $0.00. Economia estimada: $56.40/mês.
   → pwn agent edit bug-fixer  # Trocar modelo para qwen3.5:27b

2. CONTRACT: Tasks L1 com `contract-first` escalaram por contexto insuficiente em
   28% das runs. Adicione a interface `PaginatedResponse` ao context capsule sem
   ampliar a write allowlist.
   → pwn task capsule 0037/2.1

3. ROUTING: O reviewer forte não encontrou defeitos adicionais em 40 tasks L0/L1
   que já passaram pelos checks e reviewer barato. Considere manter strong review
   apenas em escalação para essas classes. A mudança exige revisão da policy.
   → pwn policy edit software-engineering
```

---

## 9. Visualizador e Editor Gráfico de Pipelines (`pwn-gui`)

O PWN inclui um utilitário visual independente (fora do runtime de execução) para inspecionar, desenhar e editar pipelines, sub-agents e contratos sem exigir edição manual de YAML.

### 9.1 Fronteira e distribuição

O editor é um utilitário opcional e separado do core, dos adapters de runtime e do executor de pipelines. Ele não executa agents, commands, hooks ou pipelines e nunca recebe secrets.

- O código-fonte pode ser organizado em HTML, CSS e JavaScript Vanilla separados durante desenvolvimento.
- O artefato distribuído é um único `tools/pipeline-editor/index.html` auto-contido, sem servidor, backend, instalação, build no ambiente do usuário ou acesso de rede.
- Parser YAML, schema da versão suportada, ícones e assets necessários são incorporados ao HTML distribuído. Nenhum recurso é carregado por CDN ou `fetch()` local.
- O artefato abre diretamente por `file://` em navegadores desktop modernos.
- `pwn pipeline gui` apenas abre o artefato estático. Com `[name]`, o CLI gera uma cópia temporária auto-contida com o YAML inicial embutido e a abre via `file://`; isso não concede permissão para sobrescrever o arquivo de origem.

### 9.2 Experiência visual e interação

A interface usa nós HTML posicionados sobre um canvas transformável e SVG para conexões Bézier. A inspiração é a ergonomia de editores como n8n, não sua identidade visual ou implementação.

- canvas com pan, zoom limitado e centralização automática;
- minimapa, grid, seleção múltipla e enquadramento do grafo;
- criação, duplicação, remoção e drag-and-drop de nós;
- conexão explícita entre portas `in`, `out`, `true`, `false`, `escalate` e `on_error`;
- containers visuais para `foreach` e sub-pipelines;
- undo/redo durante a sessão;
- busca por node ID, agent, role, skill ou variável;
- painel lateral contextual para Agent, Model Role, Tools, Skills, Write Allowlist, Validation Strategy, Budget, Conditions e Escalation Triggers;
- resumo persistente de risco, custo máximo e validações do pipeline;
- layout responsivo para desktop; edição por telefone não é requisito da versão 1.

### 9.3 Arquivos, YAML e compatibilidade `file://`

- **Abrir:** seletor de arquivo e drag-and-drop funcionam em `file://`.
- **Salvar diretamente:** usa File System Access API somente quando o navegador oferecer a capacidade e após consentimento explícito do usuário.
- **Fallback universal:** gera download de um novo `.yaml`; nunca afirma que sobrescreveu a origem quando não o fez.
- **Ctrl+S:** salva no handle autorizado ou abre o fluxo de download/escolha de arquivo.
- **Validação:** usa uma cópia embutida e versionada de `pipeline.schema.json`; erros aparecem no node e em painel global antes da exportação.
- **Schema incompatível:** abre em modo read-only ou exige migração explícita; nunca descarta campos silenciosamente.
- **Round-trip:** preserva chaves desconhecidas semanticamente, mas comentários, âncoras YAML, aliases e formatação original não têm preservação garantida. Antes de salvar uma importação, o editor mostra o diff YAML e informa quando fará serialização canônica.
- **Fonte da verdade:** o YAML exportado e validado é o contrato; posições visuais ficam sob uma chave reservada `x-pwn-layout`, ignorada pelo executor.

### 9.4 Cores e Semântica Visual dos Nós

| Tipo de Nó | Cor / Identidade Visual | Ícone / Indicação |
|---|---|---|
| **Trigger / Início** | Verde Esmeralda (`#10b981`) | Ponto de entrada (Work ID, Webhook, CLI) |
| **Strong Agent** (Spec/Plan/Audit) | Roxo / Índigo Neon (`#6366f1`) | Alto raciocínio, decisões de contrato |
| **Cheap Agent** (Execução de Tasks) | Âmbar / Laranja Suave (`#f59e0b`) | Restrito por Write Allowlist e Budget |
| **Deterministic Check** (Sem LLM) | Ciano / Azul Claro (`#06b6d4`) | Testes, Lint, Typecheck, Diff Guard ($0.00) |
| **Human Review** (Pausa AFK) | Rosa / Magenta (`#ec4899`) | Checkpoint assíncrono para aprovação |
| **Escalation Branch** | Vermelho / Carmim (`#ef4444`) | Desvio quando limits/contratos são violados |

---

## 10. Pack oficial `software-engineering`

O conteúdo do repositório `ai-engineering-skills` será portado para `packs/software-engineering/`. Trata-se de uma cópia independente com linhagem explícita, não de symlink, submodule ou substituição da origem.

### 10.1 Preservação da origem

O port obedece às seguintes regras:

1. o repositório original não é removido, alterado ou redirecionado pelo PWN;
2. a primeira importação preserva comportamento, contratos, testes e documentação antes de evoluir funcionalidades;
3. `PORTED_FROM.md` registra URL/path de origem, commit exato, data, inventário e diferenças intencionais;
4. os arquivos portados passam a ter evolução própria neste repositório;
5. uma atualização futura da origem exige `pwn pack diff software-engineering --source <path>` e uma operação explícita de port;
6. conflitos são resolvidos deliberadamente; não existe sincronização bidirecional automática.

### 10.2 Conteúdo inicial portado

| Origem atual | Destino no pack |
|--------------|-----------------|
| `skills/*` | `packs/software-engineering/skills/*` |
| `skills/engineering-workflow/references/*` | `packs/software-engineering/workflows/v3/*` |
| `scripts/validate_*.js` | `packs/software-engineering/validators/v3/*` |
| `scripts/task_evidence.js` | `packs/software-engineering/evidence/v3/*` |
| `scripts/work_artifacts.js` | `packs/software-engineering/artifacts/v3/*` |
| `scripts/project_status.js` | `packs/software-engineering/status/v3/*` |
| `scripts/unattended_exec.js` | `packs/software-engineering/execution/v3/*` |
| `adapters/pi/prompts/*` | `packs/software-engineering/adapters/pi/*` |
| testes e documentação | diretórios correspondentes no pack |

Os entrypoints podem receber wrappers TypeScript/Bun, mas a primeira fase precisa manter os resultados observáveis dos scripts Node existentes.

### 10.3 Compatibilidade v3

O contrato v3 permanece legível e executável sem relaxamento:

```text
BASELINE → RED → GREEN → mutation → ACs → gates → regressão → audit
```

Works v3 continuam usando seus manifests e artefatos atuais. Nenhuma migração automática altera um Work existente para v4. O CLI `pwn` apenas fornece novos entrypoints sobre o mesmo comportamento.

### 10.4 Evolução v4

O contrato v4 adiciona, sem reescrever v3:

- classificação de risco com razões;
- estratégia de validação por task;
- behavioral, change, architecture, acceptance e scope contracts;
- budget de tokens, custo, duração e tentativas;
- routing por papéis de modelo;
- context capsule mínimo;
- gatilhos de escalação;
- enforcement mecânico da superfície de escrita;
- evidência normalizada entre Pi, OpenCode e omp.

### 10.5 Context capsule

O executor recebe apenas o contexto necessário para a task:

```text
TASK CONTRACT
BEHAVIORAL SCENARIOS
WRITE ALLOWLIST
OUT OF SCOPE
RELEVANT FILES AND INTERFACES
VALIDATION COMMANDS
BUDGET
ESCALATION RULES
```

Leitura adicional pode ser solicitada com justificativa registrada. Escrita adicional exige alteração do contrato, revalidação e, conforme risco, escalação.

### 10.6 Namespace independente dos adapters `pwn-*`

O repositório original conserva exclusivamente seus adapters `/make-*`. A porta no PWN instala adapters próprios sob `/pwn-*`, permitindo que os dois sistemas coexistam sem sobrescrita, redirecionamento ou ambiguidade:

```text
/pwn-spec   → pwn work specify
/pwn-prompt → pwn work contract
/pwn-todo   → pwn work plan
/pwn-task   → pwn task run
/pwn-all    → pwn work run
/pwn-ac     → pwn work audit
/pwn-status → pwn work status
/pwn-doc    → pwn work docs
```

Os nomes `/make-*` nunca são criados, removidos ou alterados pelo instalador do PWN. A skill ou workflow interno continua sendo fonte do processo; adapters apenas repassam argumentos. Pi, OpenCode e omp recebem adapters `pwn-*` próprios conforme o mecanismo suportado.

### 10.7 Skills externas continuam importáveis

O pack oficial não impede composição com skills externas:

```bash
pwn skill discover ~/.agents/skills/
pwn skill link <name> <path>
```

Skills com mesmo nome da cópia portada exigem seleção explícita de origem; o PWN não escolhe silenciosamente entre pack interno e instalação externa.

### 10.8 Artefatos de planejamento e rastreabilidade

Para Works que nascem de uma ideia ou requisito ainda não estabilizado, o pack `software-engineering` governa a cadeia anterior à execução. Artefatos versionados vivem sob `.pwn/work/<work-id>/`:

```text
.pwn/work/<work-id>/
├── intake.md
├── discovery.md
├── requirements.md
├── prd.md
├── technical-decisions.md
├── spec.md
├── spec-validation.md
├── enrichment.md
├── work-governance.yaml
├── plan.yaml
├── plan-validation.md
├── contracts/
│   └── <task-id>.yaml
├── contract-validation.md
├── progress.yaml
└── evidence/
```

Contratos em dois níveis, sem duplicação normativa:

| Artefato | Finalidade | Deve conter | Não deve conter |
|---|---|---|---|
| `intake` | Registrar o pedido bruto e sua fonte | objetivo, solicitante, fontes, incertezas, classificação preliminar | decisões inventadas |
| `discovery` | Converter o pedido em entendimento verificável | problema, atores, objetivos, contexto, restrições, referências, perguntas/respostas aprovadas | desenho técnico sem decisão |
| `requirements` | Tornar uso e regras observáveis | user stories, regras, requisitos funcionais/não funcionais, exceções conhecidas | passos de código |
| `prd` | Consolidar a decisão de produto | problema, atores, resultado, escopo, não-objetivos, métricas e IDs dos requisitos aceitos | plano por arquivo |
| `technical-decisions` | Fechar escolhas difíceis de reverter | decisão, contexto, alternativas, recomendação, consequências, aprovador, evidência | implementação completa |
| `technical-spec` | Traduzir produto aprovado em contrato técnico | comportamento, fronteiras, dados, erros, segurança, UX handoff, testes, impactos | discussão bruta e premissas não aprovadas |
| `enrichment` | Resolver ambiguidades sem alterar escopo | questões materiais, opções, decisão, mudanças rastreáveis | features novas por conta própria |
| `work-governance` | Governar a decomposição e limitar o Work | risco global, invariantes, fronteiras máximas, policies e defaults | `task_id`, comandos ou allowlists inventados |
| `plan` | Decompor a spec em unidades executáveis | identidades, dependências, propósito, referências de origem, sequência | duplicata normativa do contrato por task |
| `task-contract` | Congelar a ordem de serviço de cada task | os sete contratos v4, `task_id`, `source_refs`, routing, checks e limites | requisito/decisão inédita |
| `progress` | Registrar execução e estado real | status, evidências, falhas, exceções, links ao contrato | “concluído” sem prova |

Cada artefato carrega `work_id`, versão, status e links de rastreabilidade. Aprovação registra quem/quando/o quê foi aprovado; correções geram histórico auditável; dados sensíveis não são promovidos automaticamente.

**Matriz de rastreabilidade canônica** (uma por Work, referenciada por PRD, spec e plano):

| Origem | Requisito | Decisão técnica | Seção da spec | Task | Contrato | Evidência | Estado |
|---|---|---|---|---|---|---|---|
| `DISC-007` | `REQ-014` | `TD-003` | `SPEC-API-004` | `TASK-2.3` | `CTR-2.3` | `EVD-2.3-01` | planejado |

### 10.9 Gates de revisão e validação

Cada transformação relevante passa por um gate que combina revisão semântica (contexto isolado) e validação determinística aplicável. Revisão por LLM não é prova isolada; o gate só resulta em `pass` após os checks determinísticos aplicáveis e as aprovações exigidas pela policy.

| ID | Comparação | Verifica | Ação em falha |
|---|---|---|---|
| `GATE-DISC-REQ` | Discovery → Requirements | cobertura de objetivos, atores, restrições e referências; ausência de requisito não autorizado | retorna para requirements ou solicita decisão |
| `GATE-REQ-PRD` | Requirements → PRD | PRD preserva escopo e critérios sem criar promessa nova | retorno ao PRD/requirements |
| `GATE-PRD-SPEC` | PRD + decisões → Spec | cada requisito tem comportamento técnico, caso negativo e critério verificável | bloqueia aprovação da spec em lacuna material |
| `GATE-SPEC-PLAN` | Spec + Work Governance → Plan | toda seção entregável tem task; dependências, ordem e decomposição respeitam a governança | bloqueia congelamento dos contratos |
| `GATE-PLAN-CONTRACT` | Task + Work Governance → Task Contract | limites de escrita, validação, budget e risco realizam a task sem exceder o Work | corrige contrato, replaneja ou escala |
| `GATE-DELIVERY` | Task Contract + plan → patch/evidence | entrega e provas atendem ao contrato sem escopo adicional | retorna ao executor ou escala |

Formato de saída estruturado:

```yaml
gate: GATE-PRD-SPEC
work_id: "0037"
input_versions:
  prd: 2
  technical_decisions: 1
  spec: 3
result: blocked # pass | pass_with_notes | blocked
summary:
  covered: 18
  gaps: 2
  conflicts: 1
  ambiguities: 3
findings:
  - id: FIND-001
    severity: high # low | medium | high | critical
    type: coverage_gap # coverage_gap | conflict | ambiguity | unverifiable_acceptance
    source_refs: ["REQ-014", "PRD §4.2"]
    target_refs: []
    description: "A regra de autorização não possui comportamento de erro definido."
    required_resolution: "Definir resposta observável e critério de aceite ou remover a promessa aprovada."
    resolution_owner: product-owner
    status: open
```

A severidade considera risco: ambiguidade cosmética não equivale a ambiguidade sobre dados, autorização, dinheiro ou destruição de informação. `pass_with_notes` só é aceito se as notas não forem materiais.

### 10.10 Enriquecimento cético

Após a spec ser validada, o papel `spec-enricher` (ou `adversarial-reviewer`) questiona caminhos não felizes que as fontes ainda não decidiram: concorrência, falhas, cancelamentos, reprocessamentos, limites e permissões. Restrições:

- recebe spec validada, PRD, decisões e matriz de rastreabilidade;
- classifica cada observação (`ambiguity`, `missing_failure_mode`, `state_transition`, `security/privacy`, `operability`, `UX/accessibility`, `data_lifecycle`, `testability`);
- formula perguntas curtas e materialmente relevantes;
- **não altera automaticamente** requisito, escopo, risco ou decisão técnica;
- só aplica mudança após decisão explícita do operador/owner ou regra autorizada;
- cria nova versão da spec e atualiza a matriz quando incorpora decisão;
- usa limite de questões/rounds, budget e escalonamento como os demais agentes.

A etapa termina em `resolved`, `accepted_risk`, `deferred` ou `blocked`.

### 10.11 Decisões técnicas por especialidade

Revisão especializada é acionada por policy de gatilhos, não por burocracia universal:

| Gatilho no Work | Revisão requerida |
|---|---|
| schema, migração, retenção, consistência ou recuperação de dados | dados/persistência |
| nova fronteira HTTP/evento/arquivo público ou compatibilidade | API/integração |
| identidade, permissão, segredo, dados pessoais ou exposição de rede | segurança/privacidade |
| alteração de fluxo crítico de UI ou contrato visual | UX/acessibilidade + visual |
| novo runtime/adaptador/materialização | compatibilidade de runtime |
| alteração interna localizada L0/L1 sem gatilho | nenhuma, salvo escalonamento |

Cada decisão (`TD-001`, estável no Work) registra contexto, opções consideradas, decisão, consequências, dono/aprovação, evidência e impacto de implementação. Reviews de segurança partem da fronteira e do modelo de ameaça declarado, não de checklist universal; omitir um controle de alto risco exige `accepted_risk` documentado.

### 10.12 Contrato do plano/sprints

O plano materializa apenas a decomposição e referencia o contrato normativo de cada task, sem duplicá-lo:

```yaml
id: "TASK-2.3"
title: "..."
purpose: "Resultado observável entregue por esta unidade."
source_refs: ["REQ-014", "SPEC-API-004", "TD-003"]
depends_on: ["TASK-2.1"]
contract_id: "CTR-2.3"
```

Comportamento, cenários de aceite, casos negativos, agent/routing, risco, validation strategy, budget, allowlist, checks, evidência exigida e `out_of_scope` ficam no contrato por task depois de congelados. `contract_id` é reservado antes da derivação; não indica contrato já aprovado. Sugestões contratuais do planner são marcadas como draft e removidas do plano canônico após `GATE-PLAN-CONTRACT`.

**Definition of Done por task** (versionada; não relaxável silenciosamente após início):

1. implementação limitada ao Change/Scope Contract aceito;
2. cenários de aceite e casos negativos demonstrados ou com N/A justificado;
3. comandos/checks declarados executados com saída registrada;
4. mudança de contrato, expansão de escrita, tentativa excedida ou budget estourado escalados, não escondidos;
5. auditoria de diff confirma ausência de trabalho fora de escopo;
6. rastreabilidade de `source_refs` até a evidência completa;
7. status em `progress` atualizado somente após os itens anteriores.

### 10.13 UX Handoff Manifest

Works que alteram interface referenciam o handoff autorizado sem embuti-lo nem redesenhá-lo:

```yaml
ux_handoff:
  id: UX-001
  source:
    type: exported_bundle # exported_bundle | figma | screenshot_set | existing_ui
    reference: "URI ou caminho resolvível"
    revision: "hash do conteúdo ou revisão do VCS"
  authority: approved_reference # approved_reference | directional_reference
  scope:
    surfaces: [conversation, activity-panel]
    states: [empty, loading, streaming, error, collapsed]
  invariants:
    - "Não redesenhar tokens, paleta ou hierarquia visual aprovados."
    - "O painel pode colapsar sem ocultar o caminho de reabertura."
  behavioral_bindings:
    - visual_state: streaming
      trigger: EVT-STREAM-START
      completion: EVT-STREAM-COMPLETE
  verification:
    required_screenshots: [empty, streaming, error, collapsed]
    viewport_profiles: [desktop-default]
  exceptions:
    - "Conflitos entre fidelidade visual e acessibilidade exigem decisão explícita."
```

A autoridade (`approved_reference` vs `directional_reference`) é declarada por Work; default é `approved_reference` quando um handoff autorizado é fornecido. Conflito entre fidelidade visual e acessibilidade normativa nunca é resolvido rebaixando a acessibilidade silenciosamente.

---

## 11. Implementação — Stack e Fases

### 11.1 Stack decidida

PWN será implementado em **TypeScript sobre Bun**. A escolha mantém compatibilidade com as extensions TypeScript do Pi, os scripts JavaScript das skills existentes e o ecossistema de plugins dos runtimes. O CLI roda diretamente com Bun durante desenvolvimento e pode ser distribuído como executável standalone por `bun build --compile` quando a entrega exigir.

A implementação deve:
- expor o executável `pwn`;
- ler e escrever YAML, Markdown, JSON/JSONC e JSONL;
- executar processos filhos dos runtimes e hooks sem daemon;
- isolar adapters de Pi, OpenCode e omp atrás de um contrato interno;
- manter a lógica de pipeline independente das APIs específicas dos runtimes.

### 11.2 Fases de implementação

#### Fase 1 — Port fiel do `ai-engineering-skills`

**Objetivo:** Trazer o sistema existente para `packs/software-engineering` sem alterar seu comportamento observável.

- registrar commit e inventário em `PORTED_FROM.md`;
- copiar skills, workflows, scripts, testes, docs e adapters;
- ajustar apenas caminhos necessários à nova localização;
- executar no pack os checks existentes `npm test` e `npm run check`;
- comprovar que contratos v3, Works e evidência continuam semanticamente válidos sob adapters novos `pwn-*`;
- não remover nem modificar o repositório de origem.

**Entrega:** PWN contém uma distribuição independente e funcional do `ai-engineering-skills` v3.

#### Fase 2 — CLI `pwn` sobre o pack v3

**Objetivo:** Expor o workflow existente sem rewrite prematuro.

- `pwn work specify / contract / plan / run / audit / status`;
- `pwn task run` e `pwn task capsule`;
- wrappers independentes `/pwn-*`, sem tocar nos `/make-*` instalados pela origem;
- scaffolding de profile, rules e skills;
- preservação dos paths de artefatos dos projetos trabalhados.

**Entrega:** O mesmo processo v3 pode ser operado pelo CLI canônico, inicialmente via Pi e sem perda de evidência.

#### Fase 3 — Baseline de artefatos e revisões de Work

**Objetivo:** Estabelecer os artefatos e gates que alimentam o Contract Engine antes de congelar qualquer contrato.

- artefatos de Work (`intake`, `discovery`, `requirements`, `prd`, `technical-decisions`, `spec`, `enrichment`, `work-governance`, `plan`, `progress`) sob `.pwn/work/<work-id>/`;
- matriz de rastreabilidade canônica e IDs estáveis;
- gates `GATE-DISC-REQ`, `GATE-REQ-PRD` e `GATE-PRD-SPEC` com formato de saída estruturado;
- enriquecimento cético e registro de decisões técnicas;
- schema do plano e contrato dos gates versionados.

**Entrega:** Works de engenharia têm artefatos rastreáveis e gates de aprovação antes da atomização.

#### Fase 4 — Contract Engine v4

**Objetivo:** Adicionar governança proporcional ao risco sem enfraquecer v3.

- schemas dos sete contratos;
- níveis L0–L4 e razões obrigatórias;
- estratégias `tdd-strict`, `contract-first`, `regression-guarded` e `visual-contract`;
- budget e escalation policy;
- validação de write allowlist, diff e out-of-scope;
- context capsule;
- `work-governance` no nível do Work e contratos por task congelados após o plano (dois níveis, sem duplicação normativa);
- gates `GATE-SPEC-PLAN` e `GATE-PLAN-CONTRACT` ligando spec → plano → contratos;
- leitura v3 e v4 lado a lado, sem migração automática.

**Entrega:** Tasks v4 limitam mecanicamente modelos baratos e escolhem validação proporcional.

#### Fase 5 — Executor econômico e escalação

**Objetivo:** Usar modelos baratos/local-first na execução e modelos fortes apenas quando o contrato exigir.

- routing declarativo por roles `cheap`, `strong`, `review` e `plan`;
- limites de tokens, custo, duração e tentativas;
- worktree por run;
- checks determinísticos antes de review por LLM;
- reviewer barato para L0/L1;
- escalação forte/humana por risco ou gatilho;
- fila assíncrona em `queue/review/`.

**Entrega:** Pipeline `Spec → Gates → Work-Governance → Plan → Task-Contracts → Cheap Patch → Verify → Escalate → Accept` funcional no Pi.

#### Fase 6 — OpenCode, omp e sub-agents

**Objetivo:** Executar o mesmo Work e os mesmos contratos nos três runtimes primários.

- adapters headless para OpenCode e omp;
- materialização nativa de sub-agents;
- normalização de sessão, tools, outputs e erros;
- materialização de profiles, rules e skills;
- testes de contrato compartilhados entre adapters.

**Entrega:** Um Work pode escolher Pi, OpenCode ou omp sem alterar seu contrato de negócio.

#### Fase 7 — Editor visual de pipelines

**Objetivo:** Entregar o utilitário gráfico offline sem acoplá-lo ao core.

- parser/serializer YAML incorporado e schema versionado;
- canvas de nós, conexões, containers, minimapa, pan, zoom e undo/redo;
- inspector para agents, roles, contracts, budget, validation e escalation;
- abrir por seletor/drag-and-drop e importar YAML embutido pelo CLI;
- salvar por File System Access API quando permitido e download como fallback;
- diff YAML, validação e aviso de serialização canônica antes de exportar;
- testes em `file://` nos navegadores desktop definidos pelo projeto;
- nenhuma execução de pipeline, hook ou command dentro do editor.

**Entrega:** `tools/pipeline-editor/index.html` auto-contido e `pwn pipeline gui [name]` funcionais.

#### Fase 8 — Métricas, otimização e teach skills

**Objetivo:** Evoluir o harness com evidência histórica.

- extension `pwn-metrics.ts` e adapters equivalentes;
- comparação por modelo, runtime, risk level e validation strategy;
- custo por Work/task aceita;
- taxa e motivo de escalação;
- recomendações de routing e budget sem aplicação automática;
- teach skills com estado bruto gitignored e `learnings.yaml` versionado.

**Entrega:** O operador consegue melhorar contratos, policies, skills e routing com base em runs reais.

---

## 12. Riscos e Mitigações

| Risco | Impacto | Mitigação |
|-------|---------|-----------|
| Divergência silenciosa entre origem e pack portado | Alto | `PORTED_FROM.md`, inventário, diff explícito e nenhuma sincronização automática |
| Regressão do workflow v3 durante o port | Alto | Port fiel primeiro; executar a suíte original antes de introduzir v4 |
| v4 enfraquecer evidência de Works v3 | Alto | Contratos versionados paralelos; sem migração automática; `tdd-strict` preserva semântica v3 |
| Modelo barato escrever fora do escopo | Alto | Tool-call guard + verificação de diff contra `write_allow` e `write_deny` |
| Classificação de risco otimista | Alto | Razões obrigatórias, promotion rules e proibição de downgrade pelo executor |
| Escalação excessiva apagar a economia | Médio | Métricas por gatilho, budget por task e otimização revisada pelo operador |
| Agentes concordarem sobre uma premissa errada | Alto | Validadores determinísticos; reviewer LLM não conta como prova isolada; humano em L4 |
| Drift com runtimes | Médio | Adapter isolado e testes de contrato compartilhados por versão observada |
| Complexidade de pipelines | Médio | Schemas, dry-run, steps curtos e topologia declarativa |
| Teach skills vazarem dados | Médio | Estado bruto gitignored; promoção manual e sanitizada para `learnings.yaml` |
| Omissão entre documentos de planejamento | Alto | Gates de cobertura/consistência e matriz de rastreabilidade com IDs estáveis |
| Aprovação implícita por timeout | Alto | Aprovação explícita; sem autoaprovação; `pass` só após checks aplicáveis |
| Revisor expandir requisitos não solicitados | Alto | Revisor não reescreve escopo; mudança só após decisão explícita do operador/owner |
| Perda silenciosa de campos na materialização | Alto | Capability matrix; falha/degrad explícita; campos de segurança/escopo/budget nunca descartados |

---

## 13. O que PWN NÃO é

- **Não é um webapp** — nenhum server, nenhum frontend, nenhum banco.
- **Não é um runtime de modelo** — não implementa inferência nem chama providers diretamente; orquestra Pi, OpenCode e omp via seus CLIs.
- **Não é um fork do Pi** — não modifica o Pi, apenas gera artefatos para ele.
- **Não substitui nem controla o repositório original `ai-engineering-skills`** — mantém uma porta independente e evolutiva no pack oficial.
- **Não é um MCP** — não expõe tools para agentes. É infraestrutura para o operador humano.
- **Não impõe stack aos projetos trabalhados** — TypeScript/Bun é a stack do PWN, não uma convenção global para os projetos.

---

## 14. Glossário

| Termo | Definição |
|-------|-----------|
| **Harness** | Tudo que está em volta do modelo LLM: contratos, prompts, rules, skills, tools, agents, processos e evidências |
| **Contract** | Ordem de serviço executável que congela comportamento, limites, aceitação, budget e escalação |
| **Risk Policy** | Regras determinísticas que associam impacto a executor, validação e review mínimos |
| **Validation Strategy** | Protocolo de prova selecionado antes da execução: tdd-strict, contract-first, regression-guarded ou visual-contract |
| **Context Capsule** | Contexto mínimo e delimitado entregue a um executor |
| **Pack** | Pacote de domínio que adiciona skills, workflows, validators e evidence ao núcleo genérico |
| **Port** | Cópia independente com proveniência registrada e evolução própria, sem sincronização automática |
| **Profile** | Unidade de identidade + configuração de um harness. Declara modelo, skills, rules e agents |
| **Skill** | Unidade de conhecimento ativável. Tipo reference, workflow, tool ou teach |
| **Teach Skill** | Skill com estado que entrevista o usuário e aprende progressivamente |
| **Rule** | Restrição ou padrão injetado passivamente no system prompt |
| **Sub-agent** | Agente especializado com modelo, prompt e tools próprios, selecionado explicitamente por um step do pipeline |
| **Pipeline** | Processo multi-step onde cada step pode usar um sub-agent diferente |
| **Hook** | Script executado em evento do ciclo de vida (pre-task, post-task, error, complete) |
| **Memory** | Sistema de persistência de conhecimento (graph ou session) |
| **Queue** | Fila de tarefas para execução AFK com review humano |
| **Target** | Runtime de destino para materialização (Pi, OpenCode, omp ou Raw) |
| **Materializer** | Componente que gera artefatos nativos de um target a partir da configuração PWN |
| **Metrics** | Dados coletados por execução: custo, tokens, tempo, loops, pass rate |
| **Discovery** | Entendimento verificável do problema a partir do pedido bruto (problema, atores, objetivos, restrições) |
| **Requirement** | Uso ou regra observável derivada do Discovery (story, regra, requisito funcional/não funcional) |
| **PRD** | Documento que consolida a decisão de produto aprovada, antes da spec técnica |
| **Technical Decision** | Escolha difícil de reverter, registrada com alternativas, consequências e aprovação |
| **Specification Review** | Revisão de cobertura/consistência da spec com contexto isolado e validação determinística |
| **Plan Review** | Gate que confirma que a spec foi decomposta sem perda e com ordem coerente |
| **Work Governance** | Contrato de nível de Work que congela risco global, invariantes e limites máximos antes do plano |
| **Traceability Matrix** | Mapa canônico de IDs ligando origem → requisito → decisão → spec → task → contrato → evidência |
| **Gate** | Etapa que combina revisão semântica e validação determinística e bloqueia findings materiais |
| **Skeptical Enrichment** | Revisão cética de caminhos não felizes, sem alteração automática de escopo |
| **UX Handoff Manifest** | Referência versionada e autoritativa do design visual de uma interface |

---

## 15. Registro de decisões do grilling

| ID | Tema | Decisão |
|----|------|---------|
| DEC-001 | Formatos | YAML para estrutura; Markdown para conteúdo destinado ao LLM. |
| DEC-002 | Execução de pipelines | Modelo híbrido: `dry-run` revisável e execução programática real dos runtimes. |
| DEC-003 | Métricas | Extension/adapters dedicados produzem um contrato JSONL estável de tokens, custo e duração. |
| DEC-004 | Sandbox AFK | Git worktree por default; checkpoint local como fallback; Docker fora do default inicial. |
| DEC-005 | Stack | TypeScript sobre Bun; compilação standalone opcional. |
| DEC-006 | Teach state | `state/` gitignored; `learnings.yaml` destilado e versionado. |
| DEC-007 | Repositório | PWN permanece separado do repositório original `ai-engineering-skills`. |
| DEC-008 | Orquestração | Pipeline YAML é o orquestrador; sem roteador LLM no MVP. |
| DEC-009 | Profiles | Um profile por projeto; sub-agents fornecem as especializações por step. |
| DEC-010 | Invocação de runtime | Adapters invocam CLIs headless; no Pi, `pi --print` com prompt/config materializados por step. |
| DEC-011 | Rules | Concatenação simples e ordenada com warning de budget; sem merge ou corte mágico. |
| DEC-012 | Review humano | Run é serializada em `queue/review/`, encerra sem bloquear e retoma após `pwn queue review`; sem autoaprovação inicial. |
| DEC-013 | Targets e sub-agents | Pi, OpenCode e omp são targets primários; sub-agents usam a melhor tradução nativa de cada um. |
| DEC-014 | CLI | O executável chama-se `pwn`. |
| DEC-015 | Port do ai-engineering-skills | O conteúdo é copiado para `packs/software-engineering`, com proveniência e evolução independente; a origem permanece intacta. |
| DEC-016 | Compatibilidade de contrato | O workflow v3 estrito permanece executável; v4 é aditivo e não migra Works antigos automaticamente. |
| DEC-017 | Governança econômica | Modelos fortes definem contratos e tratam escalações; modelos baratos executam dentro de limites impostos mecanicamente. |
| DEC-018 | Validação proporcional | TDD estrito é obrigatório por risco/policy, não universal; outras tasks usam estratégias executáveis declaradas. |
| DEC-019 | Namespace de adapters | O PWN instala somente `/pwn-*`; o repositório original conserva `/make-*`, e os dois podem coexistir. |
| DEC-020 | Editor visual de pipelines | O framework inclui utilitário gráfico autônomo (HTML/CSS/JS puros em `file://`) baseado em nós para visualização e edição de pipelines YAML. |
| DEC-021 | Persistência do editor | Save direto depende de File System Access API e consentimento; fallback obrigatório é download, com diff antes de serialização canônica. |
| DEC-022 | Discovery e PRD | Modelo híbrido: o pack `software-engineering` gera templates e valida imports; artefatos externos são validados e rastreados antes de virar contrato. |
| DEC-023 | Aprovação humana | Obrigatória ao menos para PRD, decisões técnicas de alto risco, spec com lacunas materiais e mudança de contrato/escrita; proporcional ao risco e nunca implícita. |
| DEC-024 | Localização dos artefatos | Artefatos v4 vivem em `.pwn/work/<work-id>/`; Works v3 mantêm seus manifests sem migração automática. |
| DEC-025 | Status do UX handoff | Declarado por Work (`approved_reference` ou `directional_reference`); default é `approved_reference` quando um handoff autorizado é fornecido. |
| DEC-026 | Finding material não resolvido | Varia por risco: L0/L1 podem adiar com referência; L2+ bloqueiam ou exigem `accepted_risk` documentado; nunca resolução implícita. |
| DEC-027 | Contrato dos gates | Gates produzem saída estruturada (`gate`, `work_id`, versões, `result`, findings com severidade e referências); LLM não marca PASS sozinho. |
| DEC-028 | Granularidade dos contratos | Dois níveis: `work-governance` antes do plano; contratos por task congelados após a atomização; sem duplicação normativa. |

As decisões acima substituem as perguntas abertas da versão 0.1. DEC-015 esclarece DEC-007: separação de repositórios não significa apenas integração externa; significa que este repositório mantém uma porta própria sem controlar a origem. DEC-022 a DEC-028 resultam da revisão v1.2 (governança de planejamento, granularidade dos contratos e capabilities de runtime). Novas dúvidas descobertas na implementação devem ser registradas como decisões numeradas, não reabrir silenciosamente estes contratos.
