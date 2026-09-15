# 🛡️ Piwerness (`pwn`)

> **Contract-Governed Agent Harness CLI** — Harness autônomo governado por contratos normativos em JSON, validação determinística de portões (*gates*), execução isolada em sandboxes Git Worktree e suporte multialvo de runtimes (Pi, OpenCode, omp).

[![Bun](https://img.shields.io/badge/Bun-v1.4.0-black?logo=bun)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)](https://www.typescriptlang.org/)
[![JSON Schema](https://img.shields.io/badge/JSON_Schema-Draft_07-green?logo=json)](https://json-schema.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## 📌 Visão Geral

O **Piwerness** (`pwn`) é uma plataforma de engenharia de software autônoma e um harness de agentes de IA governado por **contratos formais e determinísticos**. Ele substitui prompts genéricos por pipelines orientadas a artefatos e contratos rígidos de 7 dimensões, garantindo que executores de IA não violem o escopo, a arquitetura ou os invariantes do projeto.

### 🌟 Principais Recursos

- **Governança por Documentos Normativos JSON (DEC-029):** Pipelines, PRDs, especificações do sistema, tarefas e evidências são representados em arquivos JSON estritamente validados contra JSON Schemas (`schemas/*.schema.json`).
- **Contract Engine v4:** Contratos atômicos de 7 dimensões (`behavioral`, `change`, `architecture`, `acceptance`, `scope`, `budget`, `escalation`) com classificação de risco **L0 a L4**.
- **Diff Guard (Guarda Mecânica de Escrita):** Bloqueio automático por `git diff` caso o executor modifique arquivos fora da `write_allow` ou dentro de `write_deny`.
- **Portões Determinísticos (Gates):** Transições de fases (`GATE-DISC-REQ`, `GATE-REQ-PRD`, `GATE-PRD-SPEC`, `GATE-SPEC-PLAN`, `GATE-PLAN-CONTRACT`) avaliadas nativamente via TypeScript.
- **Roteamento por Papéis e Escalação:** Roteamento econômico de agentes (`cheap` para execução rápida, `strong` para raciocínio complexo, `plan` para planejamento, `review` para auditoria).
- **Sandboxes em Git Worktree:** Isolamento de execução de tarefas sob `.piwerness/sandboxes/<run-id>` sem sujar o branch de trabalho principal.
- **Fila Assíncrona AFK (`queue/review/`):** Suspensão graciosa de tarefas de alto risco (L4) ou escaladas para aprovação/rejeição humana via CLI.
- **Matriz de Capacidades Multialvo:** Adapters nativos de materialização para os runtimes **Pi**, **OpenCode** e **omp** sem degradação silenciosa.
- **Editor Visual (`pwn-gui`):** Utilitário web standalone em `file://` (`tools/pipeline-editor/index.html`) para edição e visualização de pipelines em tempo real.
- **Telemetria & Teach Skills:** Métrica de tokens/custo em JSONL (`.piwerness/metrics.jsonl`) com recomendações de otimização de routing e aprendizado contínuo (`.piwerness/learnings.json`).

---

## 🚀 Instalação e Uso Rápido

### Pré-requisitos
- [Bun](https://bun.sh) v1.4.0 ou superior
- [Node.js](https://nodejs.org) v20+ / v26.3.0
- Git

### Instalação e Validação

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/piwerness.git
cd piwerness

# Runtime obrigatório: Bun (>= 1.4). Node não é suportado.
bun --version

# Validar os documentos normativos do próprio framework
bun bin/pwn.js self-check

# Executar a suíte de testes (Bun) — o número de testes fica visível na saída
bun test

# Gate de CI local: typecheck + testes + self-check + validate
bun run check
```

> **Runtime único:** o `pwn` é Bun-first. `node bin/pwn.js` falha com mensagem clara
> apontando para `bun`. Os scripts npm (`bun run check`, `bun run validate`) usam Bun.
> O CLI é autocontido: toda a lógica de governança e auditoria vive em `src/`, sem
> dependência de packs ou scripts externos.

> **Códigos de saída de `work run` / `task run`:** `0` sucesso · `1` falha (gate, contrato,
> política ou diff guard) · `3` **suspenso para revisão humana** (risco L4 enfileirado em
> `queue/review/`, sem executar). O código `3` existe para que automação AFK não confunda
> "não executou" com "sucesso".

---

## 🛠️ Guia de Comandos do CLI (`pwn`)

```bash
# Ajuda geral e versão
bun bin/pwn.js --help
bun bin/pwn.js --version

# Validação de Documentos Normativos
bun bin/pwn.js validate --work 0001            # Valida prd.json/plan.json do Work com JSON Schema (ajv)
bun bin/pwn.js self-check                      # Valida os documentos do próprio framework

# Gestão de Works e Portões (Gates) — Auto-incremento inteligente de Work IDs
bun bin/pwn.js work init                       # Auto-atribui o próximo Work ID (ex: 0001, 0002)
bun bin/pwn.js work init 0001                  # Inicializa um Work ID específico
bun bin/pwn.js work gate GATE-DISC-REQ         # Executa gate no último Work ID ativo
bun bin/pwn.js work gate GATE-REQ-PRD --work 0001
bun bin/pwn.js work specify --work 0001        # Especifica mudanças no baseline (valida o prompt-change.md)
bun bin/pwn.js work contract --work 0001       # Valida os contratos V4 congelados (CTR-*.json) do Work
bun bin/pwn.js work scaffold --title "..."     # Cria um Work novo com cadeia completa e válida (discovery→prd→spec→plan+CTR)
bun bin/pwn.js work import --all               # Importa Works do layout v3 (.work/, .todo/) para o layout canônico
bun bin/pwn.js work import --all --risk auto   # idem, congelando risco por task (L1/L2/L3) a partir do conteúdo
bun bin/pwn.js work plan --work 0001           # Gera/valida o markdown do plano a partir de plan.json
bun bin/pwn.js work sync --work 0001           # Sincroniza o state do manifest .work/NNNN.json

# Execução e Auditoria (fail-closed por padrão + enforcement em runtime)
bun bin/pwn.js work run --work 0001 --timeout-seconds 600 -- bun test   # Exige a cadeia de 5 gates + executa em sandbox com diff guard
bun bin/pwn.js work run --no-gate --work 0001 --timeout-seconds 600 -- bun test    # Pula gates; enforcement continua
bun bin/pwn.js work run --no-isolation --work 0001 -- bun test          # Pula sandbox; política continua (escape registrado em metrics.jsonl)
bun bin/pwn.js work audit --work 0001 --task 1.1                        # Verifica evidência TDD (assume verify)
bun bin/pwn.js work audit red --work 0001 --task 1.1 --expect "..." -- bun test   # Registra RED via CLI

# Cápsula de Contexto de Tarefas (contrato V4 congelado)
bun bin/pwn.js task capsule 1.1 0001           # Lê o CTR congelado (não gera default genérico)

# Fila de Revisão Humana Assíncrona (AFK)
bun bin/pwn.js queue list
bun bin/pwn.js queue approve <run-id>
bun bin/pwn.js queue reject <run-id>

# Gerenciamento de Target Runtimes e Materialização
bun bin/pwn.js target list
bun bin/pwn.js target materialize --target opencode

# Telemetria de Métricas e Otimização de Routing
bun bin/pwn.js metrics list                    # Histórico de execuções, com flag de sandbox (isolated) por run
bun bin/pwn.js metrics optimize
```

## ⚡ Scripts Utilitários de Pré-Implementação

Os scripts criam a cadeia completa e **válida** de um Work novo (discovery → requirements →
PRD → spec → plan + contrato V4 congelado), aprovam os 5 portões determinísticos, validam os
schemas e exibem a cápsula de contexto. Ambos são wrappers finos de `pwn work scaffold`, rodam
**de qualquer diretório** e aceitam `PWN_DIR` (projeto-alvo) e `PWN_BIN` (comando do CLI).

```bash
# Greenfield (sem spec legada): a partir de uma ideia
./scripts/prepare-greenfield-work.sh "Novo Módulo de Pagamentos PIX"

# Brownfield (com spec legada): importa a spec.md e a snapshota no Work
./scripts/prepare-legacy-reimplementation.sh /caminho/para/sua-spec.md

# Contra outro projeto, sem sair do diretório atual
PWN_DIR=../meu-projeto ./scripts/prepare-greenfield-work.sh "Nova feature"
```

> Os scripts só produzem um **esqueleto** com placeholders; o plano
> (`.piwerness/work/<id>/plan.json`) precisa ser detalhado antes de implementar. Para adequar um
> projeto que já usa o layout v3 (`.work/`, `.todo/`, `.prompts/`, `.sources/`, `.specs/`) ao
> piwerness, use `pwn work import --all --gate-chain`.

---

## 🎨 Editor Visual de Pipelines (`pwn-gui`)

O Piwerness inclui um editor visual de pipelines autocontido em HTML/CSS/JS que funciona 100% offline via `file://`:

- **Arquivo:** `tools/pipeline-editor/index.html`
- **Recursos:** Edição JSON dual-pane, renderização gráfica de estágios com badges de portões e papéis, validação em tempo real e exportação.

Abrir no navegador:
```bash
# Linux
xdg-open tools/pipeline-editor/index.html
# macOS
open tools/pipeline-editor/index.html
```

---

## 📁 Estrutura do Repositório

```
piwerness/
├── bin/                       # Binário do CLI (pwn.js)
├── src/
│   ├── cli.ts                 # Ponto de entrada do CLI
│   ├── commands/              # Subcomandos (work, task, queue, target, metrics, validate)
│   ├── core/                  # Motores nativos (gates, contract-engine, router, sandbox, queue, metrics, validação e auditoria TDD)
│   └── targets/               # Adapters de target (pi, opencode, omp)
├── packs/
│   └── core/                  # Pipeline normativo base (pipeline-core.json)
├── .specs/
│   └── system.json            # Especificação do sistema baseline (normativo)
├── schemas/                   # JSON Schemas formais (draft-07): pipeline, prd, tasks, evidence, system, plan
├── tests/                     # Suíte de testes automatizados (Bun)
├── tools/
│   └── pipeline-editor/       # Editor visual standalone (index.html)
├── docs/
│   ├── MANUAL.md              # Manual Extenso e Completo da Ferramenta
│   └── archive/               # Arquivo histórico (SPEC.md e DECISIONS.md)
├── spec.json                  # Especificação técnica normativa técnica
└── todo.json                  # Plano de execução normativo (normativo)
```

---

## 📚 Documentação e Manual

- 📖 **[Manual Completo da Ferramenta (MANUAL.md)](docs/MANUAL.md)** — Guia extenso de arquitetura, contrato V4, roteamento, gates, sandboxes e casos de uso.
- 🧭 **[Plano de Ajustes (PLANO-AJUSTES.md)](docs/PLANO-AJUSTES.md)** — Diagnóstico F0-F5, critérios de aceite e status de execução.
- 🗄️ **[Arquivo Histórico (DECISIONS.md & SPEC.md)](docs/archive/)** — Registro de decisões de arquitetura e especificação original.

---

## ⚖️ Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais detalhes.
