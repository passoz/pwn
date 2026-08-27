# 🛡️ Piwerness (`pwn`)

> **Contract-Governed Agent Harness CLI** — Harness autônomo governado por contratos normativos em JSON, validação determinística de portões (*gates*), execução isolada em sandboxes Git Worktree e suporte multialvo de runtimes (Pi, OpenCode, omp).

[![Bun](https://img.shields.io/badge/Bun-v1.4.0-black?logo=bun)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)](https://www.typescriptlang.org/)
[![JSON Schema](https://img.shields.io/badge/JSON_Schema-Draft_2020--12-green?logo=json)](https://json-schema.org/)
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

# Executar a validação de todos os documentos normativos do repositório
bun bin/pwn.js validate

# Executar a suíte de testes (27/27 PASS)
bun test
```

---

## 🛠️ Guia de Comandos do CLI (`pwn`)

```bash
# Ajuda geral e versão
bun bin/pwn.js --help
bun bin/pwn.js --version

# Validação de Schemas JSON Normativos
bun bin/pwn.js validate [caminho]

# Gestão de Works e Portões (Gates) — Auto-incremento inteligente de Work IDs
bun bin/pwn.js work init                       # Auto-atribui o próximo Work ID (ex: 0001, 0002)
bun bin/pwn.js work init 0001                  # Inicializa um Work ID específico
bun bin/pwn.js work gate GATE-DISC-REQ         # Executa gate no último Work ID ativo
bun bin/pwn.js work gate GATE-REQ-PRD --work 0001

# Cápsula de Contexto de Tarefas (Contrato v4)
bun bin/pwn.js task capsule T-001              # Usa o último Work ID ativo automaticamente
bun bin/pwn.js task capsule T-001 0001

# Fila de Revisão Humana Assíncrona (AFK)
bun bin/pwn.js queue list
bun bin/pwn.js queue approve <run-id>
bun bin/pwn.js queue reject <run-id>

# Gerenciamento de Target Runtimes e Materialização
bun bin/pwn.js target list
bun bin/pwn.js target materialize --target opencode

# Telemetria de Métricas e Otimização de Routing
bun bin/pwn.js metrics list
bun bin/pwn.js metrics optimize

# Skills e Packs do Harness
bun bin/pwn.js skill list
bun bin/pwn.js pack list
```

## ⚡ Scripts Utilitários de Pré-Implementação

O Piwerness disponibiliza scripts autônomos para acelerar o ciclo de pré-implementação e aprovação nos 5 portões determinísticos até o congelamento da cápsula de contexto V4:

```bash
# Greenfield (sem spec legada): Cria e aprova a esteira até a pré-implementação a partir de uma ideia
./scripts/prepare-greenfield-work.sh "Novo Módulo de Pagamentos PIX"

# Brownfield (com spec legada): Importa a spec.md legada, vincula requisitos e aprova os portões
./scripts/prepare-legacy-reimplementation.sh /caminho/para/sua-spec.md
```

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
│   ├── commands/              # Subcomandos (work, task, queue, target, metrics, validate, skill, pack)
│   ├── core/                  # Motores nativos (gates, contract-engine, router, sandbox, queue, metrics)
│   └── targets/               # Adapters de target (pi, opencode, omp)
├── packs/
│   ├── core/                  # Pipeline normativo base (pipeline-core.json)
│   └── software-engineering/  # Pack oficial portado do ai-engineering-skills (88/88 PASS)
├── .specs/
│   └── system.json            # Especificação do sistema baseline (normativo)
├── schemas/                   # JSON Schemas formais (pipeline, prd, tasks, evidence, system)
├── tests/                     # Suíte de testes automatizados (Bun)
├── tools/
│   └── pipeline-editor/       # Editor visual standalone (index.html)
├── docs/
│   ├── MANUAL.md              # Manual Extenso e Completo da Ferramenta
│   └── archive/               # Arquivo histórico (SPEC.md e DECISIONS.md)
├── spec.json                  # Especificação técnica normativa técnica
├── todo.json                  # Plano de execução normativo (normativo)
└── validate.js                # Script de validação de esquemas
```

---

## 📚 Documentação e Manual

- 📖 **[Manual Completo da Ferramenta (MANUAL.md)](docs/MANUAL.md)** — Guia extenso de arquitetura, contrato V4, roteamento, gates, sandboxes e casos de uso.
- 🗄️ **[Arquivo Histórico (DECISIONS.md & SPEC.md)](docs/archive/)** — Registro de decisões de arquitetura e especificação original.

---

## ⚖️ Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais detalhes.
