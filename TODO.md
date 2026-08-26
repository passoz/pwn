# TODO — Piwerness

Mapa de implementação do Piwerness conforme `SPEC.md` v1.2. Cada marco é rastreado a uma fase da seção 11.2 e às seções que a detalham.

> Quando houver repositório git e código, cada marco se transforma em um plano v3 do `engineering-workflow` (`.todo/NNNN-tasks.md` com RED/GREEN e evidência), começando pelo Marco 1.

## Pré-requisitos (bloqueadores)

- [ ] Inicializar o repositório git (`git init`) — a evidência RED/GREEN do workflow depende de git.
- [ ] Definir a spec governante em `.specs/system.md` (ou declarar `SPEC.md` como fonte canônica para o validador do workflow).
- [ ] Scaffolding do monorepo (`packages/`, `packs/`, `extensions/`, `schemas/`, `tests/`) conforme seção 3.1.

## Marco 1 — Port fiel do `ai-engineering-skills` (Fase 1)

- [ ] Registrar commit e inventário em `PORTED_FROM.md` (seção 10.1).
- [ ] Copiar skills, workflows, scripts, testes, docs e adapters (seção 10.2).
- [ ] Ajustar apenas caminhos necessários à nova localização.
- [ ] Executar `npm test` e `npm run check` no pack — evidência v3 preservada.
- [ ] Comprovar contratos v3 sob adapters `/pwn-*` (seção 10.6).
- [ ] Não remover nem modificar o repositório de origem (seção 10.1).

## Marco 2 — CLI `pwn` sobre o pack v3 (Fase 2)

- [ ] `pwn work specify / contract / plan / run / audit / status`.
- [ ] `pwn task run` e `pwn task capsule`.
- [ ] Wrappers `/pwn-*` sem tocar nos `/make-*` da origem.
- [ ] Scaffolding de profile, rules e skills.
- [ ] Preservação dos paths de artefatos dos projetos trabalhados.

## Marco 3 — Baseline de artefatos e revisões de Work (Fase 3)

- [ ] Artefatos de Work sob `.piwerness/work/<work-id>/` (seção 10.8).
- [ ] Matriz de rastreabilidade canônica e IDs estáveis (seção 10.8).
- [ ] Gates `GATE-DISC-REQ`, `GATE-REQ-PRD` e `GATE-PRD-SPEC` (seção 10.9).
- [ ] Enriquecimento cético (seção 10.10) e decisões técnicas por especialidade (seção 10.11).
- [ ] Schema do plano e contrato dos gates versionados.

## Marco 4 — Contract Engine v4 (Fase 4)

- [ ] Schemas dos sete contratos (seção 4.1).
- [ ] Níveis L0–L4 e razões obrigatórias (seção 4.2).
- [ ] Estratégias de validação (seção 4.3).
- [ ] Budget e escalation policy.
- [ ] Validação de write allowlist, diff e out-of-scope.
- [ ] `work-governance` + contratos por task congelados após o plano (seções 10.8/10.12).
- [ ] Gates `GATE-SPEC-PLAN` e `GATE-PLAN-CONTRACT` (seção 10.9).
- [ ] Context capsule (seção 10.5).
- [ ] Leitura v3/v4 lado a lado, sem migração automática (seção 10.3).

## Marco 5 — Executor econômico e escalação (Fase 5)

- [ ] Routing declarativo por roles `cheap`, `strong`, `review`, `plan`.
- [ ] Limites de tokens, custo, duração e tentativas.
- [ ] Worktree por run (seção 4.11).
- [ ] Checks determinísticos antes de review por LLM.
- [ ] Reviewer barato para L0/L1; escalação forte/humana por risco ou gatilho.
- [ ] Fila assíncrona `queue/review/`.

## Marco 6 — OpenCode, omp e sub-agents (Fase 6)

- [ ] Adapters headless para OpenCode e omp (seção 6).
- [ ] Capability matrix e materialização sem perda silenciosa (seção 6.5).
- [ ] Materialização nativa de sub-agents.
- [ ] Normalização de sessão, tools, outputs e erros.
- [ ] Testes de contrato compartilhados entre adapters.

## Marco 7 — Editor visual de pipelines (Fase 7)

- [ ] Parser/serializer YAML incorporado e schema versionado.
- [ ] Canvas, conexões, containers, minimapa, pan, zoom e undo/redo.
- [ ] Inspector para agents, roles, contracts, budget, validation e escalation.
- [ ] `pwn pipeline gui [name]` (seção 9).
- [ ] Testes em `file://` nos navegadores desktop definidos.

## Marco 8 — Métricas, otimização e teach skills (Fase 8)

- [ ] Extension `pwn-metrics.ts` + adapters equivalentes.
- [ ] Comparação por modelo, runtime, risk level e validation strategy.
- [ ] Custo por Work/task aceita; taxa e motivo de escalação.
- [ ] Métricas de qualidade do processo e rastreabilidade (seção 8.1).
- [ ] Recomendações de routing/budget sem aplicação automática.
- [ ] Teach skills com `state/` gitignored e `learnings.yaml` versionado.

## Próximos passos

1. `git init` e definição da spec governante (`.specs/system.md`).
2. Concluir Marco 1 (port) — aqui o plano v3 (`/make-todo`) já se aplica, pois há código real (a origem) para evidenciar com RED/GREEN.
3. A partir do Marco 2, cada subcomando/contrato vira uma task atômica rastreável à spec.
