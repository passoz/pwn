# 🛡️ PWN — Policy Work Norms (`pwn`)

> **Contract-Governed Agent Harness CLI** — Governança determinística de agentes de IA por contratos normativos em JSON, validação mecânica de portões (*gates*), execução isolada em Git Worktree sandboxes e contenção de escopo via Diff Guard.

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
[![JSON Schema](https://img.shields.io/badge/JSON_Schema-Draft_07-green?logo=json)](https://json-schema.org/)
[![Tests](https://img.shields.io/badge/Tests-go%20test%20.%2F...-brightgreen)](internal/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## 📌 Por que o PWN existe?

Agentes de codificação autônomos baseados unicamente em *prompts* sofrem de quatro falhas estruturais conhecidas:
1. **Desvio de Escopo (*Scope Drift*):** O agente decide refatorar arquivos não relacionados, deletar testes ou alterar a arquitetura sem autorização.
2. **Alucinação de Requisitos:** Invenção de premissas não aprovadas durante a transição entre ideia, requisitos e código.
3. **Custo Desproporcional:** Modelos de fronteira caros executando tarefas triviais, ou modelos baratos operando sem rédeas em tarefas críticas.
4. **Falso Sucesso:** Agentes reportam conclusão sem evidência mecânica auditável (ex.: testes não foram executados ou foram alterados para passar).

O **PWN** substitui a confiança cega em prompts por **mecanismos determinísticos de engenharia**:

| Abordagem Tradicional (Prompt-Only) | Abordagem PWN (Contract-Governed) |
|---|---|
| Prompts longos e instruções informais em Markdown | **Documentos normativos JSON** validados contra JSON Schemas formais |
| Agente altera qualquer arquivo do repositório | **Diff Guard mecânico**: escrita bloqueada fora de `write_allow` |
| Execução direta no branch de trabalho | **Sandboxes descartáveis em Git Worktree** (`.pwn/sandboxes/`) |
| Transições de fase avaliadas pelo próprio LLM | **5 Gates determinísticos em Go** com cache por hash e veredito HMAC |
| Modelo único ou seleção manual | **Roteamento por 5 níveis de risco (L0–L4)** com escalação automática |
| Conclusão baseada em texto ("Tarefa finalizada!") | **Aceitação independente** (`pwn verify`) com recibo assinado Ed25519 sobre um snapshot executado em sandbox; o loop local (`work audit`) apenas diagnostica |

---

## 🔄 Fluxo de Trabalho e Modelo Mental

Toda alteração de software no PWN segue uma cadeia estrita de rastreabilidade (proveniência) do problema à evidência verificada:

```mermaid
flowchart LR
    A[Discovery\nProblema & Atores] -->|GATE-DISC-REQ| B[Requirements\nRequisitos Funcionais]
    B -->|GATE-REQ-PRD| C[PRD\nDecisões Aceitas]
    C -->|GATE-PRD-SPEC| D[Spec\nCapabilities & Regras]
    D -->|GATE-SPEC-PLAN| E[Plan\nTarefas Atômicas]
    E -->|GATE-PLAN-CONTRACT| F[Contrato V4\n7 Dimensões Congeladas]
    F --> G[Sandbox Worktree\n+ Diff Guard]
    G --> H[Auditoria TDD local\nRed ➔ Green (diagnóstico)]
    H --> I[pwn verify\nsnapshot + bwrap + recibo Ed25519]
    I --> J[Global gates\nrecibo por gate]
```

1. **Cadeia de Planejamento:** Cada transição de fase exige a aprovação de um portão determinístico (*gate*). Se faltar vínculo de rastreabilidade, o portão bloqueia a execução.
2. **Contrato V4 Congelado:** Antes de executar qualquer código, a tarefa recebe um contrato atômico imutável (`CTR-*.json`) definindo `write_allow`, `write_deny`, invariantes e critérios de aceite. A partir de risco **L3+** o `GATE-PLAN-CONTRACT` exige também o congelamento dos testes de aceitação (`work contract --freeze-tests`), gravando seus hashes no contrato.
3. **Execução Confinada:** O agente executa dentro de uma Git Worktree isolada. O sandbox recebe o **HEAD mais a sua working tree não commitada** (diff rastreado + arquivos novos não ignorados, exceto `.pwn`, `.todo`, `.work` e `queue/review`): o comando de aceitação valida o seu código atual, não apenas o último commit. O Diff Guard confere as modificações via `git diff`; se o agente tocar em arquivos proibidos, a execução é abortada e escalada para revisão.
4. **Auditoria TDD local (diagnóstico):** O CLI só aceita, em cada ação, o comando exatamente como declarado no plano da task (`.todo/NNNN-tasks.md`, derivado de `.pwn/work/NNNN/plan.json`). O ciclo local é `baseline` (congela a definição da task) → `red` (comando do plano, `--expect` não-genérico e literal no arquivo de teste) → `green` (restaura a implementação ao commit do baseline e exige que a asserção volte a falhar) → `check` dos ACs do plano (cada `AC-*` também roda sem a implementação; se ainda passar, é recusado como **vácuo**) → `verify` (re-executa o comando do plano sobre a árvore atual). Esse loop é **diagnóstico do agente**: ele não conclui nada e não existe mais `audit candidate`/`audit gate`.
5. **Aceitação independente (`pwn verify`):** a conclusão vem de um verificador fora do repositório. `pwn verify init` cria a raiz protegida (chaves Ed25519, runtime aprovado, `bwrap`); `pwn verify approve --by <responsável>` congela um **pacote imutável** (checks do plano + cópia dos testes de aceitação congelados); `pwn verify run` captura um **snapshot determinístico** da entrega, materializa uma **cópia isolada**, **restaura o teste aprovado** por cima dela, executa cada check em `bwrap` com mounts mínimos (sem `HOME` do operador, sem rede, sem a chave) e emite um **recibo assinado** Ed25519. Só depois marque `[x]`: task concluída = recibo independente válido para a árvore atual (`ACCEPTED`). Alterar qualquer arquivo (ou dependência) **invalida** o recibo.

---

## 🚀 Instalação e Uso Rápido

### Pré-requisitos
- [Go](https://go.dev/dl/) 1.27 ou superior
- [Git](https://git-scm.com/)
- `bwrap` para a aceitação independente em Linux

### Instalação

```bash
# 1. Clonar o repositório
git clone https://github.com/passoz/pwn.git
cd pwn

# 2. Compilar o binário estático
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/pwn ./cmd/pwn

# 3. Validar a integridade dos documentos normativos do framework
bin/pwn self-check

# 4. Rodar a suíte completa de testes
go test ./...
```

*(Opcional)* Crie um alias local no seu shell para facilitar:
```bash
alias pwn="$(pwd)/bin/pwn"
```

---

## 👤 Guia do Usuário: Governando um Projeto com PWN

### 1. Criando um novo Work governado (Greenfield)

Para criar uma funcionalidade do zero com a cadeia completa e válida de ponta a ponta:

```bash
# Cria o esqueleto completo: discovery → requirements → prd → spec → plan + contratos V4
./scripts/prepare-greenfield-work.sh "Sistema de Autenticação JWT"

# Ou diretamente pelo CLI:
bin/pwn work scaffold --title "Sistema de Autenticação JWT" --risk L2
```

O comando gera os artefatos sob `.pwn/work/<work-id>/` (ex.: `.pwn/work/0002/`).

### 2. Validando a cadeia de portões (Gates)

Verifique se a cadeia documental está íntegra antes de encostar no código:

```bash
# Roda todos os 5 gates e exibe todos os achados em uma passada só:
bin/pwn work gate --all --work 0002

# Ou avalie um portão específico (com cache determinístico por hash):
bin/pwn work gate GATE-DISC-REQ --work 0002
bin/pwn work gate GATE-PLAN-CONTRACT --work 0002
```

### 3. Pré-voo de Execução (`--dry-run`)

Antes de gastar tokens ou criar sandboxes, faça o pré-voo para listar **todos** os impedimentos:

```bash
bin/pwn work run --dry-run --work 0002 -- bun test
```

Se houver gates pendentes ou contratos inválidos, o PWN lista todos os problemas e encerra sem executar comandos.

### 4. Executando com Sandbox e Diff Guard

Execute a tarefa com confinamento estrito:

```bash
# Exige gates aprovados, cria worktree temporária em .pwn/sandboxes/ e confere diff:
bin/pwn work run --work 0002 --timeout-seconds 600 -- bun test
```

- **Fail-closed:** Sem `--no-gate`, recusa qualquer Work com portão pendente.
- **Diff Guard:** Se o agente modificar algo fora de `write_allow` ou dentro de `write_deny`, a execução é abortada.
- **Escape consciente:** `--no-gate` pula os portões mantendo a guarda de escrita; `--no-isolation` pula a sandbox mas registra o escape em `.pwn/metrics.jsonl`.

### 5. Auditoria TDD Local (diagnóstico) + Aceitação Independente (`pwn verify`)

Cada ação do audit recebe, após `--`, o comando **exatamente como declarado no plano** da task (`.todo/NNNN-tasks.md`, derivado de `.pwn/work/NNNN/plan.json`): tokens idênticos ou `sh -c '<texto do plano>'`. Os arquivos de implementação e teste também saem do plano — `--implementation`/`--tests` são opcionais e, se passados, precisam bater com ele. O harness **nunca** executa um comando lido do repositório.

As ações válidas são **`baseline`, `red`, `green`, `verify` e `check`**. Esse loop é **diagnóstico local do agente** — ele prova causalidade e vacuidade, mas **não conclui** a task. Não existem mais `audit candidate` nem `audit gate`; a autoridade de conclusão é do verificador independente.

```bash
# 1. Baseline: exige árvore limpa nos arquivos declarados e congela a definição da task
#    (digest do bloco do plano + hash do contrato).
bin/pwn work audit baseline --work 0002 --task 1.1

# 2. RED: o comando tem que ser o RED do plano; --expect precisa ser não-genérico e
#    estar literalmente no arquivo de teste congelado.
bin/pwn work audit red --work 0002 --task 1.1 --expect "should throw UnauthorizedError" -- bun test tests/auth.test.ts

# 3. GREEN: implementação pronta. O mutation check restaura a implementação ao commit do
#    baseline e exige que a asserção volte a falhar; os testes não podem mudar após o RED.
bin/pwn work audit green --work 0002 --task 1.1 -- bun test tests/auth.test.ts

# 4. Checks do plano sobre o snapshot do GREEN. Todo AC-* roda também SEM a implementação:
#    se ainda passar, é recusado como vácuo.
bin/pwn work audit check --work 0002 --task 1.1 --name AC-1 -- bun test tests/auth.test.ts
bin/pwn work audit check --work 0002 --task 1.1 --name REGRESSION -- bun test

# 5. Verify local: re-executa o comando do plano sobre a árvore atual (exit 0 + expect).
bin/pwn work audit verify --work 0002 --task 1.1 -- bun test tests/auth.test.ts
```

- **Amarrado ao plano:** comando divergente do declarado reprova a ação; um `--expect` genérico (`fail`, `Error`, `expected`, muito curto…) é recusado no contrato v3.
- **Drift e contrato atual:** todas as fases do audit recusam divergência entre o Markdown e `plan.json`; um `plan.json` existente ilegível também é recusado. O `status` marca `INVALID PLAN` mesmo sem recibo.
- **GREEN/VERIFY:** exigem exit code `0` e o texto de sucesso (`expect`) quando declarado; a presença de `redExpect` na saída bem-sucedida não implica falha. O mutation check continua exigindo falha ao restaurar a implementação ao baseline.
- **Teste congelado (L3+):** `bin/pwn work contract --work 0002 --task 1.1 --freeze-tests tests/auth.test.ts` grava o `sha256` dos testes no contrato antes da implementação. A partir de risco L3 o `GATE-PLAN-CONTRACT` exige o congelamento; se um teste congelado mudar, o audit recusa `baseline` e o verificador recusa a aprovação (`frozen_tests` exigidos e conferidos contra o arquivo).
- **Marcador `[x]`:** só depois de `pwn verify run` **PASS** para a árvore atual. O `status` acusa `INCONSISTENT STATE` quando o marcador e o recibo discordam.

#### Aceitação independente

O audit local roda no mesmo processo e na mesma árvore do agente — por isso ele **não** conclui. A conclusão vem do `pwn verify`, um verificador cuja raiz fica **fora do repositório**:

```bash
# 1. init: cria a raiz protegida (~/.config/pwn/verifier, ou PWN_VERIFIER_HOME)
#    com chaves Ed25519, runtime aprovado e suporte a bwrap detectados no host.
bin/pwn verify init

# 2. approve: o OPERADOR aprova o pacote imutável de uma task (checks do plano +
#    cópia dos testes de aceitação congelados). Exige --by <responsável>.
bin/pwn verify approve --work 0002 --task 1.1 --by "ana"
#    Ou um item de ## Global gates:
bin/pwn verify approve --work 0002 --global G-1 --by "ana"

# 3. run: captura o snapshot da entrega, restaura o teste aprovado, executa cada
#    check em bwrap com mounts mínimos e emite o recibo assinado.
bin/pwn verify run --work 0002 --task 1.1

# 4. status/show: consulta a aceitação vigente e inspeciona aprovação + último recibo.
bin/pwn verify status --work 0002 --task 1.1
bin/pwn verify show --work 0002
```

- **Pacote imutável:** a aprovação guarda, na raiz protegida, o conteúdo dos testes de aceitação congelados. Durante o `run`, o verificador **restaura** esses arquivos por cima da cópia do candidato — enfraquecer o teste no repositório não muda o que é executado.
- **Snapshot determinístico:** o recibo identifica exatamente a árvore avaliada (caminho, tipo, modo e conteúdo de cada arquivo), exceto os diretórios de estado/dependência **na raiz** (`.git`, `.pwn`, `.todo`, `.work`, `queue`, `.pwn-verifier`, `node_modules`). Alterar qualquer arquivo depois da verificação **invalida** o recibo.
- **Causalidade do AC:** cada check `AC-*` roda também com a implementação revertida ao commit aprovado (baseline) e **precisa falhar**. Uma falha de baseline que pareça erro de ambiente/import (`looksEnvironmental`) recusa o check em vez de aceitá-lo.
- **Sandbox do verificador:** a cópia isolada roda em `bwrap` com mounts mínimos (sem `/` inteiro), `HOME=/nonexistent`, sem rede, `--unshare-user/pid`, ambiente reduzido e **sem a raiz do verificador nem a chave privada** ao alcance do código avaliado. O `projects` do `config.json` da raiz protegida pode ajustar a política por projeto: `path_prepend`, `mounts_ro`, `mounts` (`{source, dest}`), `home` e `env`. Esses ajustes são do **operador** (ficam fora do repositório avaliado) e entrada malformada **bloqueia** a verificação. Use `mounts` + `home` para toolchains e caches que exigem um caminho fixo relativo a `$HOME` (por exemplo, o cache do Postgres embarcado nos testes de integração).

  **Cache pré-aquecido (`overlays`, só no pwn Go).** O cache de compilação do Go fica em tmpfs e começa vazio a cada execução do sandbox: a biblioteca padrão é compilada de novo, cerca de 10 s por execução. Declare `"overlays": [{"source": "<dir fora do repositório>", "dest": "/tmp/gocache"}]` na entrada do projeto (com `GOCACHE` igual a `dest` em `env`) e rode `pwn verify warm`. O comando preenche `source` num sandbox que não contém arquivos do projeto (`go build std` por padrão, ou o comando depois de `--`). Nas verificações, `source` entra como camada somente leitura (`bwrap --overlay-src` e `--tmp-overlay`): o código avaliado lê o cache, e suas escritas somem ao fim da execução. `overlays` entra no digest do sandbox do recibo, então um recibo emitido com overlay não confere no verificador TypeScript. No projeto de teste, `pwn verify run` caiu de 24,6 s para 8,3 s.
- **Sem bwrap não há aceitação:** se o host não tem `bwrap`, o `run` **bloqueia** (exit `2`) em vez de degradar para execução no host.
- **Gate global com recibo próprio:** cada item de `## Global gates` é aprovado e verificado (`--global G-1`) com recibo próprio; `COMPLETE` deriva só de recibos válidos.
- **Limites de confiança (reais):** a aprovação é **ato do operador** e não é protegida contra um agente que rode como o **mesmo usuário do SO** (ele alcança a raiz protegida). A chave default vive no host — é uma raiz protegida `0700`, **não um HSM**. O `node_modules` é montado **read-only** a partir do repositório: a integridade de dependência é vinculada apenas pelo **digest dos manifestos** (`package.json`, `bun.lock`, `tsconfig.json`…). E testes fracos, uma vez aprovados, continuam aprovando. Congelar testes protege a **imutabilidade**, não a **suficiência**. Veja [os limites](docs/LIMITES.md).

### 6. Fila Assíncrona AFK (*Away From Keyboard*)

Tarefas de risco **L4** ou que falharam em múltiplas tentativas são suspensas para revisão humana em `queue/review/`:

```bash
# Listar tarefas suspensas aguardando aprovação
bin/pwn queue list

# Inspecionar e aprovar para execução
bin/pwn queue approve <run-id>

# Rejeitar execução de alto risco
bin/pwn queue reject <run-id>
```

### 7. Pós-conciliação (mudanças feitas sem o PWN)

Alterou o código por conta própria? Peça para o PWN conciliar depois do fato:

```bash
# Lista o que mudou fora da governança (não commitado; ou --since <commit> para o que já foi commitado)
bin/pwn work reconcile --dry-run

# Cria o Work conciliado (contrato com escopo exato dos arquivos). Sem teste na mudança? O Work já declara o teste a escrever depois
bin/pwn work reconcile --title "Corrige soma do add"

# Commite, congele o teste (se o comando avisar) e passe pela aceitação independente
bin/pwn work gate --all --work 0003
bin/pwn verify approve --work 0003 --task 1.1 --by "ana"   # baseline = commit anterior à mudança
bin/pwn verify run --work 0003 --task 1.1
```

A conciliação **não declara nada concluído**: não houve RED/GREEN observado. A task só vira `ACCEPTED` com recibo do `pwn verify`,
que reverte a implementação ao commit-base e exige que o teste congelado falhe lá.

---

## 🛠️ Guia do Desenvolvedor: Contribuindo com o PWN

Se você deseja desenvolver ou estender o PWN, a arquitetura foi desenhada para ser simples, sem magia e com checagens rigorosas.

### Estrutura do Código-Fonte

```
pwn/
├── cmd/pwn/                   # Composition root e código de saída
├── internal/
│   ├── cli/                   # Despacho de subcomandos, flags e ajuda
│   ├── commands/              # Handlers dos comandos (work, verify, task, queue, metrics, target, validate)
│   ├── assets/                # Schemas e VERSION embutidos com go:embed
│   ├── harness/
│   │   ├── plan/              # Plano, aceitação, validação e cápsula
│   │   ├── contract/          # Contrato V4, risco e Diff Guard
│   │   ├── policy/            # Política declarativa e motor ALLOW/DENY
│   │   ├── gates/             # 5 portões, cache HMAC e mutation testing
│   │   ├── audit/             # baseline/red/green/check/verify
│   │   ├── verify/            # Raiz protegida, snapshot, bwrap e recibo Ed25519
│   │   ├── decider/           # Decisor, políticas e ledger
│   │   ├── run/               # Orquestrador, Tool API e roteador
│   │   ├── sandbox/           # Git worktree e bwrap
│   │   ├── work/              # Artefatos, scaffold, reconcile e import v3
│   │   ├── batch/             # Lotes paralelos
│   │   ├── queue/             # Fila AFK
│   │   ├── metrics/           # Telemetria
│   │   ├── learnings/         # Aprendizados
│   │   └── target/            # Materializador Pi, OpenCode e omp
│   └── platform/              # jsonx, jsonschema, glob, fsx, proc, gitx, sandbox, cryptox
├── schemas/                   # JSON Schemas formais (Draft-07)
├── testdata/parity/           # Linha de base, vetores, corpus e prova do sandbox
├── tests/                     # Suíte TypeScript de referência
├── src/                       # Implementação TypeScript de referência
└── tools/pipeline-editor/     # Editor visual standalone (HTML/CSS/JS sem servidor)
```

A implementação oficial é o binário Go. `src/` e `tests/` permanecem como referência de comportamento e oráculo de paridade.

### Leis Embutidas e Proteção contra *Drift*

Os JSON Schemas em `schemas/` são copiados para `internal/assets/` e embutidos no binário com `go:embed`. Se os schemas em disco divergirem da cópia embutida, o CLI aborta com erro de integridade. Isso impede que alterações acidentais em schemas afrouxem a governança em tempo de execução.

### Comandos de Verificação do Framework

```bash
# Valida conformidade de schemas do framework
bin/pwn self-check

# Mutation testing dos gates (revela se algum gate é decorativo)
bin/pwn self-check --mutate

# Validação completa de CI (gofmt + vet + lint + testes + self-check + validate)
make check
```

---

## 📋 Referência Rápida de Comandos do CLI

### 🩺 Integridade & Validação
| Comando | Descrição |
|---|---|
| `pwn self-check` | Valida todos os documentos normativos do framework contra seus schemas |
| `pwn self-check --mutate` | Roda mutation testing quebrando artefatos para verificar se os gates bloqueiam |
| `pwn validate [--work NNNN]` | Valida os documentos JSON do(s) Work(s) com o validador Draft-07 |

### 📋 Governança de Works e Gates
| Comando | Descrição |
|---|---|
| `pwn work init` | Auto-atribui e cria o próximo Work ID sequencial com templates iniciais |
| `pwn work scaffold --title "..."` | Cria Work completo com cadeia válida (discovery → requirements → prd → spec → plan + CTR) |
| `pwn work reconcile [--since REF] [--tests ...] [--dry-run]` | **Pós-conciliação:** cria um Work que absorve mudanças feitas fora do pwn (escopo exato dos arquivos alterados; aceitação só via `pwn verify` contra o commit-base) |
| `pwn work gate --all [--work NNNN]` | Avalia os 5 gates em uma passada única e agrupa todos os achados |
| `pwn work gate <GATE> [--work NNNN]` | Avalia um portão específico (`GATE-DISC-REQ`, `GATE-REQ-PRD`, etc.) usando cache |
| `pwn work gate --clear-cache` | Limpa o cache de vereditos (`.pwn/gate-cache/`) |
| `pwn work status --coverage` | Exibe matriz de rastreabilidade (requisitos → caps → tasks → contratos → ACs) |
| `pwn work status` | Reporta o progresso: só conta task concluída com **recibo de aceitação independente** válido para a árvore atual (`ACCEPTED`); gates globais sem recibo próprio deixam o Work em `TASKS COMPLETE` (não `COMPLETE`) |
| `pwn work plan [--work NNNN]` | Renderiza ou valida o `plan.md` a partir do `plan.json` normativo |

### 🛡️ Execução, Sandboxes & Auditoria TDD
| Comando | Descrição |
|---|---|
| `pwn work run --dry-run -- <cmd>` | Pré-voo: lista todos os impedimentos (gates/contratos) sem executar comandos |
| `pwn work run -- <cmd>` | Execução completa em sandbox Worktree com Diff Guard e checagem de gates |
| `pwn work run --no-gate -- <cmd>` | Pula verificação de portões mantendo enforcement de sandbox e escrita |
| `pwn work audit baseline --work NNNN --task <T>` | Congela a definição da task (digest do bloco do plano + hash do contrato) e exige árvore limpa nos arquivos declarados |
| `pwn work audit red --work NNNN --task <T> --expect "..." -- <cmd do plano>` | Registra a fase RED: `--expect` não-genérico e literal no teste; comando tem que ser o RED do plano |
| `pwn work audit green --work NNNN --task <T> -- <cmd do plano>` | Registra a fase GREEN; o mutation check restaura a implementação ao commit do baseline e exige que a asserção volte a falhar |
| `pwn work audit check --work NNNN --task <T> --name AC-n\|VISUAL\|DOCUMENTATION\|REGRESSION\|LOCAL-GATES -- <cmd do plano>` | Roda um check do plano sobre o snapshot do GREEN; `AC-*` também roda sem a implementação (recusa critério vácuo) |
| `pwn work audit verify --work NNNN --task <T> -- <cmd do plano>` | Re-executa o comando do plano sobre a árvore atual (exit `0` + `expect`); diagnóstico local, **não** conclui |
| `pwn work audit --task <T> -- <cmd>` | Atalho legado: sem ação explícita, roda `verify` |
| `pwn work contract --work NNNN --task <T> --freeze-tests <arquivos>` | Congela (`sha256`) os testes de aceitação no contrato; exigido a partir de risco L3 |

> `pwn work audit candidate` e `pwn work audit gate` foram **removidos**: nenhum deles autoriza conclusão.

### ✅ Aceitação Independente (`pwn verify`)
| Comando | Descrição |
|---|---|
| `pwn verify init` | Cria a raiz protegida **fora do repositório** (`~/.config/pwn/verifier` ou `PWN_VERIFIER_HOME`): chaves Ed25519, runtime aprovado e suporte a `bwrap` detectado |
| `pwn verify approve --work NNNN --task <T> --by <responsável>` | O operador aprova o **pacote imutável** da task: checks do plano + cópia dos testes de aceitação congelados |
| `pwn verify approve --work NNNN --global G-n --by <responsável>` | Aprova um item de `## Global gates` (recibo próprio) |
| `pwn verify run --work NNNN --task <T>` | Executa a aceitação: snapshot da entrega, cópia isolada, restaura o teste aprovado, checks em `bwrap` (sem HOME do operador, sem rede, sem a chave) e emite o **recibo assinado Ed25519** |
| `pwn verify run --work NNNN --global G-n` | Executa a aceitação independente de um gate global |
| `pwn verify status --work NNNN --task <T>` | Informa se a árvore atual tem aceitação independente válida |
| `pwn verify show --work NNNN [--task <T>]` | Mostra a aprovação vigente e o último recibo |

### ⏸️ Fila Humana AFK & Cápsula
| Comando | Descrição |
|---|---|
| `pwn task capsule <task> <work>` | Exibe o contrato congelado V4 e a cápsula de contexto para o agente |
| `pwn queue list` | Lista tarefas suspensas aguardando revisão humana |
| `pwn queue approve <run-id>` | Aprova execução de tarefa retida na fila |
| `pwn queue reject <run-id>` | Rejeita execução de tarefa retida |

### 🎯 Targets, Métricas & Ferramentas Visuais
| Comando | Descrição |
|---|---|
| `pwn target list` | Exibe matriz de capacidades dos targets (`pi`, `opencode`, `omp`, `raw`) |
| `pwn target materialize --target opencode` | Materializa configs nativas (`AGENTS.md`, `opencode.jsonc`) sem perda silenciosa |
| `pwn metrics list` | Lista histórico de execuções com duração, custo e status de isolamento |
| `pwn metrics optimize` | Analisa telemetria e sugere papéis de modelo mais econômicos |

---

## 🚦 Códigos de Saída Semânticos (Automação AFK)

Para que pipelines de CI/CD e orquestradores não supervisionados operem sem ambiguidades, o PWN utiliza códigos de saída estritos por classe:

### Em `work run` (`--task`) e `task run`:
- `0`: **Sucesso** — Execução concluída dentro do orçamento e sem violações. Com `--task`, dispara a aceitação independente logo em seguida (quando existe aprovação vigente).
- `1`: **Violação / Bloqueio** — Portão bloqueado, violação do Diff Guard, estouro de orçamento, comando falhou ou a aceitação independente automática não foi `pass`.
- `3`: **Suspenso para Revisão Humana** — Tarefa de risco L4 ou com limite de tentativas esgotado colocada na fila `queue/review/`. Permite que loops AFK saibam que a tarefa **não** executou e **não** é uma falha irrecuperável.

### Em `work audit` (`baseline`, `red`, `green`, `verify`, `check`):
- `0`: **Sucesso** — Ação aceita: ciclo TDD comprovado ou check/vácuo aprovado. **Diagnóstico local; não conclui a task.**
- `1`: **Violação** — Procedimento inválido (ex.: comando divergente do plano, `--expect` genérico, implementação alterada antes do RED, teste modificado após o GREEN, check vácuo).
- `2`: **Incompleto** — Evidência ou pré-requisito ausente. O relatório lista exatamente o que falta fazer.
- `3`: **Suspenso** — Tarefa aguardando aprovação na fila.

### Em `verify` (`init`, `approve`, `run`, `status`, `show`):
- `0`: **Aceito / pronto** — `run` emitiu recibo `pass`; `status` encontrou aceitação válida; `init`/`approve`/`show` concluíram.
- `1`: **Não aceito / erro** — `run` com recibo `fail` (inclui check `blocked` por timeout); `status` sem aceitação válida; erro de comando.
- `2`: **Bloqueado** — verificador indisponível (`bwrap`, runtime ou chave ausentes) ou sem aprovação vigente. **Nunca** vira "aceito".

---

## ⚙️ Política Declarativa Opcional (`.pwn/policy.json`)

Você pode customizar thresholds, palavras-chave de risco e allowlists de shell sem alterar o código-fonte criando um arquivo `.pwn/policy.json`:

```json
{
  "risk_keywords": {
    "l3": ["auth", "payment", "webhook", "crypto", "token"],
    "l1": ["readme", "changelog", "docs"]
  },
  "gate_thresholds": {
    "max_findings_before_block": 0,
    "max_acs_per_task": 12
  },
  "shell": {
    "allowed_commands": [{ "command": "bun", "args": ["test"] }],
    "denied_commands": [],
    "allow_all_shell": false
  },
  "network": {
    "allowed_domains": [],
    "denied_domains": [],
    "allow_all_network": false
  }
}
```

O arquivo é validado por `schemas/policy.schema.json`. Se ausente, o PWN utiliza seus valores padrão seguros automaticamente.

---

## 🎨 Editor Visual de Pipelines (`pwn-gui`)

O PWN inclui um editor gráfico de pipelines web standalone em HTML/CSS/JavaScript puro que opera **100% offline via `file://`**, sem necessidade de backend ou dependências npm:

- **Localização:** `tools/pipeline-editor/index.html`
- **Recursos:** Renderização em tempo real de grafos de estágios, badges de gates, painel dual de código JSON, formulário visual para configuração de modelos e exportação de templates `.env.example`.

Abrir no navegador:
```bash
# Linux
xdg-open tools/pipeline-editor/index.html

# macOS
open tools/pipeline-editor/index.html
```

---

## 📚 Índice da Documentação

Aprofunde-se na arquitetura e nos detalhes de implementação através da documentação técnica:

- 📖 **[Manual Completo da Ferramenta (`docs/MANUAL.md`)](docs/MANUAL.md)** — Guia aprofundado cobrindo o Contract Engine v4, as 7 dimensões, roteamento, sandboxes e tutorial passo a passo.
- ⚠️ **[Limites Conhecidos (`docs/LIMITES.md`)](docs/LIMITES.md)** — Relatório de transparência técnica sobre o que o harness **não** garante, com evidências em código e alternativas recomendadas.
- 🛡️ **[Plano de Testes Adversariais (`docs/SECURITY-TEST-PLAN.md`)](docs/SECURITY-TEST-PLAN.md)** — Matriz adversarial de testes de segurança, validação de sandbox e contenção de Tool API.
- 🔍 **[Revisão da Fase 1 de Enforcement (`docs/REVIEW-FASE-1-ENFORCEMENT.md`)](docs/REVIEW-FASE-1-ENFORCEMENT.md)** — Auditoria técnica de arquitetura sobre os mecanismos de contenção e resiliência.
- 🧭 **[Plano de Ajustes (`docs/PLANO-AJUSTES.md`)](docs/PLANO-AJUSTES.md)** — Diagnóstico histórico de conformidade e critérios de aceite.
- 🗄️ **[Arquivo Histórico (`docs/archive/`)](docs/archive/)** — Registro de decisões arquiteturais originais (`DECISIONS.md`) e especificação inicial (`SPEC.md`).

---

## ⚖️ Licença

Distribuído sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para obter mais detalhes.
