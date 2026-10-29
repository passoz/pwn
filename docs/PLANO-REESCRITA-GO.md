# Panorama do plano: reescrita do pwn em Go

**Status:** revisão 1. Proposta para aprovação. Nenhum código de produção existe nesta proposta.

**Data:** 2026-10-28

**Branch:** `pwngo`

**Referência de comportamento:** commit `c81a18b` do pwn atual em TypeScript sobre Bun.

**Resumo:** a reescrita tem 9 fases e um contrato de paridade em três níveis. A ordem das fases segue o grafo real de dependências do código. O pwn atual governa a reescrita, com um Work por fase. O corte troca o ambiente de execução TypeScript por um binário Go estático, sem dependência externa. A estimativa é de 43 a 55 dias de trabalho, isto é, 9 a 11 semanas.

A seção 15 registra os achados da revisão e as correções.

---

## 1. Objetivo

Reescreva o CLI (interface de linha de comando) pwn em Go. Mantenha o comportamento observável, os artefatos e as garantias de segurança. Use o pwn atual como referência de comportamento e como orquestrador da própria reescrita.

## 2. Não objetivos

- O editor visual `tools/pipeline-editor` permanece em HTML (linguagem de marcação de hipertexto), CSS (folhas de estilo em cascata) e JavaScript.
- Os ambientes de execução Pi, OpenCode e omp permanecem externos.
- Os schemas, os formatos de artefato e o modelo de governança não mudam nesta fase.
- O binário não terá servidor HTTP (protocolo de transferência de hipertexto), banco de dados, ORM (mapeamento objeto-relacional), contêiner ou interface web.
- A reescrita não adiciona funcionalidade nova.

## 3. Fatos de base

| Item | Valor |
|---|---|
| Implementação atual | TypeScript sobre Bun |
| Commit de referência | `c81a18b` |
| Código | 17.185 linhas em `src/` |
| Testes | 41 suítes, 470 testes, 649 asserções |
| Interface | 36 subcomandos |
| Schemas | 7 arquivos Draft-07, 1.324 linhas |
| Palavras-chave de schema em uso | 17 (seção 7) |
| Limites do plano | 40 tarefas por Work, 3 componentes por tarefa. O schema aceita 12 arquivos de implementação, mas o validador semântico limita 3 arquivos, 3 critérios de aceite e 2 passos por tarefa |
| Targets | `pi`, `opencode`, `omp`, `raw` |
| Ambiente de teste | Bun 1.4.2 |
| Conjunto de ferramentas Go | Go 1.27.1 instalado |
| Isolamento | `bwrap` instalado em `/usr/bin/bwrap` |
| Lint | `golangci-lint` 2.14.0 instalado |
| Worktree | `/home/passoz/dev/pwn-pwngo`, branch `pwngo` |

### 3.1 Superfície atual

O CLI tem 36 subcomandos:

| Grupo | Subcomandos |
|---|---|
| `work` | `init`, `import`, `scaffold`, `reconcile`, `gate`, `specify`, `contract`, `plan`, `run`, `run-all`, `batch`, `audit`, `status`, `sync` |
| `task` | `run`, `capsule` |
| `target` | `list`, `materialize` |
| `metrics` | `list`, `optimize` |
| `queue` | `list`, `approve`, `reject` |
| `verify` | `init`, `approve`, `run`, `run-all`, `status`, `show` |
| `decider` | `show`, `set`, `remove`, `log` |
| Outros | `validate`, `self-check`, `init` |

O código tem 52 módulos em `src/core`, 9 manipuladores de comando em `src/commands` e 3 adaptadores em `src/targets`.

### 3.2 Artefatos que precisam de compatibilidade

| Artefato | Local |
|---|---|
| Works (unidades de governança) | `.pwn/work/<id>/` |
| Planos derivados | `.todo/NNNN-tasks.md` |
| Evidência local | `.todo/evidence/` |
| Manifesto v3 | `.work/NNNN.json` |
| Cache de portão | `.pwn/gate-cache/` |
| Métricas | `.pwn/metrics.jsonl` |
| Fila AFK (revisão longe do teclado) | `queue/review/` |
| Lote | `.pwn/batch.json` |
| Travas entre processos | diretório `<alvo>.lock` |
| Raiz do verificador | `~/.config/pwn/verifier/` ou `PWN_VERIFIER_HOME` |
| Targets (alvos de materialização) | `.pwn/targets/` |
| Schemas normativos | `schemas/` |

Os dois binários podem tocar os mesmos artefatos durante a transição. Por isso a trava `mkdir` do pwn atual permanece. Uma trava `flock` não exclui o outro binário.

## 4. Contrato de paridade

A paridade tem três níveis. Cada nível tem um critério de aceite próprio.

| Nível | Escopo | Critério |
|---|---|---|
| A. Dados e segurança | JSON (JavaScript Object Notation) canônico, SHA-256, HMAC (código de autenticação de mensagem), Ed25519, recibos, aprovações, instantâneos, cache de portão, markdown do plano, arquivos de target | Bytes idênticos |
| B. Interface | Comandos, opções, códigos de saída, efeitos no sistema de arquivos, decisões de validação | Mesmo resultado observável |
| C. Texto humano | Ajuda, mensagens de erro, relatórios | Mesmos termos-chave e mesma estrutura; texto pode ter ajuste |

O nível A vale quando o byte entra em hash, assinatura ou comparação. Um recibo emitido pelo pwn atual precisa valer no pwn Go. O contrário também precisa valer.

O nível B vale para toda automação. Um comando com a mesma entrada precisa produzir o mesmo código de saída e a mesma árvore de arquivos.

O nível C permite ajuste de redação. Os testes de contrato fixam os termos-chave, os códigos de saída e as linhas de uso.

### 4.1 Compatibilidade do JSON

O pacote `jsonx` tem dois modos. O modo canônico ordena as chaves para assinatura. O modo de inserção preserva a ordem do arquivo para os hashes de instantâneo e de leis.

O `encoding/json` de Go difere do `JSON.stringify` em cinco pontos:

- Go escapa `<`, `>` e `&`. O JavaScript não escapa. Desligue o escape HTML.
- Go escapa U+2028 e U+2029. O JavaScript não escapa.
- Go troca um substituto isolado por U+FFFD. O JavaScript escreve `\udXXX`.
- O JavaScript ordena primeiro as chaves inteiras. Um `map` de Go não guarda ordem.
- A forma de números como `1e21` e de decimais difere.

Por isso o modo de inserção usa um decodificador próprio sobre `json.Decoder.Token`. Cada ponto acima tem um vetor de referência gerado pelo pwn atual.

## 5. Arquitetura Go proposta

```text
cmd/
  pwn/
    main.go                 # raiz de composição, sinais e código de saída
internal/
  cli/                      # argumentos, opções globais, ajuda, despacho
  config/                   # variáveis de ambiente lidas uma vez
  harness/
    plan/                   # plano, aceitação, validação de plano e de prompt, cápsula, contrato da tarefa
    contract/               # contrato V4, risco, Diff Guard
    policy/                 # política declarativa e motor de política
    gates/                  # 5 portões, cache HMAC, mutation testing
    audit/                  # baseline, red, green, check, verify local
    verify/                 # raiz do verificador, aprovação, instantâneo, executor, recibo, fluxo
    decider/                # configuração, políticas, adaptador HTTP, registro
    run/                    # orquestrador, roteador, Tool API, sobreposição de escopo
    queue/                  # fila AFK
    metrics/                # telemetria e otimização
    learnings/              # aprendizados
    work/                   # artefatos, manifesto, status, scaffold, reconcile, import
    batch/                  # lotes paralelos
    target/                 # matriz de capacidades e materializadores
  platform/
    jsonx/                  # JSON canônico e de inserção
    jsonschema/             # validador Draft-07 próprio
    glob/                   # matcher com **, {a,b} e classes
    fsx/                    # escrita atômica, trava mkdir, detecção de entrada
    cryptox/                # SHA-256, HMAC e Ed25519
    proc/                   # conjunto, tempo limite e grupo de processos
    gitx/                   # adaptador do git
    sandbox/                # worktree e bwrap
  assets/                   # schemas e arquivo VERSION embutidos com go:embed
```

### 5.1 Regras de dependência

- O pacote `cli` importa `harness` e `platform`.
- Os pacotes `harness` importam `platform` e outros pacotes `harness`, na ordem das camadas da seção 5.3.
- Nenhum pacote importa `cli`. O pacote `platform` nunca importa `harness`.
- Declare uma interface (porta) só na fronteira de entrada e saída que o teste precisa trocar. Essas fronteiras são git, processo, sandbox, HTTP e relógio.
- Declare a interface no pacote que a consome.
- Não crie interface para `jsonx`, `glob`, `cryptox` e `fsx`. Os testes usam `t.TempDir()`.
- O `cmd/pwn` monta as dependências à mão. Não use contêiner de injeção.
- Use erros sentinela e `%w`. Nunca retorne `nil, nil`.
- Passe `context.Context` como primeiro argumento das funções com entrada e saída. O `main` cria o contexto com `signal.NotifyContext`.
- Leia o ambiente só em `internal/config`. Nenhum pacote `harness` chama `os.Getenv`.

### 5.2 Mapa de módulos

Todos os 59 módulos de `src/` têm um destino. A coluna de linhas conta o código TypeScript de referência.

| Pacote Go | Módulos TypeScript | Linhas | Fase |
|---|---|---|---|
| `platform/fsx` | `fs-lock`, `entry-guard` | 104 | 1 |
| `platform/glob` | `glob-utils` | 182 | 1 |
| `platform/jsonschema` | `validator` | 257 | 1 |
| `platform/proc` | `process-pool` | 96 | 1 |
| `harness/plan` | `plan-renderer`, `acceptance`, `validate_tasks`, `validate_prompt`, `capsule`, `task-contract` | 2.081 | 2 |
| `harness/contract` | `contract-engine`, `contract-guard` | 459 | 2 |
| `harness/policy` | `policy-config`, `policy-engine` | 609 | 2 |
| `harness/verify` | `verifier-home`, `acceptance-approval`, `candidate-snapshot`, `verification-runner`, `verification-receipt`, `acceptance-flow` | 1.496 | 3 |
| `harness/gates` | `gates`, `gate-cache`, `self_check_mutate` | 2.015 | 4 |
| `harness/audit` | `task_evidence` | 1.019 | 4 |
| `harness/decider` | `decider/**` | 933 | 5 |
| `platform/sandbox` | `sandbox` | 208 | 6 |
| `harness/run` | `run-orchestrator`, `runner`, `tool-api`, `router`, `scope-overlap` | 1.491 | 6 |
| `harness/queue` | `queue` | 100 | 6 |
| `harness/metrics` | `metrics` | 93 | 6 |
| `harness/learnings` | `learnings` | 55 | 6 |
| `harness/work` | `work-artifacts`, `work-manifest`, `project_status`, `manifest-sync`, `scaffold`, `reconcile`, `v3-import` | 2.680 | 7 |
| `harness/batch` | `batch` | 775 | 7 |
| `harness/target` | `target-materializer`, `targets/*` | 332 | 8 |
| `cli` | `cli`, `commands/*` | 2.200 | 1 a 8 |

O código de `commands/*` divide-se por grupo de comando. Cada fase porta os manipuladores dos comandos que entrega.

### 5.3 Camadas de dependência

A tabela vem do grafo de importações do código atual. Um pacote só depende de camadas mais baixas.

| Camada | Pacotes | Depende de |
|---|---|---|
| 0 | `fsx`, `glob`, `jsonschema`, `jsonx`, `cryptox`, `proc`, `queue`, `target` | Nenhum pacote interno |
| 1 | `contract`, `sandbox`, `metrics`, `learnings` | Camada 0 |
| 2 | `plan`, `policy` | `contract`, `fsx` |
| 3 | `audit`, `gates`, `verify` | `plan`, `contract`, `fsx`, `jsonschema` |
| 4 | `decider` | `verify`, `plan`, `contract` |
| 5 | `run`, `work` | `decider`, `verify`, `gates`, `policy`, `plan`, `sandbox`, `metrics`, `learnings`, `queue` |
| 6 | `batch` | `run`, `work`, `verify`, `sandbox`, `plan` |

Os pacotes da mesma camada são independentes entre si. As camadas 3 e 5 permitem trabalho em paralelo.

## 6. O que adotar do `go.md`

O `go.md` descreve uma stack para serviços web. Aplique só o que serve a um CLI.

| Prática do `go.md` | Decisão |
|---|---|
| Go 1.27, `go` e `toolchain` no `go.mod` | Aplicar |
| Layout `cmd/` e `internal/` | Aplicar |
| Injeção manual na raiz de composição | Aplicar |
| Erros com `%w` e erros sentinela | Aplicar |
| Configuração só por ambiente, lida uma vez | Aplicar sem biblioteca; use a biblioteca padrão |
| `gofmt`, `go vet` e `golangci-lint` | Aplicar, com `.golangci.yml` no formato v2 |
| `go test -race` e cobertura | Aplicar |
| `govulncheck` | Aplicar na CI |
| `gitleaks` no pre-commit e na CI | Aplicar |
| `lefthook` | Aplicar |
| Marca `//go:build integration` para testes lentos | Aplicar nos testes diferenciais |
| Jobs `quality`, `test` e `security` como checks obrigatórios | Aplicar |
| `.editorconfig` e `.gitignore` da stack | Aplicar; ignore só `/bin/pwn`, porque `bin/pwn.js` é rastreado |
| Arquivo `Makefile` com alvo `check` | Aplicar; o alvo espelha o `bun run check` |
| Regra de ingresso: todo pedido passa pelo pwn | Aplicar (seção 10) |
| Compilação estática com `CGO_ENABLED=0` | Aplicar |
| `goreleaser` para binários de release | Aplicar no corte |
| `vendor/` | Aplicar só se uma dependência entrar |
| UUIDv7 para IDs | Aplicar com o pacote `uuid` da biblioteca padrão do Go 1.27 (`uuid.NewV7()`). Não use `github.com/google/uuid`. O pwn atual não usa UUID, então nenhum código portado precisa dele. Os IDs de execução seguem `RUN-<base36>-<hex>` |
| `net/http` como servidor, templates, hot reload | Não aplicar |
| SQLite, sqlc, ORM e migrations | Não aplicar; o pwn não usa banco |
| `go-playground/validator` | Não aplicar; o validador de schema cobre a borda |
| Sessão, CSRF, observabilidade, health check | Não aplicar |
| Contêiner, Compose e Kubernetes | Não aplicar |

## 7. Dependências

O binário Go não tem dependência externa. Use só a biblioteca padrão.

| Necessidade | Decisão | Motivo |
|---|---|---|
| Validar Draft-07 | Validador próprio em `platform/jsonschema` | Veja a seção 7.1 |
| Leitura de argumentos | Código próprio | O pwn tem sintaxe própria, com separador `--` |
| Glob | Código próprio | O comportamento precisa ser idêntico ao de `glob-utils.ts` |
| Cliente HTTP do decisor | `net/http` | Chamada síncrona e tempo limite nativos |
| Testes | Pacote `testing` | Sem dependência de asserção |
| Identificador UUID, se surgir a necessidade | Pacote `uuid` da biblioteca padrão | O Go 1.27 inclui `uuid.NewV7()`. Dispensa `google/uuid` |

### 7.1 Por que um validador próprio

Os schemas usam 17 palavras-chave: `type`, `properties`, `required`, `items`, `additionalProperties`, `enum`, `pattern`, `minLength`, `maxLength`, `minItems`, `maxItems`, `minimum`, `maximum`, `minProperties`, `oneOf`, `$ref` local e `format`.

O Ajv do pwn atual não valida `format`. A opção `formats: { 'date-time': true }` desliga a checagem. Um teste com `santhosh-tekuri/jsonschema` v6.0.3 mostrou o contrário. A biblioteca rejeita uma data inválida que o Ajv aceita. A mensagem também difere. A biblioteca exige ainda `golang.org/x/text`.

Um validador próprio resolve os três pontos. Ele copia a semântica e a mensagem do Ajv e ignora `format`. Os 30 padrões `pattern` dos schemas não usam construção fora do RE2 (motor de expressão regular de Go). Um conjunto de conformidade, gerado pelo Ajv a partir dos schemas reais, prova a paridade.

## 8. Fases

A ordem das fases segue as camadas da seção 5.3. Cada fase lista as entregas, o critério de saída e a estimativa.

| Fase | Tema | Linhas TS de módulos | Dias |
|---|---|---|---|
| 0 | Referência de comportamento | 0 | 2 a 3 |
| 1 | Fundação | 639 | 4 a 5 |
| 2 | Plano, contrato e política | 3.149 | 7 a 9 |
| 3 | Verificador independente | 1.496 | 4 a 5 |
| 4 | Portões e auditoria | 3.034 | 7 a 9 |
| 5 | Decisor | 933 | 2 a 3 |
| 6 | Execução e isolamento | 1.947 | 5 a 6 |
| 7 | Work e lote | 3.455 | 9 a 11 |
| 8 | Targets e corte | 332 | 3 a 4 |
| | **Total** | **14.985** | **43 a 55** |

As 2.200 linhas de `commands/*` e `cli` somam-se às fases. A estimativa assume 310 a 400 linhas de referência por dia. Essa taxa inclui testes, paridade e o ciclo de governança. [INFERÊNCIA] A taxa não foi medida. Meça na Fase 1 e reestime.

### Fase 0 — Referência de comportamento

**Entrega:**

- Congele o commit `c81a18b` como referência.
- Execute `bun run check` e guarde a saída.
- Crie `testdata/parity/` com repositórios temporários e cenários.
- Gere vetores de referência para JSON canônico, hashes, HMAC, assinaturas, recibos e markdown.
- Gere o conjunto de conformidade do validador a partir do Ajv.
- Crie o executor diferencial. Ele roda o pwn atual e o pwn Go no mesmo cenário.
- Prove que o pwn TypeScript roda dentro do sandbox do verificador.
- Redija o DEC que substitui o DEC-005 (decisão D9).

**Saída:** o executor reproduz o comportamento atual. Todos os vetores são estáveis. O operador decide D9.

### Fase 1 — Fundação

**Entrega:**

- Crie `go.mod` com o caminho `github.com/passoz/pwn`, `go 1.27` e `toolchain go1.27.1`.
- Implemente o despacho, as opções globais, a ajuda, a versão e os códigos de saída.
- Preserve o separador `--` e o limite das opções globais.
- Implemente `config`, `jsonx`, `cryptox`, `jsonschema`, `glob`, `fsx` e `proc`.
- Mantenha a trava `mkdir` e a escrita atômica do pwn atual.
- Embuta os schemas e o arquivo `VERSION`. Reproduza a checagem de divergência das leis.
- Faça `validate` e `self-check` passarem.
- Crie `Makefile`, `.golangci.yml`, `.editorconfig`, `lefthook.yml` e a CI.
- Configure o projeto no verificador (seção 10.2).

**Saída:** o executor diferencial passa nos comandos da fundação. Os vetores de JSON e de cripto batem byte a byte. O conjunto de conformidade do validador passa.

### Fase 2 — Plano, contrato e política

**Entrega:**

- Porte o modelo, o analisador e o gerador do plano.
- Porte a amarração da aceitação e o analisador de comandos.
- Porte a validação de plano e de prompt.
- Porte o contrato V4, o cálculo de risco e o Diff Guard.
- Porte a política declarativa e o motor de política.
- Porte `work plan`, `work contract`, `work specify` e `task capsule`.

**Saída:** o markdown do plano é idêntico byte a byte. O Diff Guard e o motor de política têm paridade nos cenários adversariais.

### Fase 3 — Verificador independente

**Entrega:**

- Porte a raiz protegida, as chaves Ed25519 e a impressão digital da chave.
- Porte a aprovação imutável, o instantâneo e o `bwrap` do verificador.
- Porte o recibo assinado e o fluxo de aceitação automática.
- Porte `verify init`, `approve`, `run`, `run-all`, `status` e `show`.
- Aceite só `--by` em `verify approve`. A Fase 5 liga o decisor.

**Saída:** cada binário valida o recibo do outro. A chave privada fica fora do sandbox. O verificador recusa recibo e aprovação adulterados.

### Fase 4 — Portões e auditoria

**Entrega:**

- Porte os 5 portões, o cache HMAC e o mutation testing.
- Porte `baseline`, `red`, `green`, `check` e `verify` do audit.
- Porte `work gate`, `work audit` e `self-check --mutate`.
- Leia a versão do arquivo `VERSION` embutido. A versão entra no payload assinado.

**Saída:** os vereditos e as assinaturas dos portões batem com a mesma versão de harness e o mesmo hash de leis. O audit recusa um AC vácuo.

### Fase 5 — Decisor

**Entrega:**

- Porte a configuração, as políticas, o adaptador HTTP e o registro de decisões.
- Use `net/http` síncrono. O processo auxiliar do pwn atual deixa de existir.
- Porte `init` e `decider show|set|remove|log`.
- Ligue o decisor a `verify approve` sem `--by`.

**Saída:** o decisor falha fechado sem chave, sem rede ou com resposta inválida. O `init` não trava sem terminal. A chave nunca vai para disco.

### Fase 6 — Execução e isolamento

**Entrega:**

- Porte o sandbox de worktree (árvore de trabalho do git) e o `bwrap`.
- Porte a Tool API (interface de programação de aplicações), o roteador e o orquestrador de execução.
- Porte a fila AFK, as métricas e os aprendizados.
- Porte `work run`, `work run-all`, `task run`, `queue` e `metrics`.
- Ligue a aceitação automática depois da execução com `--task`.
- Cubra Diff Guard, travessia de caminho, link simbólico e processos netos.

**Saída:** as execuções isoladas têm paridade. O tempo limite mata o grupo inteiro. Nenhum processo neto sobrevive. O Diff Guard bloqueia escrita fora do escopo. A fila humana devolve o código 3. O sandbox some depois de um sinal de interrupção.

### Fase 7 — Work e lote

**Entrega:**

- Porte os artefatos, o manifesto, o status e a sincronização do Work.
- Porte `scaffold`, `reconcile` e `import`, com a classificação de risco automática.
- Porte os lotes paralelos: `plan`, `prepare`, `integrate`, `rebase` e `abort`.
- Porte `work init`, `import`, `scaffold`, `reconcile`, `status`, `sync` e `batch`.

**Saída:** o scaffold gera a mesma cadeia de arquivos. O `reconcile` é idempotente. O lote recusa conflito e regressão como no pwn atual.

### Fase 8 — Targets e corte

**Entrega:**

- Porte a matriz de capacidades e os 3 materializadores.
- Porte `target list` e `target materialize`.
- Substitua DEC-005 em `spec.json` e `.specs/system.json` (decisão D9).
- Aponte o alvo `make build` para `bin/pwn`. Mantenha `bin/pwn.js` só na transição.
- Atualize README, `docs/MANUAL.md`, CI e scripts.
- Mova o código TypeScript para `legacy/` ou remova depois do tag.
- Rode a aceitação final em todos os Works.

**Saída:** o binário executa os 36 subcomandos. O pwn atual não é necessário em tempo de execução. A suíte Go, o `self-check`, o `validate` e o `verify run-all` passam.

## 9. Testes e aceitação

- O executor diferencial compara código de saída, saída normalizada e árvore de arquivos.
- Normalize carimbos de tempo, identificadores de execução e caminhos temporários.
- Marque os testes diferenciais com `//go:build integration`.
- Porte a cobertura das 41 suítes para testes Go por fase.
- Mantenha as suítes TypeScript como contrato externo até o corte.
- Cubra os testes de segurança:
  - Travessia de caminho e link simbólico
  - Diff Guard e chave fora do sandbox
  - Cache e recibo adulterados
  - Tempo limite e ausência de `bwrap`
- Use `go test -race ./...` na máquina local e na CI.
- Use `go test -count=1` na aceitação do sandbox, com `CGO_ENABLED=0`. O detector de corrida exige CGO.
- Use `-count=1` em todo critério de aceite. O cache de resultado do Go esconderia um AC vácuo.
- Use teste fuzz para glob, analisador de plano e JSON canônico.
- Exija 90% de cobertura nos pacotes críticos e 85% no total durante a reescrita.
- Exija 90% no total antes do corte. Este é o limite do `go.md`.
- Rode `pwn self-check --mutate` em cada Work da reescrita.
- Aceite final: um recibo do pwn atual e um recibo do pwn Go. Cada binário valida o recibo do outro.

Os pacotes críticos são `jsonx`, `jsonschema`, `gates`, `contract`, `policy`, `sandbox`, `verify` e `audit`.

## 10. Governança com o pwn atual

O pwn atual governa a reescrita. O pwn Go só entra depois do corte.

### 10.1 Fluxo

1. Registre o pedido da fase em `.prompts/NNNN-change.md`. Esta é a regra de ingresso do `go.md`.
2. Valide o pedido com `bun bin/pwn.js work specify`. O comando confere o pedido contra `.specs/system.json`.
3. Crie o Work da fase com `bun bin/pwn.js work scaffold --title "<fase>" --risk L3`.
4. Use um Work por fase, de `0002` a `0010`. O schema limita um Work a 40 tarefas.
5. Substitua o esqueleto pelos artefatos da fase. Detalhe discovery, requirements, PRD (documento de requisitos de produto), spec e plan.
6. Divida o trabalho em tarefas de até 3 arquivos de implementação, 3 critérios de aceite e 2 passos. O schema aceita 12 arquivos, mas o validador semântico recusa acima de 3.
7. Defina `write_allow` por tarefa. Negue `.pwn/**`, `.git/**`, `queue/**` e a raiz do verificador.
8. Use risco L3 nos pacotes críticos e congele os testes. Use L4 só quando a tarefa lê ou grava a chave privada do verificador.
9. Aprove cada tarefa com `pwn verify approve`.
10. Execute o ciclo da seção 10.2.
11. Rode `pwn work gate --all`, `pwn work status --coverage` e `pwn verify run-all`.
12. Marque `[x]` só depois de um recibo válido.

O agente não aprova. A aprovação é ato do operador ou do decisor configurado.

[INFERÊNCIA] A reescrita gera cerca de 45 a 60 tarefas. Cada tarefa exige uma aprovação. Configure o decisor com teto L3 para reduzir a fila do operador (decisão D11).

### 10.2 Ciclo TDD com Go

O audit exige que o RED mostre a asserção na saída. O mutation check restaura a implementação ao commit do baseline. Ele exige que a asserção falhe de novo.

Um arquivo novo é removido nessa restauração. O teste então falha na compilação e a saída não traz a asserção. O mutation check reprova.

Por isso cada tarefa segue esta ordem:

1. Commite um stub que compila. O stub tem as assinaturas e retorna valores errados.
2. Commite o teste. A mensagem de falha contém um identificador literal, por exemplo `SUM-001`.
3. Rode `audit baseline`. A árvore precisa estar limpa nos arquivos declarados.
4. Rode `audit red --expect "SUM-001"`.
5. Implemente e rode `audit green`.
6. Rode `audit check` para cada AC e para `REGRESSION`.

### 10.3 Regras de aceitação

- Cada critério de aceite usa `go test <pacote> -run <teste> -count=1`.
- Use `-tags=integration` nos testes diferenciais.
- O comando `go test ./...` fica nos portões globais. O gate rejeita a suíte inteira como critério de aceite.
- O texto de `--expect` é a asserção literal do teste.

### 10.4 Configuração do verificador para Go

A configuração atual do verificador não tem entrada para este projeto. O operador precisa adicionar:

```json
"/home/passoz/dev/pwn-pwngo": {
  "path_prepend": [
    "/home/passoz/.local/share/mise/installs/go/1.27.1/bin",
    "/home/passoz/.local/share/mise/installs/bun/1.4.2/bin"
  ],
  "mounts_ro": ["/home/passoz/.local/share/mise/installs/go"],
  "env": {
    "GOCACHE": "/tmp/gocache",
    "GOPROXY": "off",
    "GOTOOLCHAIN": "local",
    "CGO_ENABLED": "0",
    "GOFLAGS": "-mod=vendor",
    "GOLANGCI_LINT_CACHE": "/tmp/golangci"
  }
}
```

O diretório do Bun entra em `path_prepend` porque os testes diferenciais executam `bun src/cli.ts`. O `GOCACHE` e o `GOLANGCI_LINT_CACHE` ficam em `/tmp`, que o sandbox monta como `tmpfs` gravável. O conjunto de ferramentas Go fica somente leitura.

**Prova executada em 2026-10-28.** O teste usou a função `sandboxPolicy` real e o `bwrap`. Um módulo de brinquedo com uma dependência vendorizada rodou `go test`, `go vet` e `golangci-lint`. Os comandos `bun --version` e `git --version` também funcionaram. O DNS ficou bloqueado, como o sandbox exige.

**Não provado:** a execução do pwn TypeScript completo dentro do sandbox. A Fase 0 prova esse ponto.

## 11. Riscos

| Risco | Efeito | Mitigação |
|---|---|---|
| Diferença no JSON canônico | Recibo ou cache inválido | Vetores de referência e comparação byte a byte (seção 4.1) |
| Divergência do validador | Documento aceito ou recusado de forma diferente | Validador próprio e conjunto de conformidade do Ajv |
| Divergência no analisador do plano | Portão e audit divergem | Renderização byte a byte, ida e volta e teste fuzz |
| Fase depende de módulo posterior | Fase bloqueada | Ordem pelas camadas da seção 5.3 |
| Tarefa nova sem stub compilável | Mutation check reprova | Ciclo da seção 10.2 |
| Limites do schema do plano | Work recusado | Um Work por fase e tarefas pequenas |
| DEC-005 contradiz a reescrita | Governança bloqueia a mudança | Decisão D9 antes da Fase 1 |
| Dois binários tocam os mesmos artefatos | Corrida e corrupção | Trava `mkdir` compatível |
| Versão do harness diferente | Cache de portão recusado | Arquivo `VERSION` embutido, sem `ldflags` |
| Fila de aprovação cresce | Fluxo para | Decisor com teto L3 (D11) |
| Processo neto sobrevive ao tempo limite | Sandbox travado | Grupo de processos e teste com `sleep` |
| Go indisponível no sandbox | Aceitação bloqueada | Configuração provada na seção 10.4 |
| Remoção precoce do TypeScript | Perda da referência | Mover para `legacy/` até o corte |
| Estimativa baixa | Prazo estoura | Medir a taxa na Fase 1 e reestimar |
| Escopo cresce | Prazo e risco aumentam | Contrato de paridade e não objetivos |
| Windows e macOS | Comportamento diferente | Linux primeiro; falhar fechado em outro sistema |

## 12. Decisões para aprovação

| ID | Decisão | Recomendação |
|---|---|---|
| D1 | Caminho do módulo | `github.com/passoz/pwn` |
| D2 | Paridade do texto humano | Nível C; texto pode ter ajuste |
| D3 | Código TypeScript no corte | Mover para `legacy/` e manter por uma versão |
| D4 | Distribuição | `go install`, `goreleaser` e `make build` para `bin/pwn`; não commite binário |
| D5 | Versão | `0.2.0` no corte |
| D6 | Cobertura | 90% nos pacotes críticos; 85% no total; 90% no total antes do corte |
| D7 | Plataformas | Linux primeiro; outros sistemas falham fechado |
| D8 | Escopo do editor visual | Preservar sem reescrita |
| D9 | DEC-005 (`TypeScript sobre Bun`) | Substituir por novo DEC; a regra BR-006 exige decisão explícita do operador |
| D10 | Validador de schema | Próprio, sem dependência externa |
| D11 | Aprovação das tarefas | Decisor com teto L3; o operador aprova só L4 |

Se você aprovar, eu começo pela Fase 0 e crio o Work `0002`.

## 13. Definição de pronto

- O binário Go executa os 36 subcomandos.
- O executor diferencial passa em todos os cenários.
- O pwn atual e o pwn Go validam os recibos um do outro.
- `go test -race ./...` passa.
- `golangci-lint run` e `govulncheck ./...` não reportam erro.
- `pwn self-check`, `pwn validate` e `pwn self-check --mutate` passam.
- `pwn work gate --all` passa em cada Work da reescrita.
- Cada tarefa tem recibo válido.
- `spec.json` e `.specs/system.json` não têm mais a restrição DEC-005.
- A documentação e o README apontam para o binário Go.
- O código TypeScript está em `legacy/` ou o tag marca a remoção.

## 14. Primeiros passos após aprovação

1. Registre o DEC que substitui o DEC-005 e peça a decisão D9.
2. Crie `.prompts/0002-change.md` e valide com `work specify`.
3. Crie o Work `0002` com o scaffold.
4. Detalhe os artefatos e as tarefas da Fase 0.
5. Rode os cinco portões.
6. Peça a aprovação da primeira tarefa.
7. Implemente a Fase 0.

## 15. Registro da revisão

Esta seção lista cada achado da revisão 1 e a correção no plano.

| ID | Achado | Evidência | Correção |
|---|---|---|---|
| R1 | A ordem das fases contradizia as dependências | 12 importações apontavam para uma fase posterior. Exemplos: `decider` importa `verifier-home`; `v3-import` importa `decider`; `project_status` importa `verification-receipt` | Fases reordenadas pelas camadas (seção 5.3) |
| R2 | 7 módulos não tinham pacote | `batch` (775 linhas), `validate_prompt` (308), `router` (282), `acceptance-flow` (69), `manifest-sync` (52), `scope-overlap` (30), `entry-guard` (22) | Mapa completo na seção 5.2 |
| R3 | Os pacotes propostos tinham 2 ciclos | `contract` com `plan`; `run` com `sandbox`, `metrics` e `learnings`. A causa era `fs-lock` e `task-contract` | `fs-lock` vai para `platform/fsx`. `task-contract` vai para `plan`. O grafo corrigido não tem ciclo |
| R4 | O ciclo TDD falharia em código novo | `task_evidence.ts` exige a asserção na saída do mutation check. A restauração remove o arquivo novo. A compilação falha sem a asserção | Stub compilável antes do baseline (seção 10.2) |
| R5 | O plano de governança ignorava os limites do schema | `plan.schema.json`: 40 tarefas, 12 arquivos de implementação e 3 componentes por tarefa | Um Work por fase e tarefas pequenas (seção 10.1) |
| R6 | A reescrita contradiz uma decisão normativa | `spec.json` linha 366 e `.specs/system.json` linha 451: DEC-005 | Decisão D9 e tarefa na Fase 0 e na Fase 8 |
| R7 | A biblioteca de schema divergia do Ajv | Teste com `jsonschema` v6.0.3: rejeitou data inválida que o Ajv aceita. A mensagem difere. A biblioteca exige `golang.org/x/text` | Validador próprio (seção 7.1, D10) |
| R8 | A versão anterior dizia que a biblioteca cobria `date-time` | O Ajv usa `format: true`, que desliga a checagem | Texto corrigido na seção 7.1 |
| R9 | A versão anterior citava UUID como necessidade | `grep -i uuid src` retornou 0 ocorrências. O Go 1.27 tem o pacote `uuid` na biblioteca padrão, com `NewV7` | O `go.md` pede `google/uuid`. O plano usa o pacote padrão quando houver UUID. Atualize o `go.md` |
| R10 | O `go.md` tinha seções não lidas | Linhas 668 a 800 e 1129 a 1248 | Seção 6 refeita: `govulncheck`, marca `integration`, jobs da CI, regra de ingresso e configuração central |
| R11 | A regra "`harness` não importa `platform`" contradizia as portas só na fronteira | O mesmo plano pedia interface só em entrada e saída | Regras da seção 5.1 |
| R12 | O sandbox não tinha `bun` no `PATH` | O `PATH` do sandbox é `path_prepend` mais `/usr/bin:/bin` | Seção 10.4; prova com `bwrap` |
| R13 | O plano ignorava a trava entre processos | `fs-lock.ts` usa `mkdir`. Dois binários compartilham `.pwn/` | Trava `mkdir` mantida (seção 3.2) |
| R14 | A versão do harness entra no HMAC | `gate-cache.ts` lê `package.json` | Arquivo `VERSION` embutido (Fase 4) |
| R15 | A estimativa de 29 a 39 dias era baixa | A Fase 2 antiga tinha cerca de 9 mil linhas em 6 a 8 dias | 43 a 55 dias, com taxa declarada |
| R16 | O JSON de Go difere do `JSON.stringify` | Cinco diferenças (seção 4.1) | Vetores e decodificador próprio |
| R17 | O limite semântico do plano é menor que o schema | `work plan` recusou 6 arquivos de implementação, 4 ACs e 4 passos; o limite real é 3, 3 e 2 | Tarefas da Fase 0 divididas em 5; seções 3, 10.1 e 11 corrigidas |
