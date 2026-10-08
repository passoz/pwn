# Limites do PWN

Documento **honesto** sobre o que o harness `pwn` (v0.1.0) **não** garante.
Os gates são checagens estruturais determinísticas: tornam explícito o que foi
decidido e vinculado, mas não provam que a decisão está certa nem que o código faz o
que o requisito pretendia. Cada limite traz afirmação, evidência no código real e o
que usar em vez da garantia que não existe.

As referências `arquivo:linha` correspondem ao estado do repositório em 2026-10-08
(v0.1.0); se o arquivo mudar, localize pelo nome da função citada.

---

## 1. Gates validam presença, vínculo e forma da aceitação — não a intenção

**Afirmação.** Os cinco gates (`GATE-DISC-REQ`, `GATE-REQ-PRD`, `GATE-PRD-SPEC`,
`GATE-SPEC-PLAN`, `GATE-PLAN-CONTRACT`) verificam que os artefatos existem, que os IDs
se referenciam e que campos obrigatórios estão preenchidos. Nenhum lê o texto para
conferir se uma capability **implementa** a intenção do requisito que ela cita: a
rastreabilidade aceita qualquer ID não vazio — um ID fabricado passa — e a checagem de
existência casa por **substring do nome de arquivo**. Desde 2026-10-08 os gates também
conferem a **forma** da aceitação (AC/RED com comando focado, arquivos concretos,
contrato autorizando os ACs e testes congelados quando o risco é L3+), o que torna
`bun test` como AC e listas de arquivos diretório/glob violações `high` — mas forma não
é intenção: um AC focado e autorizado ainda pode medir a coisa errada.

**Evidência.** `src/core/gates.ts:887` (`validatePlanAcceptance`: comando de AC/RED
vazio ou genérico, arquivos ausentes/não concretos). `src/core/gates.ts:981`
(`validateContractSemantics`: contrato ausente/ilegível, escopo/budget/risco, AC fora de
`acceptance_contract.commands`, `frozen_tests` exigidos por risco e exercitados por
algum AC). `src/core/gates.ts:751` e `:802` (semântica do PRD e cobertura de
requisitos). O uso de IDs continua estrutural: `validateTraceability` (`gates.ts:122`)
aceita qualquer ID não vazio nem `PLACEHOLDER-<campo>`, e a existência do artefato é
`files.some(f => f.includes(artifactId) || ...)` (`gates.ts:177`).

**Em vez disso.** Use revisão humana e testes de aceitação escritos fora do loop de
implementação (congele-os; ver seção 4). O gate garante que a cadeia DISC → REQ → PRD →
CAP → TASK → CONTRACT → EVIDENCE está amarrada e que a aceitação é *executável e
específica* — não que ela é verdadeira.

## 2. Um gate segue decorativo (medido, não suposto)

**Afirmação.** Quatro das cinco mutações canônicas de `pwn self-check --mutate`
**agora bloqueiam** — `mut-missing-ac` e `mut-missing-contract` passaram a
`expect_blocked: true` com a validação semântica do plano/contrato dentro dos gates. A
quinta continua advisory: remover `rules` de todas as capabilities deixa `GATE-PRD-SPEC`
em `severity: 'medium'` → `pass_with_notes`. Resultado medido: `4/5 mutações
detectadas`. Um gate `pass_with_notes` com findings `medium`/`low` **não** bloqueia a
execução.

**Evidência.** `src/core/self_check_mutate.ts:201` (`mutationCases`) e `:327`
(`runMutations`); `src/commands/validate.ts` (`handleMutationCheck`). Só
`critical`/`high` com `status: 'open'` bloqueiam, e capability sem rules é
`severity: 'medium'` (`validateSpecCoversPRD` em `src/core/gates.ts:838`).

**Em vez disso.** Rode `pwn self-check --mutate` após mexer em gates e trate cada
`NÃO DETECTADO` como dívida: endureça o gate ou declare o caso `advisory` com
justificativa. Mutações advisory aparecem no relatório mas **não** afetam o exit code.

## 2b. A aceitação é forma; a chave do verificador mora no repositório

**Afirmação.** `pwn work audit` compara o comando digitado pelo operador com o comando
declarado no plano (`src/core/acceptance.ts:136`, `commandMatches`), recusa `--expect`
genérico ou não literal no teste do contrato v3 (`acceptance.ts:224`) e roda cada AC
também **sem a implementação** para recusar critério vácuo (`task_evidence.ts:927`).
Nada disso julga o *conteúdo* da asserção: um AC focado, autorizado pelo contrato e que
falha sem a implementação ainda pode afirmar a coisa errada (ver seção 4). E a chave que
assina atestações e evidências de gate nasce em `.pwn/.verifier_key` **dentro do
repositório** quando `PWN_VERIFIER_KEY` não está definida: quem pode versionar o estado
pode assinar o que quiser, e o `status` não distingue "assinado pelo operador" de
"assinado pelo repositório".

**Evidência.** `src/core/gate-cache.ts` (`getVerifierKey` cria a chave em
`.pwn/.verifier_key`; `readVerifierKey` só lê), `src/core/task_evidence.ts:995`
(`candidate` assina) e `:1169`/`:1219` (`verifyTaskAttestation`/`verifyGlobalGates`
conferem); `src/core/task_evidence.ts` (`run` remove `PWN_VERIFIER_KEY` do ambiente
dos comandos auditados). **Em vez disso.** Uma chave externa sozinha **não** garante
proteção contra repositório hostil: a chave default continua acessível, e `candidate`
consome estado, logs e cadeia fornecidos pelo repositório. A assinatura não prova
independentemente que o histórico foi executado. Para atravessar essa fronteira,
exija execução e verificação em contexto confiável, segredo fora do alcance do código
auditado e evidência produzida pelo verificador. Estas correções **não implementam**
essa fronteira de confiança.

## 3. O diff guard valida caminho, não conteúdo

**Afirmação.** O contrato de escopo protege contra escrita **fora** de `write_allow` e
dentro de `write_deny`. Escrever a implementação errada — `return null`,
`process.exit(0)`, teste vazio — dentro do caminho permitido não é detectado: não há
análise de conteúdo no diff guard.

**Evidência.** `src/core/contract-guard.ts:16-80` (`checkFileAgainstScope`,
`checkDiffAgainstContract`): a decisão é `minimatch(normalizedPath, pattern)`
(`:34` e `:47`; implementação em `src/core/glob-utils.ts`), sem leitura de bytes
do arquivo.

**Limite adicional — o guard só vê o que o `git status` do repositório reporta.** O
inventário vem de `git status --porcelain=v1 -z` **no repositório cuja identidade foi
fixada na criação do sandbox** (apagar o `.git` ou rodar `git init` dentro dele faz o
guard recusar o inventário em vez de descrever outra árvore). Restam dois buracos
conhecidos: (a) caminhos cobertos pelo `.gitignore` do repositório **não** aparecem —
é o caso de `.env`, que o contrato default põe em `write_deny`; (b) um comando que faça
`git commit` ou `git stash` dentro do sandbox move a base de comparação e some com as
próprias escritas. **Evidência.** `src/core/run-orchestrator.ts` (`modifiedFiles`),
`src/core/contract-engine.ts:144` (`.env*` no deny default).

**Nota — a working tree não commitada agora conta.** `work run` leva para o sandbox o
diff rastreado contra `HEAD` e os arquivos novos não ignorados
(`src/core/run-orchestrator.ts:238`, `overlayWorkingTree`), exceto `.pwn`, `.todo`,
`.work`, `queue/review` e os artefatos que o harness injeta. Consequência prática: o
comando de aceitação valida o **seu código não commitado** (não o HEAD), e qualquer
arquivo sujo fora do `write_allow` — inclusive um rascunho seu no repo — reprova o run
com `DIFF VIOLATION`. Commite ou isole o que não pertence à task.

**Em vez disso.** Combine o contrato com evidência de teste (seção 4) e revisão de
`git diff` antes do merge. Escopo é contenção de dano, não correção. E não leia
"DIFF OK" como prova de contenção: confira `git status`, `git log` e os arquivos
ignorados do worktree.

## 4. A auditoria TDD prova a asserção declarada — não que ela é suficiente

**Afirmação.** O mutation check continua forte: ele **restaura os arquivos de
implementação ao commit do baseline** (`baseline_commit`) e exige que o teste falhe —
prova que a asserção depende da implementação. Desde 2026-10-08 o texto de `--expect`
precisa ser **não-genérico** e estar **literalmente no arquivo de teste** (contrato v3),
e cada AC precisa falhar sem a implementação (senão o check é recusado como vácuo) —
mas nada disso julga o *conteúdo* da asserção: a comparação de saída continua sendo
**substring**, e quem escreve o teste é quem escreve o código. Um teste honesto e
focado que afirma só `sum(1, 1) === 2` atesta uma implementação que ignora o resto
(demonstrado no repro de aceitação, seção 8). O congelamento
(`bun bin/pwn.js work contract --freeze-tests`) grava os hashes no contrato e o audit
recusa baseline/candidate se algum arquivo congelado mudar — exigido a partir de L3.
Isso protege a **imutabilidade** dos testes, não a suficiência de seu conteúdo.

**Evidência.** `src/core/task_evidence.ts:546` (`withoutImplementation`), `:778`
(`red`: `literalInTests`, `genericExpectReason`) e `:927` (`auditCheck`: probe de
vacuidade para `AC-*`); `src/core/acceptance.ts:224` (`genericExpectReason`), `:232`
(`placeholderPathReason`) e `:440` (`allowedCheckCommands`); `src/core/task-contract.ts:54`
(`freezeAcceptanceTests`); `src/core/gates.ts:981` (frozen exigido/exercitado em risco
L3+). GREEN e VERIFY exigem exit code `0` e o `expect` de sucesso quando declarado;
não inferem falha só porque `redExpect` aparece na saída bem-sucedida. O mutation
check continua exigindo que a asserção falhe ao restaurar a implementação ao baseline.

**Em vez disso.** Escreva e **congele** os testes de aceitação antes da implementação
(L3+ obriga; faça em L2 também), use texto de `--expect` específico do caso, prefira
runners com saída estruturada e revise o log gravado. O audit garante causalidade da
asserção declarada — a suficiência dela é revisão humana.

**Limite adicional — o veredicto ainda é do repositório.** A cadeia
`.todo/evidence/<work>/<task>-chain.jsonl` é SHA-256 **sem chave** sobre campos
públicos, e o estado carrega `green_*`/`baseline_*` que o próprio audit confere contra
si mesmo (agora também contra o commit do baseline). Um repositório hostil pode
versionar estado, logs, cadeia e `audit_checks` coerentes entre si, plantar o comando
que sabe ser usado e obter `candidate` com `result: "pass"` sem nunca ter rodado
RED/GREEN. O que mudou: a atestação v3 é **assinada** e amarrada à definição da task
(digest do bloco do plano + contrato), então ela agora é consumida e detecta alteração
*posterior* (`status` marca `stale`); e a chave default mora no próprio repositório
(seção 2b).
**Evidência.** `src/core/task_evidence.ts:454` (`verifyEvidenceChain`, `GENESIS_HASH`),
`:995` (`candidate`) e `:1169` (`verifyTaskAttestation`, consumido por
`src/core/project_status.ts:151`).
**Em vez disso.** Trate `.todo/attestations/**` como alegação do repositório, não como
prova independente. Uma chave externa (`PWN_VERIFIER_KEY`) sozinha não basta: aplique
a fronteira de execução/verificação confiável descrita na seção 2b.

## 5. Sandbox: isolamento de árvore sempre, de SO só quando há `bwrap`

**Afirmação.** O sandbox cria um `git worktree` em branch próprio e **sempre** isola a
árvore de arquivos do checkout. O isolamento de SO é **condicional**: quando o host tem
`bwrap` (Bubblewrap), o comando roda em namespaces próprios com o sistema de arquivos
inteiro montado somente-leitura, apenas o `cwd` gravável, `/tmp` em tmpfs e rede
desligada (`--unshare-net`). **Sem `bwrap`** (macOS, Windows, contêiner sem user
namespaces, ou `--no-isolation`), o comando roda com o usuário do operador, sem
namespace algum: pode escrever fora do worktree e acessar a rede.

**Evidência.** `src/core/sandbox.ts:19-40` (`createGitWorktreeSandbox`), `:113-153`
(`wrapWithBwrap`); a seleção é silenciosa em `src/core/tool-api.ts:401`
(`isBwrapSupported()`). O escape por subprocesso é **registrado** como documentário em
`tests/security-adv.test.ts:383-407`:
`// The test is DOCUMENTARY — it records whether subprocess escape is possible.`

**Em vez disso.** Para código não confiável, garanta `bwrap` presente (ou rode em
container/VM: Docker, gVisor, firecracker) e trate `--no-isolation` como execução sem
contenção nenhuma. Aqui o sandbox evita sujar o Work; não contém um adversário.

**Limite adicional — o harness abre uma escrita para o host.** `prepareSandbox` cria
`node_modules` dentro do sandbox como **symlink para o `node_modules` do projeto
real**; escrever por esse link atinge a árvore real enquanto o worktree é descartado.
Com `bwrap` ativo a escrita é recusada pelo mount somente-leitura; **sem** `bwrap` (ou
com `--no-isolation`) o comando escreve dentro do `node_modules` real — e o diff guard
não tem como ver isso, porque a mudança acontece fora do repositório que ele
inspeciona. O guard desconsidera o link apenas enquanto a assinatura registrada por
`prepareSandbox` continuar batendo; substituí-lo devolve o caminho ao inventário, mas
**escrever através** dele continua invisível. **Evidência.**
`src/core/run-orchestrator.ts` (`prepareSandbox`, `pathFingerprint`, `modifiedFiles`).

## 6. O sandbox limita escrita, não leitura: o host inteiro é legível

**Afirmação.** Sob `bwrap`, o sistema de arquivos do host é montado **somente-leitura e
por inteiro** (`--ro-bind / /`): o comando executado **lê** qualquer arquivo que o
usuário do operador possa ler — `~/.config/gh` (token do GitHub CLI), `~/.config/*`
(perfis de navegador, opencode), `~/.gnupg` (`private-keys-v1.d`), `~/.docker`,
`~/.kube`, `~/.netrc`, `~/.gitconfig` — além de herdar o ambiente do operador
(`GITHUB_TOKEN`, `OPENAI_API_KEY`, `AWS_*`, `SSH_AUTH_SOCK`). Só `~/.ssh` e `~/.aws`
são mascarados (tmpfs vazio). Ler não é impedido pelo isolamento de escrita.

**Evidência.** `src/core/sandbox.ts:114-134` (bind global + lista `sensitiveDirs` com
apenas `~/.ssh` e `~/.aws`) e `src/core/tool-api.ts:389-397` (`env: { ...process.env }`,
removendo somente `PWN_VERIFIER_KEY`). O `PolicyEngine` aprova toda leitura
(`evaluateFileRead` em `src/core/policy-engine.ts` devolve `allowed: true` sem consultar
a allowlist).

**Em vez disso.** Rode o executor com um usuário separado, HOME dedicado e ambiente
explicitamente reduzido; nunca execute em sandbox código que você não executaria
diretamente, e trate qualquer credencial exportada no seu shell como legível pelo
comando do agente.

## 7. Não existe verificação de qualidade do código produzido

**Afirmação.** O harness não compila, não roda linter estático nem avalia
complexidade, segurança ou desempenho do **código** produzido: não há análise de
conteúdo — o diff guard olha caminho (seção 3) e a auditoria olha comandos, snapshots e
asserções declaradas (seções 2b e 4). O que existe é semântica sobre o **plano**: os
gates agora recusam AC/RED genérico, arquivo não concreto, AC que o contrato não
autoriza e risco L3+ sem teste congelado (`validatePlanAcceptance`,
`validateContractSemantics`), e o `pwn validate` do markdown repete as mesmas regras —
mas isso valida a *forma da aceitação*, não o código nem a intenção do requisito.

**Evidência.** `src/core/task_evidence.ts:995` (`candidate`): confere que os checks do
plano (`requiredAuditChecks` em `src/core/acceptance.ts:430`) foram registrados com os
comandos do plano, sobre o snapshot do GREEN, e assina; `verify`
(`src/core/task_evidence.ts` `verify`) re-executa o comando e confere exit code 0 e a
saída. Nada lê o conteúdo da implementação.

**Em vez disso.** Coloque `tsc --noEmit`, linter e testes de mutação no comando de
verificação do contrato e no template do alvo; revise o diff.

## 8. `pwn validate` valida schema, não a verdade do conteúdo

**Afirmação.** A validação é JSON Schema (Ajv): tipos, campos obrigatórios, formatos.
Um `prd.json` sintaticamente perfeito com requisitos inventados é "VÁLIDO". Dentro de
um Work só `prd.json`, `plan.json` e `evidence.json` têm schema; `discovery.json`,
`requirements.json`, `spec.json` e `traceability-matrix.json` não têm
(`schemas/` não os define), e documento sem `$schema` declarado passa apenas por "o
JSON parseia".

**Evidência.** `src/core/validator.ts:44-70` (`validateNormativeDocument`, com
fallback `return { valid: true, ... }`) e `:72-100` (`validateWorkDocuments`, mapa
explícito de três documentos); Ajv em `src/core/validator.ts:9`.

**Em vez disso.** Leia "VÁLIDO (conforme schema)" como "bem formado, não revisado"; o
conteúdo depende dos gates (seções 1-2) e de revisão humana.

## 9. Evidência prova execução da asserção declarada; o self-check tem escopo curto

**Afirmação.** A antiga checagem por heurística de nome em `evidence/`
(`FIND-SEM-EVD-*`) foi removida: ninguém escrevia nesse diretório (o audit grava em
`.todo/evidence/<work>/`), e a prova de execução passou a ser a **atestação v3
assinada** — `status` só conta uma task como concluída com a assinatura válida e os
arquivos atestados inalterados (`stale`), e os gates globais só passam com evidência
assinada de `pwn work audit gate` (comando, log e árvore das tasks conferidos). O que
isso **não** prova: que a asserção exercita o requisito (seção 4) nem que o
implementador não plantou evidência coerente (seção 4, limite adicional). E o
`pwn self-check --mutate` segue rodando 5 mutações estruturais sobre uma **cópia
temporária**: não cobre mutações de conteúdo, combinações de violações nem gates fora
de `mutationCases()`.

**Evidência.** `src/core/project_status.ts:151` (`evidenceFor`, estágio `ACCEPTED`) e
`:232` (`globalGates` + `verifyGlobalGates`); `src/core/task_evidence.ts:454`
(cadeia), `:927` (checks sobre o snapshot do GREEN, com probe de vacuidade) e `:995`
(atestacão assinada). `src/core/self_check_mutate.ts:201` para o escopo das mutações.

**Registro de correções (2026-10-08).** O drift entre Markdown e `plan.json` é validado
em todas as fases do audit, na leitura das atestações e dos gates globais; `plan.json`
existente ilegível é recusado. O `status` marca `INVALID PLAN` mesmo sem evidência.
O ID e o SHA-256 do contrato atual são conferidos, invalidando aceitação anterior
após alteração. GREEN/VERIFY usam exit `0` e `expect` de sucesso quando declarado,
sem heurística de ausência de `redExpect`; o mutation check mantém a falha no baseline.
Os comandos auditados não herdam `PWN_VERIFIER_KEY`. Essas correções não garantem
suficiência dos testes, código completo/correto nem proteção contra árvore hostil.

**Em vez disso.** Marque `[x]` só depois do `candidate` (o `status` acusa
`INCONSISTENT STATE` quando o marcador e a atestação discordam) e rode
`pwn work audit gate` para cada item de `## Global gates` ao fim do Work; ao endurecer
um gate, mude o caso correspondente para `expect_blocked: true` — essa mudança é o
registro de que o gate deixou de ser decorativo.
