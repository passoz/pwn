# Limites do PWN

Documento **honesto** sobre o que o harness `pwn` (v0.1.0) **não** garante.
Os gates são checagens estruturais determinísticas: tornam explícito o que foi
decidido e vinculado, mas não provam que a decisão está certa nem que o código faz o
que o requisito pretendia. Cada limite traz afirmação, evidência no código real e o
que usar em vez da garantia que não existe.

As referências `arquivo:linha` correspondem ao estado do repositório em 2026-09-23
(v0.1.0); se o arquivo mudar, localize pelo nome da função citada.

---

## 1. Gates validam presença e vínculo de ID — não a intenção

**Afirmação.** Os cinco gates (`GATE-DISC-REQ`, `GATE-REQ-PRD`, `GATE-PRD-SPEC`,
`GATE-SPEC-PLAN`, `GATE-PLAN-CONTRACT`) verificam que os artefatos existem, que os IDs
se referenciam e que campos obrigatórios estão preenchidos. Nenhum lê o texto para
conferir se uma capability **implementa** a intenção do requisito que ela cita, e a
rastreabilidade aceita qualquer ID não vazio: um ID fabricado passa, e a checagem de
existência casa por **substring do nome de arquivo**.

**Evidência.** `src/core/gates.ts:411-500` (`evaluateGatePrdSpec`): a única checagem
por capability é `if (!cap.rules || cap.rules.length === 0)` — qualquer string serve
como regra. `src/core/gates.ts:512-603` (`evaluateGateSpecPlan`) só confere que
`plan.json` tem tasks e que `spec_reference` existe em `spec.json`. Um ID é aceito se
não for vazio nem `PLACEHOLDER-<campo>` (`src/core/gates.ts:122`, `validateTraceability`),
e `validateFullTraceability` considera que o artefato existe quando
`files.some(f => f.includes(artifactId) || ...)` (`src/core/gates.ts:177`).

**Em vez disso.** Use revisão humana e testes de aceitação derivados do requisito. O
gate garante que a cadeia DISC → REQ → PRD → CAP → TASK → CONTRACT → EVIDENCE está
amarrada — não que ela é verdadeira.

## 2. Alguns gates são decorativos (medido, não suposto)

**Afirmação.** Nem toda violação bloqueia. Das cinco mutações canônicas de
`pwn self-check --mutate`, três **não** produzem `blocked` no repo atual: remover
`acceptance_criteria` das tasks (`GATE-SPEC-PLAN` não olha esse campo), apontar
`contract_id` para contrato inexistente (`GATE-PLAN-CONTRACT` só checa presença) e
remover `rules` de todas as capabilities (`GATE-PRD-SPEC` emite finding `medium`,
advisory → `pass_with_notes`). Resultado medido: `2/5 mutações detectadas`.

**Evidência.** `src/core/self_check_mutate.ts` (`mutationCases`, `runMutations`) e
`src/commands/validate.ts` (`handleMutationCheck`). Só `critical`/`high` com
`status: 'open'` bloqueiam (`hasCriticalOrHigh` em `src/core/gates.ts:287,392,493,593,674`),
e capability sem rules é `severity: 'medium'` (`src/core/gates.ts:444`).

**Em vez disso.** Rode `pwn self-check --mutate` após mexer em gates e trate cada
`NÃO DETECTADO` como dívida: endureça o gate ou declare o caso `advisory` com
justificativa. Mutações advisory aparecem no relatório mas **não** afetam o exit code.

**Limite adicional — a chave do cache de veredictos é incompleta.** `GATE-DISC-REQ` e
`GATE-REQ-PRD` leem `traceability-matrix.json` (`validateTraceability`) e podem bloquear
por causa dele, mas esse arquivo **não** entra em `input_versions` — que é o que a chave
do cache usa. Resultado: um PASS assinado continua sendo servido depois de a matriz ser
esvaziada, e o gate imprime `PASS (cache)` com exit `0` sobre um estado que a avaliação
fresca bloquearia. **Evidência.** `src/core/gates.ts:280-283` e `:385-388` (leitura) vs.
`:293` e `:398` (chave); consumo em `src/commands/work.ts:104-106` (`cached ?? fresh`);
validação do envelope em `src/core/gate-cache.ts`. O `GATE-PLAN-CONTRACT` **inclui** o
arquivo (`src/core/gates.ts:680`) — a assimetria é o próprio sinal do defeito.
**Em vez disso.** Rode `pwn work gate --no-cache` antes de confiar num PASS (ou
`--clear-cache`, que apaga os envelopes).

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

**Em vez disso.** Combine o contrato com evidência de teste (seção 4) e revisão de
`git diff` antes do merge. Escopo é contenção de dano, não correção. E não leia
"DIFF OK" como prova de contenção: confira `git status`, `git log` e os arquivos
ignorados do worktree.

## 4. A auditoria TDD prova causalidade, mas `--expect` é substring

**Afirmação.** O mutation check é forte: ele remove o diff de implementação e exige
que o teste falhe — isso prova que o teste depende da implementação. Mas a "falha
esperada" é comparada por **substring na saída**; qualquer log contendo o texto serve.
`--expect-literal` endurece apenas isso: exige que `--expect` apareça **literalmente**
em algum arquivo de teste congelado — não que o texto seja uma asserção.

**Evidência.** `src/core/task_evidence.ts:490` (`mutationCheck`:
`!mutationResult.output.includes(expect)`), `:546` e `:591` (RED/GREEN com
`output.includes`), `:538-543` (`literalInTests` com `--expect-literal`).
`assertionRan = !result.output.includes(redExpect)` (`:642`) trata a asserção como
"não executada" só quando o texto de falha reaparece — um teste silencioso passa.

**Em vez disso.** Use texto de `--expect` específico do caso (nunca genérico como
`"Error"`), prefira runners com saída estruturada e revise o log gravado.

**Limite adicional — a evidência é auto-atestada pelo repositório.** O comando
executado é sempre o do operador (ver `docs/MANUAL.md`), mas o *veredicto* ainda vem
de artefatos versionados: a cadeia `.todo/evidence/<work>/<task>-chain.jsonl` é SHA-256
**sem chave** sobre campos públicos, e o estado carrega `green_*`/`baseline_*` que o
próprio audit confere contra si mesmo. Um repositório hostil pode versionar estado,
logs, cadeia e `audit_checks` coerentes entre si e obter `candidate` com
`result: "pass"` sem nunca ter rodado RED/GREEN — a única barreira restante é o
comando do operador ter de coincidir com o `red_command` plantado (basta plantar o
comando que o repositório sabe que será usado, ex.: `bun test`).
**Evidência.** `src/core/task_evidence.ts:372-401` (`verifyEvidenceChain`, `GENESIS_HASH`),
`:707-758` (`candidate`). Nada em `src/` consome atestações hoje.
**Em vez disso.** Trate `.todo/attestations/**` como alegação do repositório, não como
prova independente; assine a evidência com uma chave fora da árvore versionada
(`PWN_VERIFIER_KEY`) se precisar de garantia contra um repositório hostil.

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

## 7. Não existe verificação de qualidade semântica de código

**Afirmação.** O harness não compila, não roda linter estático nem avalia
complexidade, segurança ou desempenho do código produzido. Ele registra que comandos
rodaram e que produziram a saída esperada — e o que conta como "esperado" é declarado
no próprio plano.

**Evidência.** `src/core/task_evidence.ts:611-651` (`verify`) re-executa o comando e
confere exit code 0 e ausência do texto de falha; a lista de checagens vem do texto
do plano (`taskAuditRequirements`, `:687-705`, que conta ACs por regex em `**ACs:**` e
lê `**Visual:** REQUIRED`), e `candidate` (`:707-758`) só confirma que os nomes
exigidos foram registrados.

**Em vez disso.** Coloque `tsc --noEmit`, linter e testes no comando de verificação do
contrato e no template do alvo; revise o diff.

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

## 9. Evidência prova execução; o self-check tem escopo curto

**Afirmação.** `evidence/` é auditada por presença de arquivos e heurística de nome
(`/test|spec|result|log|output|coverage/i`), não por utilidade: o harness garante que
o comando rodou naquele instante com aquele resultado, não que o teste exercita o
requisito. E `pwn self-check --mutate` roda 5 mutações estruturais sobre uma **cópia
temporária** (baseline canônica quando o Work está incompleto): não cobre mutações de
conteúdo, combinações de violações nem gates fora de `mutationCases()`.

**Evidência.** `src/core/gates.ts:932-990` (`validateEvidenceSemantics`, com
`hasTestEvidence` por regex e `FIND-SEM-EVD-003` em `severity: 'low'`); logs gravados
com sha256 em `src/core/task_evidence.ts:675` (`auditCheck`) e revalidados em `:723`;
`src/core/self_check_mutate.ts` para o escopo das mutações.

**Em vez disso.** Nomeie cada evidência com a AC que ela prova
(`AC-3-timeout.log`) e mantenha a matriz apontando para ela; ao endurecer um gate,
mude o caso correspondente para `expect_blocked: true` — essa mudança é o registro de
que o gate deixou de ser decorativo.
