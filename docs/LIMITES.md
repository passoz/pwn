# Limites do Piwerness

Documento **honesto** sobre o que o harness `piwerness` (v0.1.0) **não** garante.
Os gates são checagens estruturais determinísticas: tornam explícito o que foi
decidido e vinculado, mas não provam que a decisão está certa nem que o código faz o
que o requisito pretendia. Cada limite traz afirmação, evidência no código real e o
que usar em vez da garantia que não existe.

As referências `arquivo:linha` correspondem ao estado do repositório em 2026-09-18
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

## 3. O diff guard valida caminho, não conteúdo

**Afirmação.** O contrato de escopo protege contra escrita **fora** de `write_allow` e
dentro de `write_deny`. Escrever a implementação errada — `return null`,
`process.exit(0)`, teste vazio — dentro do caminho permitido não é detectado: não há
análise de conteúdo no diff guard.

**Evidência.** `src/core/contract-guard.ts:16-80` (`checkFileAgainstScope`,
`checkDiffAgainstContract`): a decisão é `minimatch(normalizedPath, pattern)`
(`:34` e `:47`; implementação em `src/core/glob-utils.ts:109`), sem leitura de bytes
do arquivo.

**Em vez disso.** Combine o contrato com evidência de teste (seção 4) e revisão de
`git diff` antes do merge. Escopo é contenção de dano, não correção.

## 4. A auditoria TDD prova causalidade, mas `--expect` é substring

**Afirmação.** O mutation check é forte: ele remove o diff de implementação e exige
que o teste falhe — isso prova que o teste depende da implementação. Mas a "falha
esperada" é comparada por **substring na saída**; qualquer log contendo o texto serve.
`--expect-literal` endurece apenas isso: exige que `--expect` apareça **literalmente**
em algum arquivo de teste congelado — não que o texto seja uma asserção.

**Evidência.** `src/core/task_evidence.ts:370` (`mutationCheck`:
`!mutationResult.output.includes(expect)`), `:426` e `:471` (RED/GREEN com
`output.includes`), `:418-423` (`literalInTests` com `--expect-literal`).
`assertionRan = !result.output.includes(redExpect)` (`:472`) trata a asserção como
"não executada" só quando o texto de falha reaparece — um teste silencioso passa.

**Em vez disso.** Use texto de `--expect` específico do caso (nunca genérico como
`"Error"`), prefira runners com saída estruturada e revise o log gravado.

## 5. Sandbox é Git Worktree: isolamento de árvore, não de SO

**Afirmação.** O sandbox cria um `git worktree` em branch próprio: isola a **árvore de
arquivos** do checkout. Não há namespaces, chroot, cgroups, usuário separado nem
firewall — um subprocesso do agente roda com o mesmo usuário, pode escrever fora do
worktree (inclusive no Work real) e acessar a rede.

**Evidência.** `src/core/sandbox.ts:19-56` (`createGitWorktreeSandbox`, com
`git worktree add -b ... HEAD` em `:37`). O escape por subprocesso é **registrado**
como documentário em `tests/security-adv.test.ts:383-407`:
`// The test is DOCUMENTARY — it records whether subprocess escape is possible.`

**Em vez disso.** Para código não confiável, rode em container/VM (Docker, gVisor,
firecracker) ou com usuário separado. Aqui o sandbox evita sujar o Work; não contém
um adversário.

## 6. Não existe verificação de qualidade semântica de código

**Afirmação.** O harness não compila, não roda linter estático nem avalia
complexidade, segurança ou desempenho do código produzido. Ele registra que comandos
rodaram e que produziram a saída esperada — e o que conta como "esperado" é declarado
no próprio plano.

**Evidência.** `src/core/task_evidence.ts:491-517` (`verify`) re-executa o comando RED
e confere exit code 0 e ausência do texto de falha; a lista de checagens vem do texto
do plano (`taskAuditRequirements`, `:558-576`, que conta ACs por regex em `**ACs:**` e
lê `**Visual:** REQUIRED`), e `candidate` (`:578-600`) só confirma que os nomes
exigidos foram registrados.

**Em vez disso.** Coloque `tsc --noEmit`, linter e testes no comando de verificação do
contrato e no template do alvo; revise o diff.

## 7. `pwn validate` valida schema, não a verdade do conteúdo

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

## 8. Evidência prova execução; o self-check tem escopo curto

**Afirmação.** `evidence/` é auditada por presença de arquivos e heurística de nome
(`/test|spec|result|log|output|coverage/i`), não por utilidade: o harness garante que
o comando rodou naquele instante com aquele resultado, não que o teste exercita o
requisito. E `pwn self-check --mutate` roda 5 mutações estruturais sobre uma **cópia
temporária** (baseline canônica quando o Work está incompleto): não cobre mutações de
conteúdo, combinações de violações nem gates fora de `mutationCases()`.

**Evidência.** `src/core/gates.ts:932-990` (`validateEvidenceSemantics`, com
`hasTestEvidence` por regex e `FIND-SEM-EVD-003` em `severity: 'low'`); logs gravados
com sha256 em `src/core/task_evidence.ts:546` (`auditCheck`) e revalidados em `:597`;
`src/core/self_check_mutate.ts` para o escopo das mutações.

**Em vez disso.** Nomeie cada evidência com a AC que ela prova
(`AC-3-timeout.log`) e mantenha a matriz apontando para ela; ao endurecer um gate,
mude o caso correspondente para `expect_blocked: true` — essa mudança é o registro de
que o gate deixou de ser decorativo.
