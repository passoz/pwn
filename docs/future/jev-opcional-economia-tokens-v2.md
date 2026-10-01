# Verificador semântico tipado no PWN (v2) — Jev ou qualquer decisor compatível

> **Status:** proposta future / opt-in. Nada aqui altera o comportamento default do PWN.
> **Princípio:** os gates determinísticos continuam sendo a verdade. A verificação semântica
> é advisory, opt-in e fail-open — e entra **depois** de esgotar o que o determinismo resolve
> de graça.
> **Agnóstico de decisor:** o desenho não depende de Jev. Define um **contrato de adaptador**
> (§1.1); Jev é o adaptador de referência, não o assunto. Qualquer provedor compatível
> (remoto ou local) entra trocando um módulo, sem tocar nos gates.
> **Nome do arquivo:** mantido por continuidade com a v1 (`jev-opcional-economia-tokens.md`);
> o conteúdo é a v2 agnóstica. O apêndice §10 lista as correções factuais aplicadas.

---

## 1. Definições operacionais (antes de qualquer número)

A v1 foi lida como se o PWN consumisse tokens. Não consome, e nunca foi essa a tese.
Este documento fixa os termos para que as metas sejam falsificáveis.

| Termo | Definição operacional nesta proposta |
|---|---|
| **Tokens de LLM** | Tokens consumidos pelo **agente executor** (Claude Code, opencode, etc.) ao **codificar para cumprir os Works**: gerar `spec.json`/`plan.json`, reescrever artefatos após gate reprovado, re-executar `run`/`audit`. O PWN não gera nem chama modelos — ele **governa** o trabalho que consome tokens. |
| **Retrabalho** | Ciclos de reescrita de artefatos + re-execuções causados por falha **tardia** (erro semântico que só aparece em `work run` ou `audit`, depois de o gate ter dado `pass`). |
| **Decisor tipado (DT)** | Qualquer modelo/serviço que receba `state` + perguntas e devolva **respostas tipadas com probabilidades** — sem gerar texto livre. Abstração de provedor; ver §1.1. |
| **Adaptador** | Módulo que traduz o contrato interno (§1.1) para um provedor concreto (Jev, LLM com JSON schema, modelo local…). Único ponto de acoplamento a fornecedor. |
| **Custo do instrumento** | Tokens **adicionados** pela chamada do decisor (input de `state`+perguntas). Contabilizado **à parte** — ver §4.3. |
| **PWN não é executor de LLM** | Fato verificado no HEAD: zero `fetch`/HTTP outbound em `src/`, `bin/`, `tools/`, `scripts/`; `src/core/tool-api.ts:470-489` avalia política de rede e retorna sem tocar a rede; `src/core/run-orchestrator.ts` só invoca shell sob política. `src/core/router.ts` (tabela de modelos, `maxTokens`, `evaluateEscalation`) é **código declarativo sem consumidor em produção** (`docs/PLANO-AJUSTES.md` §2.2, achado A12). |

**Consequência direta:** a economia de tokens desta proposta é economia **do agente hospedeiro**,
indiretamente causada por decisões melhores e menos ciclos de reescrita. Por isso a medição é
parte do plano, não apêndice (§4).

### 1.1 Contrato do decisor (a fronteira agnóstica)

O núcleo do PWN fala com uma **interface**, nunca com um fornecedor. Toda a proposta vive
dessa interface; trocar de decisor = trocar de adaptador.

**Primitivas internas neutras** (o adaptador mapeia para as primitivas nativas do provedor —
ex.: `enum`/`bin`/`grade` → `choice`/`noul`/`score` no Jev):

| Primitiva interna | Semântica | Saída obrigatória |
|---|---|---|
| `enum` | Escolha entre N rótulos mutuamente exclusivos | distribuição de probabilidade por rótulo |
| `bin` | A condição vale? (uma por pergunta) | probabilidade de "sim" |
| `grade` | Grau em níveis ordenados descritos (0..n) | nível + score normalizado |
| `pick` | Seleção de um candidato ou trecho fornecido **pelo código** (pré-parse) | índice do candidato + probabilidade |

**Requisitos mínimos de um adaptador (obrigatório para entrar):**

1. Saída **tipada/JSON-schema** — sem texto livre para casar com regex.
2. **Probabilidade por resposta** (não só o rótulo) — é o que sustenta os thresholds da §7.6.
3. **Batch**: N perguntas independentes sobre o mesmo `state` em 1 chamada (sem interferência
   entre respostas). Sem batch, o custo do instrumento multiplica pelo número de perguntas.
4. **Confidence** derivável (concentração da distribuição) **ou** declaração explícita de que
   não fornece — nesse caso o adaptador cai no modo conservador (§1.2).
5. P95 de latência e custo por chamada **medidos** no F0.5 (§8), não prometidos.

**Requisitos proibidos (não entra):** decidir sozinho `write_allow`, assinar atestação,
gerar código, reescrever prompts do agente, alterar exit codes dos gates (§7.5).

### 1.2 Fallback e degradação (independente de provedor)

Cascata de decisão — sempre do mais barato/determinístico para o mais caro/humano:

```
T0  determinístico (regex/schema/existência)   → sempre roda, 0 tokens, dono da verdade
T1  decisor tipado barato (remoto ou local)    → verificação semântica advisory
T2  decisor tipado forte / revisão             → só quando T1 incerto ou P(wrong) alto
T3  humano                                     → confidence baixa ou alto risco
```

Regras de degradação, em qualquer ordem de provedor:

- **Sem probabilidade/confidence** → tratar como `0.5` (incerto) → caminho conservador
  (nunca relaxa, nunca rebaixa risco sozinho).
- **Sem chave, sem rede, sem adaptador configurado** → verificação vira **no-op com aviso
  visível** (fail-open para o comportamento atual, nunca para o sandbox).
- **Latência/custo acima do orçamento medido** → cair para T0 e registrar a queda.

---

## 2. Tese — determinismo primeiro, decisor onde o determinismo não alcança

O PWN já faz bem o que é determinístico: congelar o contrato V4
(`src/core/contract-engine.ts:71-162`), bloquear escopo via Diff Guard
(`src/core/contract-guard.ts:16-100`), isolar em worktree (`src/core/sandbox.ts:34-98`),
rotear por risco (`src/core/router.ts:78-98`), auditar TDD com exit codes semânticos.

O desperdício real está documentado no `docs/LIMITES.md` — e **metade dele se resolve sem
nenhum token gasto**. Esta é a correção de rumo central da v2:

| Gap (medido, não suposto) | Correção | Custo |
|---|---|---|
| 3/5 mutações canônicas não bloqueiam: `acceptance_criteria` ausente, `contract_id` inexistente, capability sem `rules` (`docs/LIMITES.md:37-43`, `src/core/self_check_mutate.ts:194-220`) | Endurecer severidade (`medium`→`high`) e acrescentar as checagens ao `GATE-SPEC-PLAN`/`GATE-PLAN-CONTRACT`/`GATE-PRD-SPEC` | **0 tokens**, ~1 dia |
| Validadores semânticos **já escritos mas órfãos**: `validateSpecCoversPRD` (`src/core/gates.ts:763`), `validateEvidenceSemantics` (`:932`) — só alcançáveis via `validateSemanticTraceability` (`:995`), chamada **exclusivamente** por `tests/gates.test.ts:163` | Ligar ao caminho de produção dos gates | **0 tokens**, ~½ dia |
| `spec_reference` **ausente passa em silêncio** — a checagem só flagra referência presente e inválida (`src/core/gates.ts:557`) | Exigir `spec_reference` obrigatório por task | **0 tokens** |
| `validate` confere schema, não verdade (`src/core/validator.ts:173,216`) | Declarado como limite, não "corrigível" — é aqui que o decisor tipado tem valor real | — |

**O decisor entra no resíduo que regex e schema não resolvem:** *o texto da capability
realmente implementa a intenção do requisito que ela cita?* — a promessa que
`src/core/gates.ts:759-761` faz no comentário e que o código (`:763-829`) não cumpre.

> A ordem importa para as metas: as correções determinísticas **também reduzem retrabalho**
> (fecham exatamente as falhas tardias), e custam zero token. Elas são o **F0**, não uma
> alternativa à verificação semântica — são a base sobre a qual o ganho adicional é medido.

---

## 3. Onde os tokens do agente são gastos (mapa do custo-alvo)

| Fonte de consumo | Causa raiz hoje | Alavanca |
|---|---|---|
| Regenerar `spec`/`plan` após erro semântico tardio | Gate dá `pass` sobre rastreabilidade vazia de intenção | **F0 (determinístico) + E1 (decisor)** |
| Re-executar RED→GREEN→candidate inteiro por falso sucesso na auditoria | `--expect` é substring (`src/core/task_evidence.ts:490,546,591`); `validateEvidenceSemantics` só regex de nome de arquivo (`src/core/gates.ts:968-970`) e é `severity: 'low'` (`:974`) | **E5** |
| Geração inicial de artefatos com modelo forte quando o barato bastaria | Sem verificação barata entre `cheap` e `strong`; roteamento por keyword erra nos dois sentidos | **E3 + E2** |
| Contexto gigante por `task capsule` / contrato completo em prompt | `generateContextCapsule` devolve o contrato inteiro (`src/core/capsule.ts:8-65`, chamado em `src/commands/task.ts:57`) | **E4** |
| Roteamento errado (L2→L3 caro) | `--risk auto` é `String.includes` sobre texto normalizado (`src/core/v3-import.ts:533-535`) | **E2** |

Observe o que **não** está no mapa: "cápsula e `--dry-run` jogam contexto no LLM" — a v1
citava `work.ts:64-93` para isso, mas essa faixa é o bloco `gate --all`, e `--dry-run`
(`work.ts:316-366`) só imprime em stdout. Ver apêndice §10.

---

## 4. Protocolo de medição e metas

### 4.1 Baseline obrigatória antes de F1

Sem baseline, −50% e −70% são o mesmo tipo de número que o próprio repo já denunciou:
`docs/PLANO-AJUSTES.md:43` (A9) — *"`optimize` inventa "70%" com histórico vazio"*.
Hoje `.pwn/metrics.jsonl` não existe e os campos de token são gravados como `0` em
`src/core/run-orchestrator.ts:228,314,402`.

**Proxies determinísticos (coletáveis hoje, sem instrumentar agente):**

- `ciclos_gate_run`: quantas vezes `work gate` → `work run` → `work audit` por Work até `pass`;
- `rewrites_artefato`: contagem de mudanças em `spec.json`/`plan.json` entre gates (hash por
  `input_versions`, já existente);
- `tempo_work`: wall-clock do `work init` até aprovação;
- `blocked_tardio`: gate `pass` seguido de falha em `run`/`audit` (**a métrica-alvo de E1**).

**Amostragem de tokens do agente:** em N Works reais (N ≥ 5), registrar manualmente os tokens
reportados pelo agente hospedeiro para geração/reescrita de artefatos. É a única forma
falsificável de sustentar a meta de tokens sem acoplar o PWN a um agente específico.

### 4.2 Metas

- **Headline (alvo declarado): −50% tokens de geração/reescrita do agente e −70% retrabalho/tempo.**
- **Aceite por fase (obrigatório, medido):**

| Fase | Critério de saída |
|---|---|
| F0 | `self-check --mutate`: 5/5 casos com comportamento declarado (hoje: `expect_blocked` 2 `true` / 3 `false`, `src/core/self_check_mutate.ts:194-220`); baseline de proxies coletado em ≥ 5 Works |
| F1 | −30% tokens de reescrita **e** −50% `ciclos_gate_run` vs. baseline F0, nos Works medidos |
| F2+ | Headline −50%/−70% avaliada contra a baseline F0, não contra a F1 |

A v1 continha duas metas concorrentes (−50% na tese, −30%/−50% no §3.2). A v2 reconcilia:
−30%/−50% é **aceite da F1**; −50%/−70% é **alvo final**. Uma só por camada.

### 4.3 Contabilidade de tokens

O verificador não é grátis em tokens — só é barato em dólar no caso do adaptador de
referência (Jev 1.12: $0.042/1M input, $0.00 output). Qualquer decisor, inclusive local,
**acrescenta** input ao ledger.

- **Nas métricas de ganho:** contam apenas tokens de **geração/reescrita do agente** (§1).
- **No custo do instrumento:** tokens de input do decisor são reportados à parte em
  `.pwn/metrics.jsonl` (campo `judgeInputTokens` + `judgeProvider`), nunca misturados com a
  meta.
- Se um dia a métrica virar "throughput total", a verificação **piora** o número no papel —
  a definição acima é travada por isso.

---

## 5. As 5 inserções, revisadas

Ordem por **ROI real**, não por intuição da v1. Todas falam com o contrato §1.1.

### E1 — `work gate --judge`: verificador semântico advisory (maior alavanca de retrabalho)

Fecha o gap de §2: o texto da capability implementa o requisito?

```bash
pwn work gate --all --judge --work 0002
pwn work gate GATE-PRD-SPEC --judge=jev --no-cache
pwn work gate --all --judge=local --work 0002    # mesmo contrato, outro adaptador
```

- Uma chamada por gate, `state={requirements, prd, spec, plan}`, bateria em paralelo (batch,
  §1.1-3):
  - `bin` por par `capability × requirement`: `hallucinated? off_target? incomplete?`;
  - `grade` de observabilidade de cada `acceptance_criteria` (0=vago, 1=observável,
    2=executável por `bun test`);
  - `enum`: qual `capability` cada task realmente implementa — detecta `spec_reference`
    fabricado e agora também o **ausente** (`src/core/gates.ts:557`).
- **Canal de ação obrigatório** (correção da v1): `pass_with_notes` silencioso não reduz
  retrabalho. Findings vão para um bloco destacado em stdout **e** para `--strict-judge`
  (exit próprio, sem tocar exit codes dos gates) **e** são persistidos para o
  `blocked_tardio` da §4.1. Advisory não é a mesma coisa que invisível.
- `severity: medium/low`, `status: open`. Não muda `laws_sha256` nem o HMAC dos gates
  (ver §6.3 para a resolução do cache).

### E2 — Classificação de risco com confidence-gate (**reescrito**)

**A premissa da v1 estava errada.** `RISK_ROLE_MAP` já manda **L3 → `strong`**
(`src/core/router.ts:82`) — não existe "2–3 tentativas falhas no `cheap`" para L3 a economizar.
A economia real é outra:

- **Falso positivo:** tarefa L2 classificada como L3 por keyword → roda em `strong`
  (`maxTokens: 16000`, `src/core/router.ts:47-52`) quando `cheap` (`4000`, `:40-45`) bastaria.
- **Falso negativo:** tarefa sensível que foge às keywords → roda barata e falha até escalar
  (`evaluateEscalation`, `src/core/router.ts:225-282`).

Proposta:

- `enum{L0..L4}` com critérios contrastivos (o que é / não é cada nível + exemplos) +
  `bin{is_security_sensitive?, is_data_destructive?}`;
- `confidence < risk_threshold` → **mantém o resultado determinístico conservador** e marca
  `accepted_risk` para humano. O decisor nunca rebaixa sozinho;
- Adaptador **sem probabilidade** (§1.1-4) → cai automaticamente no conservador: nenhuma
  troca de risco acontece só pela via semântica;
- **`risk_threshold: 0.75` é placeholder**, não regra — calibrar em F2 com a distribuição real
  de risco dos Works (§7.6).

**Uniformização de `--risk auto` (incluída aqui):** hoje `auto` existe só em `work import`
(`src/commands/work.ts:174`) e é **rejeitado** por `work scaffold` (`:239-243`); a lógica é
`String.includes` sobre texto normalizado com constantes hardcoded (`src/core/v3-import.ts:533-535`),
e o campo `risk_keywords` de `.pwn/policy.json` — que **nem existe** no repo — é lido apenas
dentro de `src/core/policy-config.ts` e **não tem nenhum consumidor externo**. Unificar
`import`/`scaffold` na mesma fonte de classificação é pré-requisito desta inserção.

### E3 — Cascata `agente gera → decisor verifica → só o errado escala` (maior alavanca de tokens)

Aqui está a única alavanca que ataca −50% de tokens de geração.

- **Escopo honesto (diferença da v1):** o agente continua sendo quem gera. O PWN/CLI executa
  a **verificação** via adaptador (§6): `enum`/`bin` por campo sobre o draft, com gate
  `any_flag` (`P(wrong) > threshold` em **qualquer** campo → escala **aquele** artefato para
  revisão forte, senão aceita o barato). `thresholds` vem de config, não hardcode.
- Pré-requisito real: `router.ts` precisa de consumidor, ou a proposta assume que a **decisão
  de escalonamento** volta ao agente com base no veredito tipado. Sem isso, não há cascata —
  há só um veredito impresso. Ver `docs/PLANO-AJUSTES.md` §2.2 (A12) e §13 (não-objetivos).
- Evidência de desenho: fronteira de Pareto da cascata *up-and-left* de modelos isolados
  (cookbook de cascata de extração do provedor de referência) — **a validar no F0.5**, não
  assumir, e **por adaptador** (o ganho de um provedor não transfere automaticamente a outro).

### E4 — Cápsula mínima e escopo pré-voo

- `pick`/rerank dos trechos de `traceability-matrix.json` + contrato para montar cápsula por
  task, em vez de dump completo (`src/core/capsule.ts:8-65`); padrão de referência: top-1
  5%→18% do contexto.
- `enum`/`pick` sobre candidatos de arquivo (pré-parse via `glob`) + `bin` (`a task precisa de
  path X?`) → sugere `write_allow` mínimo, hoje `['src/**','tests/**']` por default
  (`src/core/contract-engine.ts:143`). Diminui acionamentos à toa do Diff Guard.
- **Restrição:** sugestão de `write_allow` é advisory e exige confirmação humana — nunca
  decide sozinho (§7.5).

### E5 — Auditoria TDD triada pelo decisor

- `bin` (`o log suporta AC-X?`), `enum` (qual AC o log prova), `grade` (força da evidência).
- Só casos na faixa incerta (`0.4 < p < 0.6`) ou `confidence < 0.75` vão para T2/T3
  (`review`/`strong`/humano).
- Não toca em `candidate` versionado nem HMAC; filtra re-execução cara.
- Pré-condição: `--expect` substring (`src/core/task_evidence.ts:490,546,591`) e
  `validateEvidenceSemantics` por regex de nome (`src/core/gates.ts:968-970`, `severity: 'low'`
  em `:974`) permanecem para o caminho determinístico; o decisor complementa, não substitui.

---

## 6. Fronteira do adaptador, rede e privacidade

### 6.1 Arquitetura — vendor confinado

**Decisão: o PWN (CLI) executa as chamadas; o fornecedor vive inteiramente no adaptador.**

```
src/core/judge-gate.ts          ← orquestração, thresholds, findings (agnóstico)
src/core/judge/contract.ts      ← tipos das primitivas §1.1 + interface JudgeAdapter
src/core/judge/adapters/<x>.ts  ← ÚNICO arquivo que conhece SDK/endpoint/credencial de <x>
```

Nenhum outro módulo importa um adaptador diretamente (registry em `contract.ts`).
Isso é o que torna "Jev ou qualquer outro" uma troca de configuração, não um refactor.

Implicações declaradas (não escondidas como "só uma flag"):

- **por adaptador remoto:** nova dependência em `package.json` (hoje apenas `ajv`), credencial
  em env server-side (`*_API_KEY`), egress para o endpoint do provedor;
- **adaptador local** (ex.: modelo pequeno em Ollama/llama.cpp): 0 egress, 0 dependência de
  nuvem — mas latência e calibração têm de ser medidos no F0.5 antes de virar default;
- seleção por config, nunca por hardcode:

```jsonc
// .pwn/policy.json — seção nova (o arquivo hoje não existe)
{
  "judge": {
    "enabled": false,
    "provider": "jev",          // "jev" | "openai-json" | "local" | ...
    "budget": { "maxInputTokensPerGate": 30000, "maxCostUSDPerWork": 0.50, "p95Ms": 3000 },
    "thresholds": { "wrong": 0.75, "uncertainLow": 0.4, "uncertainHigh": 0.6, "confidence": 0.75 }
  }
}
```

### 6.2 Rede e privacidade — carve-out explícito e por provedor

O PWN nega rede com allowlist vazia por design (`src/core/policy-engine.ts:325-334`) e
`docs/LIMITES.md:155-174` documenta que o sandbox lê o host inteiro. Contraditoriamente,
E1–E5 enviam `state` com requisitos/código para API de terceiro. Resolução proposta:

1. **Carve-out documentado por provedor:** `allowedDomains` recebe **apenas** o endpoint do
   adaptador configurado, **apenas** quando `judge.enabled` e `--judge`. Sem chave, sem rede,
   no-op com aviso (fail-open para o comportamento atual, nunca para o sandbox).
2. **Allowlist de campos por inserção** (o que entra no `state` de cada E1..E5) — nunca
   `~/.config`, env, `.env`, `*.pem`, `.git/`.
3. **Redaction** de segredos antes do envio (o mesmo critério de `sensitiveDirs` em
   `src/core/sandbox.ts:163-167`, ampliado).
4. Sem nenhuma das 3 condições → **a inserção não existe**. É critério de merge, não sonho.
5. **Adaptador local é o caminho para ambientes que não podem sair da rede** — e deve ser
   considerado o plano B ativo, não curiosidade.

### 6.3 Cache, HMAC e pinagem

O envelope do cache assina `findings` e `summary` (`src/core/gate-cache.ts:60-101`) e a chave
do arquivo deriva só de `gate + input_versions` (`:150`). Três consequências:

- `judge_verdict` **fora** do payload assinado → não invalida HMAC, mas também **não tem
  integridade**. Se for advisory, aceitável e documentado; se um dia virar `blocked`, tem de
  entrar no payload assinado.
- A chave precisa de **separação por ativação** (ou bump de `GATE_CACHE_VERSION`, `:9`) **e
  por provedor+versão** — senão um veredito de um adaptador é servido a outro, ou a um pedido
  sem `--judge`.
- Pinagem: `provider + provider_version + gate_version` no envelope; `laws_sha256` permanece
  determinístico e **independente** de veredito. Um veredito de provedor A nunca é
  reutilizado como de B.

---

## 7. Críticas e guardrails

1. **Saída tipada garante interface, não verdade.** E1 começa `pass_with_notes`, nunca
   `blocked`. Endurecer só após precisão/recall medidos em Works reais **por adaptador** +
   `self-check --mutate` com novos casos `expect_blocked:true`.
2. **Custo extra real.** Cada gate com verificação = 1 chamada. Threshold baixo demais → tudo
   escala e paga-se duas vezes. Medir via `.pwn/metrics.jsonl` (`tokensInput/Output`, `costUSD`,
   `durationMs`, `attempts`, `isolated` + `judgeInputTokens`/`judgeProvider`).
3. **Latência e offline.** Sem credencial, sem rede ou sem adaptador: no-op **com aviso
   visível**. Nunca quebrar `bwrap`/sandbox por causa da verificação.
4. **Advisory não pode ser invisível** (correção da v1). Sem canal de ação (§5-E1), E1 gera
   ruído e a meta de retrabalho não se move.
5. **O decisor não decide sozinho:** nem `write_allow`, nem assinatura de atestação, nem
   reescrita de prompts, nem geração de código. Código continua dono do workflow.
6. **Thresholds são placeholders** (`0.75`, `0.7`, faixa `0.4–0.6`): confidence mede
   concentração da distribuição, **não correção** — e cada provedor tem curva de calibração
   própria. Calibrar no dado do próprio projeto **por adaptador**, antes de qualquer política
   automática; thresholds de um provedor não valem para outro.
7. **Privacidade é gate de merge** (§6.2), não item de lista de boas práticas.
8. **Agnosticismo não é grátis:** custa a camada de contrato (§1.1) e a disciplina de manter
   os adaptadores isolados (§6.1). É o preço de não casar com um fornecedor — e vale porque
   a única coisa garantida sobre um provedor de IA é que ele muda.

---

## 8. Plano de fases

| Fase | Escopo | Critério de saída |
|---|---|---|
| **F0** | Endurecimento determinístico (§2) + baseline de medição (§4.1) | 5/5 mutações declaradas; baseline em ≥ 5 Works |
| **F0.5** | Spike com **≥2 adaptadores** (ex.: Jev + um alternativo local ou LLM-com-schema): bateria E1 num Work real; medir separação `P(wrong)` em erro real vs. correto, custo, latência p95 | Tabela comparativa de adaptadores; escolha de default justificada em dados |
| **F1** | `gate --judge` advisory: `src/core/judge-gate.ts` + contrato + 1 adaptador + flag CLI, sem tocar `gates.ts` nem schemas | −30% reescrita / −50% ciclos vs. baseline F0 |
| **F2** | E2 reescrito (confidence-gate + unificação `--risk auto`) | L2→L3 falso-positivo medido e reduzido; threshold calibrado por adaptador |
| **F3** | E3 cascata (requer consumidor de roteamento / decisão de escalonamento) | Tokens de geração −X% vs. baseline, com qualidade não-regredida |
| **F4** | E4 cápsula/escopo + E5 triagem de auditoria | `blocked_tardio` e re-execução de auditoria reduzidos |
| **F5** | Endurecer sinais de alta precisão para `high`/blocked | Precisão/recall medidos **por adaptador**; casos em `self-check --mutate` |

Cada fase: flag `--judge`/`--no-judge` (alias `--jev` aceito quando `provider=jev`) +
`PWN_JUDGE_ENABLED`/`PWN_JUDGE_PROVIDER`, docs em `docs/MANUAL.md` e `docs/LIMITES.md`
atualizados com o que a verificação **não** garante.

### Conflito declarado com `docs/PLANO-AJUSTES.md`

O §13 daquele plano declara não-objetivos **"telemetria nova"** e **"alterar a semântica dos
5 gates"**, e §2.1 mantém A4/A12 (enforcement inerte, ~1.587 l. órfãs) e F2/F5 abertos.

- **F0 desta proposta não conflita**: endurecer severidade é fechar dívida já catalogada em
  `LIMITES.md` §2, e os "proxies" da §4.1 são derivados de dados que os gates já produzem —
  não é telemetria nova.
- **F1..F5 exigem exceção explícita** no PLANO-AJUSTES, registrada quando a proposta for
  aceita. Enquanto A12 não avançar, E3 não tem onde ser plugada (§5-E3) e fica **bloqueada
  por prerequisito, não por vontade**.

---

## 9. Ordem de execução resumida

```
F0 determinístico + baseline  →  F0.5 spike multi-adaptador  →  F1 gate advisory
        →  F2 risco  →  F3 cascata (gated por A12)  →  F4 cápsula/audit  →  F5 endurecer
```

Regra: **nenhuma fase avança sem o critério de saída da anterior medido.** A v1 pedia
confiança; a v2 pede evidência — e a evidência é sempre **por adaptador**.

---

## 10. Apêndice — errata da v1

Correções aplicadas nesta versão, com verificação no HEAD:

| # | v1 | v2 (verificado) |
|---|---|---|
| 1 | "cápsula e `--dry-run` jogam contexto gigante no LLM (`work.ts:64-93`)" | `work.ts:64-93` é o bloco `gate --all`; `--dry-run` é `work.ts:316-366` (stdout apenas); cápsula é `task.ts:57` + `capsule.ts:8-65` (só contrato, sem plano). Nenhum vai a LLM — não há LLM no PWN. |
| 2 | "`validate` valida schema (`validator.ts:44-100`)" | `:44-100` é `lawsDigest`/helpers; funções reais: `validateNormativeDocument` `:173`, `validateWorkDocuments` `:216`. |
| 3 | "`--risk auto` é regex; `.pwn/policy.json` com `risk_keywords`" | `String.includes` sobre texto normalizado (`src/core/v3-import.ts:535`); `.pwn/policy.json` **não existe**; `risk_keywords`/`gate_thresholds` têm consumidor **apenas** dentro de `src/core/policy-config.ts`. |
| 4 | "`spec_reference`: gate só checa presença (`gates.ts:552-570`)" | Invertido: `:557` flagra só referência **presente e inválida**; **ausente passa**. O buraco é maior. |
| 5 | "`L3/L4 vão direto para `strong` sem tentativas falhas no `cheap`" como economia de E2 | `RISK_ROLE_MAP` já manda L3→`strong` (`router.ts:82`). Economia real = falso-positivo L2→L3 (E2 reescrito). |
| 6 | `MANUAL.md:13` como referência de exit codes | É linha de sumário; referências corretas: `MANUAL.md:200,417,572`. |
| 7 | Meta de aceite `−30%/−50%` concorrendo com headline `−50%/−70%` | Reconciliadas na §4.2 (aceite por fase × alvo final). |
| 8 | `scaffold --risk auto` pressuposto em E2 | `scaffold` rejeita `auto` (`work.ts:239-243`); `auto` é exclusivo de `work import` (`:174`). Unificação listada como pré-requisito em E2. |
| 9 | Thresholds (`0.75`, `0.7`) apresentados como regra | Marcados como placeholders calibráveis **por adaptador** (§7.6). |
| 10 | Guardrail de privacidade como item de lista | Elevado a **carve-out de rede + allowlist de campos + redaction**, critério de merge (§6.2). |
| 11 | Proposta acoplada a Jev (flags `--jev`, `jev-gate.ts`, `jevInputTokens`, metas por provedor) | Reescrita como contrato de adaptador §1.1 + vendor confinado §6.1; Jev é o adaptador de referência, não o assunto. |
