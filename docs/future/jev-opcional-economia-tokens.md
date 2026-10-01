# Parecer Crítico: Jev opcional no PWN — otimizar código, reduzir retrabalho, acelerar e economizar tokens

> Status: proposta future / opt-in. Nada aqui altera o comportamento default do PWN.
> Princípio: gates determinísticos continuam sendo a verdade; Jev é sempre advisory + opt-in, fail-open para o comportamento atual.

## 1. Tese central

Jev não gera código e não deve gerar os artefatos do PWN. O PWN (`README.md`, `docs/MANUAL.md`)
já faz bem o que é determinístico:

- congelar contrato V4 (`src/core/contract-engine.ts`);
- bloquear escopo via Diff Guard (`src/core/contract-guard.ts:16-80`);
- isolar em Git Worktree (`src/core/sandbox.ts:19-40`);
- rotear por risco (`src/core/router.ts:78-98`);
- auditar TDD com exit codes semânticos (`docs/MANUAL.md:13`).

O desperdício de tokens do PWN hoje está documentado no próprio `docs/LIMITES.md`:

| Limite honesto | Custo em tokens/retrabalho hoje |
|---|---|
| Gates validam presença de ID, não intenção (`LIMITES.md:14-33`, `src/core/gates.ts:411-500`) | LLM forte gera `spec.json`/`plan.json` volumoso, gate dá `pass`, erro semântico só aparece no `work run`/`audit` — volta tudo. |
| 3/5 mutações não bloqueiam (`LIMITES.md:37-43`) | `GATE-SPEC-PLAN` não olha `acceptance_criteria`, `GATE-PLAN-CONTRACT` só checa presença de `contract_id`, capability sem `rules` é `medium` advisory. |
| `validate` valida schema, não verdade (`LIMITES.md:192-206`, `src/core/validator.ts:44-100`) | `prd.json` inventado passa como VÁLIDO. |
| Risco `auto` é regex de keyword (`MANUAL.md:391-396`, `.pwn/policy.json`) | `auth/payment/webhook` => L3. Falso positivo sobe para `strong` caro; falso negativo deixa L3 em `cheap` e falha em loop até escalar. |
| `metrics optimize` é heurística declarativa (`MANUAL.md:342-350`, `src/commands/metrics.ts:31-48`) | Sugere `strong->cheap` sem medir semântica. |
| Cápsula e `--dry-run` jogam contexto gigante no LLM (`src/commands/work.ts:64-93`, `task capsule`) | Contrato V4 + plano inteiro vai para o prompt do agente forte. |

Jev, como System One — `choice`/`score`/`noul` paralelos, ~100ms, output tipado sem tokens
de geração (ver `https://docs.typesafe.ai/introduction/coding-agents.md`) — encaixa exatamente
nesses pontos como **verificador / roteador / redutor de contexto**, nunca como gerador.
Padrão canônico: **extract barato → verify Jev → escalate só se disparar**
(ver `https://docs.typesafe.ai/cookbooks/sde_cascade.md`).

Referências de desenho:

- `https://docs.typesafe.ai/concepts/how-to-build-with-system-one.md` — código dono do workflow, IA só em julgamentos estreitos.
- `https://docs.typesafe.ai/cookbooks/parallel_questions.md` — batch de perguntas: 12.2x mais barato, 10x mais rápido.
- `https://docs.typesafe.ai/patterns/confidence-routing.md` — rotear na incerteza, não no chute.
- `https://docs.typesafe.ai/cookbooks/citation_check.md` — checar alegação contra evidência.
- `https://docs.typesafe.ai/cookbooks/pre_parsed_value_extraction_cookbook.md` — selecionar span em vez de gerar.
- `https://docs.typesafe.ai/cookbooks/rerank_typesafe.md` — rerank para contexto mínimo.

## 2. Onde introduzir — 5 inserções opcionais, em ordem de ROI

### E1. `work gate --jev`: overlay semântico advisory (maior redução de retrabalho)

Problema: `validateSpecCoversPRD()` (`src/core/gates.ts:763-829`) só checa se
`covered_requirements` contém o ID. Não lê se o texto da capability implementa o requisito.
`evaluateGateSpecPlan()` (`src/core/gates.ts:512-603`) só confere que `spec_reference` existe.

Proposta opt-in:

```bash
pwn work gate --all --jev --work 0002
pwn work gate GATE-PRD-SPEC --jev --no-cache
```

- Uma chamada `system_one` por gate, com `state={requirements, prd, spec, plan}` + bateria em paralelo:
  - `noul` por par `capability x requirement`: `hallucinated? off_target? incomplete?` (mesmos heads do SDE cascade).
  - `score` de observabilidade de cada `acceptance_criteria` (0=vago, 1=observável, 2=executável por `bun test`).
  - `choice`: para cada task, qual `capability` ela realmente implementa — detecta `spec_reference` fabricado que hoje passa em `src/core/gates.ts:552-570`.
- Resultado vira `findings` com `severity: medium/low`, `status: open` → `pass_with_notes`,
  **nunca `blocked` na fase 1**. Não muda `laws_sha256`, HMAC (`src/core/gate-cache.ts`), exit codes.
- Economiza o ciclo mais caro: reescrever `spec`/`plan` com `claude-3-7-sonnet maxTokens:16000`
  (`src/core/router.ts:47-52`) 3–5x por erro semântico tardio.

### E2. Classificação de risco + roteamento com confidence-gate

Problema: `RISK_ROLE_MAP` (`src/core/router.ts:78-84`) + `risk_keywords` em `.pwn/policy.json`
são estáticos. Erro de classificação = token queimado no papel errado +
`evaluateEscalation()` (`src/core/router.ts:225-282`) escalando tarde.

Proposta (`policy.json`, tudo opcional, default off):

```jsonc
// .pwn/policy.json
{ "jev": { "enabled": false, "model": "jev-latest",
  "risk_threshold": 0.75, "escalate_on_low_confidence": true } }
```

- `pwn work import --risk auto --jev` e `pwn work scaffold --risk auto --jev`:
  - `choice{L0,L1,L2,L3,L4}` com critérios contrastivos (o que é / não é cada nível + exemplos) + `noul` `is_security_sensitive? is_data_destructive?`.
  - Se `confidence < threshold` → mantém L2 conservador + marca `accepted_risk` para humano.
- `selectForRisk()` continua puro; Jev só sugere `risk.level` antes de
  `createDefaultContractV4()` (`src/core/contract-engine.ts:71-162`), que já escala
  `budget max_tokens 10k→200k` por nível.
- Economia direta: L0/L1 ficam no `cheap qwen3.5:27b maxTokens:4000`, L3/L4 verdadeiros vão
  direto para `strong` sem 2–3 tentativas falhas no `cheap`.

### E3. Cascata de geração de artefatos `cheap → Jev → strong`

Problema: `scaffoldWork()` (`src/core/scaffold.ts`) gera esqueleto que o operador detalha com
LLM forte. Cada regeneração de `discovery→requirements→prd→spec→plan` custa dezenas de k tokens.

Proposta: `pwn work scaffold --cascade --jev`:

1. `cheap` gera draft JSON.
2. Jev verifica por campo (`absence_wrong` para vazio, `hallucinated`/`off_target` para preenchido).
3. Gate `any_flag` (max, não média): se qualquer `P(wrong) > 0.7` escala só aquele artefato para `strong`, senão aceita o barato. Idêntico ao Step 4 do SDE cascade.

Evidência do cookbook: a fronteira de Pareto da cascata fica **up-and-left de todo modelo
isolado** — quase a qualidade do reasoning por fração do custo.

### E4. Pré-voo de escopo e cápsula mínima

Problema: `write_allow: ["src/**","tests/**"]` default (`src/core/contract-engine.ts:143`) é amplo;
`task capsule` joga o contrato inteiro no prompt.

- Jev `choice` para selecionar arquivos candidatos (pré-parse via `glob` + Jev seleciona span) + `noul` (`task precisa de path X?`) → sugere `write_allow` mínimo. Reduz `Diff Guard` acionado à toa e scope drift dentro do permitido (`LIMITES.md:65-90`).
- Jev `rerank` dos trechos de `traceability-matrix.json` + contrato para montar cápsula enxuta por task, em vez de dump completo (padrão rerank: top-1 5%→18%).
- Checagem antes de `createGitWorktreeSandbox`: evita criar sandbox + rodar `bun test` para descobrir erro de escopo depois.

### E5. Auditoria TDD triada por Jev

Problema: `--expect` é substring (`src/core/task_evidence.ts:490,546,591`) +
`validateEvidenceSemantics()` (`src/core/gates.ts:932-990`) por regex de nome de arquivo.
Falso sucesso custa re-execução completa RED→GREEN→candidate.

- `pwn work audit --jev`: `noul` (`log suporta AC-X?`), `choice` (qual AC o log prova), `score` (força da evidência). Só casos `0.4 < p < 0.6` ou `confidence < 0.75` vão para `review`/`strong` (padrão citation-check + consistency).
- Não toca em `candidate` versionado nem HMAC; só filtra o que merece re-execução cara.

## 3. Críticas e guardrails — o que pode dar errado

1. **Jev não garante verdade, só julgamento calibrado.** Saída tipada garante interface, não correção. Por isso E1 começa como `pass_with_notes`, nunca `blocked`. Endurecer para `blocked` só após medir precisão/recall nos Works reais + `self-check --mutate` com `expect_blocked:true`.
2. **Custo extra real.** Cada gate com Jev adiciona 1 chamada API. Threshold baixo demais = tudo escala para `strong` e paga-se duas vezes. Exigir medição via `.pwn/metrics.jsonl` (`tokensInput+Output`, `costUSD`, `durationMs`, `attempts`, `isolated`). Meta de aceite sugerida: `-30% tokens por Work aprovado, -50% ciclos gate→run`.
3. **Latência e offline.** Sem `TYPESAFE_API_KEY` ou sem rede, tudo degrada para o PWN atual silenciosamente (`--jev` vira no-op com aviso). Nunca quebrar `bwrap`/sandbox por causa de Jev.
4. **Privacidade.** `state` contém código/requisitos enviados à API TypeSafe. Exigir allowlist de campos, redaction de segredos, env server-side, e nunca enviar `~/.config`, env (`LIMITES.md:155-174` já alerta que o sandbox expõe demais).
5. **Pinagem.** Fixar `jev-1.x` + `gate_version` no envelope de cache; separar `laws_sha256` determinístico de `jev_verdict` advisory para não invalidar HMAC à toa.
6. **Não usar Jev para:** gerar código, reescrever prompts do agente, decidir `write_allow` sozinho, assinar atestação. Código continua dono do workflow.

## 4. Plano de execução proposto (opt-in por fase)

- **F0 — spike sem código:** playground TypeSafe com 1 Work real, bateria E1, medir separação `P(wrong)` em erro real vs. correto.
- **F1 — `gate --jev` advisory:** novo `src/core/jev-gate.ts` + flag CLI, sem tocar `gates.ts` nem schemas. Teste: taxa de `blocked` tardio evitado.
- **F2 — `risk auto --jev`:** estender `schemas/policy.schema.json` + `v3-import.ts`, confidence-gate.
- **F3 — `scaffold --cascade`:** `cheap → Jev → strong`, telemetria em `metrics.jsonl`.
- **F4 — cápsula mínima + audit triado.**
- **F5 — endurecer:** só após dados, promover sinais Jev de alta precisão para `high`/`blocked` + `metrics optimize` com features Jev.

Cada fase: flag `--jev`/`--no-jev` + `PWN_JEV_ENABLED`, docs em `docs/MANUAL.md` e `docs/LIMITES.md` atualizados com o que Jev **não** garante.
