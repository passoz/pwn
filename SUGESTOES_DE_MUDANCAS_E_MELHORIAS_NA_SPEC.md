# Sugestões de mudanças e melhorias para `SPEC.md`

**Documento analisado:** `SPEC.md` — *Technical Specification: Piwerness — Contract-Governed Agent Harness* (v1.0, 2026-08-25)  
**Fontes complementares analisadas:**

- `tactiq-free-transcript-9MNKRwKyENs.txt` — *Como Construir Qualquer App com IA Usando SDD (Discovery, PRD, SPEC, Sprints)*.
- `tactiq-free-transcript-stBfp9chHWE.txt` — *PRD + SPEC: Os 2 Documentos que Mudam Tudo no AI Coding*.

**Data da análise:** 2026-08-26  
**Natureza:** proposta de revisão da especificação principal; este arquivo **não altera** decisões já aprovadas nem presume implementação existente.

---

## 1. Parecer executivo

A `SPEC.md` já é forte no que as transcrições chamam de *harness de execução*: contratos, risco, budgets, allowlist de escrita, estratégias de validação, pipelines, sub-agents, escalonamento, evidência, fila e métricas. Ela também cobre de forma particularmente madura pontos que os vídeos tratam apenas em alto nível, como a compatibilidade v3/v4, a independência do port de `ai-engineering-skills` e a execução multi-runtime.

O principal espaço para evolução está **antes da execução dos Works de engenharia que nascem de uma ideia ou requisito ainda não estabilizado**. As transcrições defendem uma cadeia explícita de descoberta e refinamento:

```text
Discovery / pesquisa → user stories + requisitos → PRD →
revisões técnicas especializadas → spec técnica →
validação da spec → enriquecimento cético → plano/sprints →
validação do plano → execução isolada → avaliação → evidência/métricas
```

A spec atual descreve a linha canônica como `source → spec → contract → plan → execute → verify → escalate → accept → learn` (seção 4.8). O termo `source` admite, mas não governa, os artefatos que podem preceder a spec. Isso deixa implícitos os gates que reduzem ambiguidades antes de uma task ser entregue a um executor. Essa é a lacuna de maior impacto para o pack `software-engineering`; ela não precisa virar uma obrigação do core genérico nem de pipelines não relacionados a desenvolvimento.

### Recomendações prioritárias

| Prioridade | Mudança recomendada | Problema que resolve | Área atual afetada |
|---|---|---|---|
| P0 | Formalizar **Discovery e PRD** no pack `software-engineering`, com artefatos, aprovação e rastreabilidade | A spec pode começar técnica demais quando a intenção ainda não foi estabilizada | seções 4.8, 5.1, 10 e 11.2 |
| P0 | Criar revisões de **cobertura e consistência** com contexto isolado entre Discovery → requisitos → PRD → Spec → plano | Evita omissões, alucinações e decisões divergentes propagarem no pipeline | seções 4.8, 10.4 e 11.2 |
| P0 | Resolver a ordem e a fonte de verdade entre **plano e contratos por task** | O exemplo atual cria `work_contract` antes de atomizar tasks, embora o schema de Contract contenha `task_id` e limites específicos da task | seções 4.1, 4.8 e 10.4 |
| P0 | Instituir uma etapa de **enriquecimento cético**, com perguntas materiais e resolução humana | Caminhos alternativos e estados de erro tendem a ficar fora do caminho feliz | seções 4.1, 4.8 e 12 |
| P1 | Definir um contrato versionado para **handoffs de UX/UI** e evidência visual | Referências visuais não devem virar texto vago nem ser redesenhadas sem autorização | seções 4.1, 4.3, 6 e 9 |
| P1 | Acrescentar revisão de decisões por especialidade e um registro de decisões de produto/técnicas | Escolhas de arquitetura e segurança precisam de alternativas, impacto e aprovação explícita | seções 4.7, 4.8, 12 e 15 |
| P1 | Tornar o plano/sprints um artefato governado por dependências, Definition of Done e validação de cobertura | Uma lista de tasks pode não entregar toda a spec ou produzir ordem inválida | seções 4.8, 5.1 e 11.2 |
| P2 | Ampliar métricas com qualidade dos documentos, cobertura, reabertura e intervenções humanas | Custo/tokens não explicam por que o processo falhou ou melhorou | seções 4.12 e 8 |
| P2 | Revisar afirmações de compatibilidade de runtimes e comandos como requisitos condicionados a capability probes | Evita que a spec trate flags e recursos não verificados como universais | seções 4.8 e 6 |

As decisões P0 devem ser resolvidas antes de fechar o design da Fase 3 (Contract Engine v4), pois afetam as entradas e a granularidade dos contratos. Isso não bloqueia o port fiel da Fase 1 nem o CLI v3 da Fase 2.

---

## 2. Método, limites e critério de leitura das fontes

### 2.1 O que foi comparado

A análise confrontou as práticas propostas nas transcrições com as decisões e capacidades descritas na `SPEC.md`. Foram considerados principalmente:

- a separação conceitual entre **PRD** (produto/negócio) e **spec técnica**;
- o uso de uma sessão ou contexto isolado para revisar cada transformação importante;
- validações de cobertura entre artefatos consecutivos;
- enriquecimento por cenários negativos, transições de estado e ambiguidade;
- planejamento em unidades pequenas e com contexto limpo;
- escolha explícita de especialista/agent por unidade de trabalho;
- avaliação em contexto separado, limites de loops e registros de progresso;
- uso de referências visuais como insumo contratual, não como inspiração livre;
- métricas para calibrar o processo.

### 2.2 Limites importantes

As transcrições são relatos e recomendações operacionais de um autor, não contratos técnicos verificáveis do Pi, OpenCode, omp ou do próprio Piwerness. Portanto:

- elas são usadas como **fonte de hipóteses de produto e processo**, não como prova de API, comando, flag ou capacidade de runtime;
- exemplos de stacks, tecnologias, modelos e ferramentas exibidos nos vídeos não são recomendações para que Piwerness imponha essas escolhas aos projetos usuários;
- a proposta preserva o princípio atual de o Piwerness ser CLI-first, runtime-agnostic e sem impor stack aos projetos;
- onde as transcrições conflitam com a governança já decidida em `SPEC.md`, o conflito é apontado explicitamente; não se deve incorporar a recomendação de forma automática.

### 2.3 Convenção de referências

As referências de tempo abaixo apontam para as transcrições locais. Referências a “seção” apontam para a `SPEC.md` atual.

---

## 3. Diagnóstico detalhado: cobertura atual e lacunas

### 3.1 Pontos que a `SPEC.md` já cobre bem — preservar

As sugestões deste documento são aditivas. Os seguintes contratos da spec atual são coerentes com as transcrições e devem ser preservados:

1. **Contexto reduzido por executor.** O *context capsule* (seção 10.5) operacionaliza a preocupação das transcrições com degradação de qualidade em janelas longas (transcrição `stBfp9chHWE`, 00:02:32–00:12:16).
2. **Executor não toma livremente as decisões de processo.** A decisão de pipeline declarativo e de contrato congelado antes da execução (seções 2.6, 2.8 e 4.8) é uma evolução mais robusta do modelo de planner/coder/evaluator mostrado nas fontes.
3. **Validação anterior à aceitação.** A combinação de estratégia de validação, checks determinísticos, auditoria e evidências (seções 4.3, 4.8 e 10) é aderente à insistência das transcrições em validar trabalho de agentes por outro agente e por provas observáveis.
4. **Loops limitados e escalonamento.** Budgets, tentativas máximas, gatilhos de escalonamento e revisão humana para risco alto (seções 4.1, 4.2, 4.11 e 12) melhoram a ideia de rounds máximos do evaluator (transcrição `9MNKRwKyENs`, 00:46:23–00:52:12).
5. **Métricas por execução.** A coleta de custo, duração, tentativas e motivo de escalonamento (seções 4.12 e 8) corresponde à necessidade de otimizar o harness a partir de runs reais.
6. **Validação visual direta.** `visual-contract` exige screenshot e inspeção visual (seção 4.3), o que é consistente com o uso de um handoff de UI como referência de entrega (transcrição `9MNKRwKyENs`, 00:32:02–00:34:18).
7. **Escopo negativo como controle executável.** `out_of_scope`, `write_allow` e `write_deny` são essenciais para evitar expansão de mudança pelo executor (seções 4.1 e 10.5). Devem ser preservados apesar de uma afirmação contrária na transcrição, discutida na seção 14.1 deste documento.

### 3.2 Lacuna central: falta uma camada de produto explícita antes do contrato técnico

Na seção 4.8, a linha canônica menciona `source`, mas o primeiro step operacional do exemplo é `spec`. O comando `pwn work specify <source>` também sugere uma fonte anterior sem definir:

- quais formatos de entrada são aceitos e qual artefato tem precedência;
- como ideias ainda imprecisas são transformadas em uma declaração de problema;
- como se diferenciam decisões de produto, regras de negócio, requisitos e decisões de implementação;
- em que ponto o operador aprova o entendimento do problema;
- como o contrato técnico prova que não inventou requisitos ausentes da origem.

O resultado provável é que `pwn work specify` receba uma mistura de pedido, PRD parcial, conversa e suposições de implementação. Isso aumenta o risco de contratos precisos sobre um entendimento impreciso.

A primeira transcrição apresenta explicitamente perguntas, Discovery Notes, stories/requisitos e PRD antes da spec técnica (`9MNKRwKyENs`, 00:09:49–00:28:07). A segunda reforça a separação e a precedência PRD → spec (`stBfp9chHWE`, 00:03:58–00:05:41 e 00:12:19–00:15:56).

### 3.3 Lacuna de rastreabilidade entre os artefatos de planejamento

A `SPEC.md` tem rastreabilidade operacional forte para contratos e evidência de tarefas, mas não estabelece IDs e mapeamentos entre:

```text
necessidade descoberta → user story → requisito → decisão →
cenário de aceitação → seção da spec → sprint/task → evidência final
```

Sem esse mapa, os checks podem assegurar que uma task passou seu contrato local, mas não que todas as intenções e exceções aprovadas chegaram a uma task, ou que a spec não acrescentou comportamento sem origem autorizada.

Esse é exatamente o problema ilustrado na primeira transcrição quando um validador identifica fornecedor divergente e elementos visuais omitidos ao comparar stories/requisitos com Discovery Notes (`9MNKRwKyENs`, 00:20:56–00:27:43). O caso demonstra duas necessidades distintas: **cobertura** (algo necessário ficou de fora) e **consistência** (algo incluído contradiz fonte superior).

### 3.4 Lacuna de qualidade semântica da spec e do plano

A spec atual seleciona a estratégia de validação de implementação, mas não define um gate equivalente para a **qualidade do artefato de especificação** antes de torná-lo input do planner. Também não define um gate para garantir que o plano cobre a spec antes da execução.

A revisão semântica e os checks determinísticos de uma spec precisam identificar, em conjunto, ao menos:

- comportamento descrito sem fonte ou decisão aprovada;
- referências conflitantes entre artefatos;
- critérios de aceite sem cenário observável ou prova executável;
- estados, entradas inválidas, falhas externas e transições omitidas;
- decisões arquiteturais ou de segurança pendentes que bloqueiam uma task;
- UI/UX citada sem fonte de handoff ou sem critérios verificáveis;
- escopo técnico vago demais para gerar uma allowlist e uma cápsula de contexto confiáveis.

A transcrição `9MNKRwKyENs` apresenta essas duas revisões de forma separada: validar PRD → spec (00:38:30–00:40:28) e spec → sprints (00:43:54–00:45:13). É uma separação útil porque cada revisor compara fontes diferentes e pode encontrar classes de falha diferentes.

### 3.5 Inconsistência atual: contrato por task aparece antes da atomização das tasks

A linha canônica e o pipeline de exemplo da seção 4.8 produzem `work_contract` antes de `task_plan`. Porém, o Contract da seção 4.1 contém `task_id`, allowlist, budget, validação e escalações específicas de uma task. Antes da atomização, essas informações ainda não existem de forma confiável.

A revisão deve escolher e documentar uma destas alternativas:

1. **Dois níveis:** congelar primeiro um contrato de governança do Work (risco global, invariantes e limites máximos), gerar o plano e então derivar/congelar um contrato por task.
2. **Plano antes dos contratos:** gerar e validar o plano a partir da spec e só então congelar todos os contratos por task.

A primeira alternativa preserva melhor a intenção atual de governar o planner, mas exige schemas e nomes distintos. Em qualquer alternativa, plano e contrato não podem duplicar campos normativos com valores potencialmente divergentes.

---

## 4. Proposta P0 — Formalizar a cadeia de artefatos anterior à execução

### 4.1 Novo fluxo de engenharia recomendado

No pipeline oficial de engenharia, substituir a descrição resumida por uma cadeia explícita e versionada. Abaixo, adota-se a alternativa de dois níveis de contrato proposta na seção 3.5:

```text
intake
  → discovery
  → requirements
  → product review / PRD
  → technical decisions
  → technical specification
  → specification validation
  → skeptical enrichment
  → work governance contract
  → plan / sprints
  → plan validation
  → task contract freeze
  → plan / task-contract validation
  → task execution
  → deterministic verification
  → acceptance audit
  → learn / metrics
```

Esse é um fluxo canônico do pack `software-engineering`, não uma topologia obrigatória do core para qualquer domínio. A ordem também não exige documentos extensos em todo Work: os gates devem ser **proporcionais ao risco e à complexidade**. Um incidente pequeno ou uma correção isolada pode iniciar em `work governance contract` ou diretamente em uma task já especificada, desde que a policy registre quais etapas foram dispensadas e por quê.

### 4.2 Artefatos propostos e suas responsabilidades

| Artefato | Finalidade | Deve conter | Não deve conter | Gate de saída |
|---|---|---|---|---|
| `intake` | Registrar o pedido bruto e sua fonte | objetivo inicial, solicitante, fontes fornecidas, incertezas, classificação preliminar | decisões inventadas | fonte preservada e escopo da investigação definido |
| `discovery` | Converter o pedido em entendimento verificável do problema | problema, atores, objetivos, contexto existente, restrições, referências, perguntas e respostas aprovadas | desenho técnico detalhado sem decisão | operador aprova o resumo do problema e as premissas |
| `requirements` | Tornar o uso e as regras observáveis | user stories, regras, requisitos funcionais/não funcionais, critérios de produto e exceções conhecidas | estrutura de arquivos e passos de código | revisor confirma cobertura contra discovery |
| `prd` | Consolidar a decisão normativa de produto | problema, público/atores, resultado, escopo, não-objetivos de produto, métricas de sucesso e IDs dos requisitos aceitos | plano de implementação por arquivo ou requisitos paralelos sem status | owner do produto aprova versão |
| `technical-decisions` | Fechar escolhas que afetam a spec e são difíceis de reverter | decisão, contexto, alternativas, recomendação, consequências, aprovador e evidência | implementação completa | decisões bloqueantes resolvidas ou escaladas |
| `technical-spec` | Traduzir produto aprovado em contrato técnico de entrega | comportamento, contratos de fronteira, dados, erros, segurança, UX handoff, estratégia de teste e impactos arquiteturais | discussão bruta e premissas não aprovadas | revisão de spec + operador aprovam |
| `enrichment` | Resolver ambiguidades e caminhos não felizes sem alterar escopo silenciosamente | questões materiais, opções, decisão do operador, mudanças rastreáveis na spec | novas features aprovadas pelo revisor por conta própria | questões materiais resolvidas ou explicitamente adiadas |
| `work-governance` | Governar a decomposição e limitar o Work como um todo | risco global, invariantes, fronteiras máximas, policies e defaults permitidos para tasks | `task_id`, comandos ou allowlists inventados antes do plano | plano pode ser gerado dentro dos limites aprovados |
| `plan` | Decompor a spec aprovada em unidades executáveis | identidades das tasks/sprints, dependências, propósito, referências de origem e sequência | duplicata normativa de comportamento, aceite, risco, budget, allowlist ou checks do contrato por task | revisão confirma cobertura spec → plano |
| `task-contract` | Congelar a ordem de serviço de cada task planejada | os sete contratos v4, `task_id`, `source_refs`, routing, cenários, checks e limites específicos | requisito ou decisão de produto inédita | revisão confirma coerência task → contrato |
| `progress` | Registrar execução e estado real | status por task, evidências, falhas, exceções, revisão e links ao contrato | “concluído” sem prova | auditoria/aceitação final |

### 4.3 Recomendação de organização de arquivos

A estrutura é sugestiva; o caminho final deve respeitar convenções do projeto e não criar uma segunda fonte de verdade para o workflow v3. Uma opção é versionar artefatos de trabalho sob um único diretório:

```text
.piwerness/work/<work-id>/
├── intake.md
├── discovery.md
├── requirements.md
├── prd.md
├── technical-decisions.md
├── spec.md
├── spec-validation.md
├── enrichment.md
├── work-governance.yaml
├── plan.yaml
├── plan-validation.md
├── contracts/
│   └── <task-id>.yaml
├── contract-validation.md
├── progress.yaml
└── evidence/
```

Requisitos para essa estrutura, caso adotada:

1. `work_id`, versão, status e links de rastreabilidade devem estar presentes em todos os artefatos.
2. Aprovação precisa registrar **quem/quando/o quê foi aprovado**, sem registrar dados sensíveis desnecessários.
3. Correções devem gerar histórico ou diff auditável; não se deve reescrever silenciosamente decisões aprovadas.
4. O conteúdo bruto de conversas pode ser referenciado ou guardado fora do Git quando houver privacidade; o artefato versionado deve conter a síntese aprovada, não uma cópia indiscriminada de sessões.
5. O formato pode ser Markdown para leitura e YAML/JSON para campos determinísticos. A escolha deve seguir a decisão atual “YAML para dados estruturados; Markdown para conteúdo textual” (DEC-001).

### 4.4 Alterações concretas sugeridas em `SPEC.md`

- **Seção 3.1:** adicionar um diretório de artefatos de Work, se ele fizer parte da proposta de produto. Caso não faça, declarar que a localização é responsabilidade do pack `software-engineering` e documentá-la na seção 10.
- **Seção 4:** manter o core genérico e declarar `Discovery`, `Requirement`, `Product Requirement Document`, `Technical Decision`, `Specification Review` e `Plan Review` como contratos do pack oficial `software-engineering`, salvo decisão explícita de promovê-los ao core.
- **Seções 4.1 e 4.8:** distinguir `work-governance` de contratos por task e atualizar o pipeline para incluir os gates anteriores ao plano e o congelamento dos contratos após a atomização.
- **Seção 5.1:** acrescentar comandos de leitura/validação/aprovação dos artefatos, ou declarar explicitamente que são subcomandos de `pwn work`.
- **Seção 10.4:** incluir contratos de planejamento acima como evolução v4, mantendo o workflow v3 legível e sem migração automática.
- **Seção 11.2:** inserir fases ou marcos de implementação para os artefatos, revisões e validadores determinísticos de planejamento antes do executor econômico.

---

## 5. Proposta P0 — Revisões isoladas de cobertura, consistência e completude

### 5.1 Princípio recomendado

Cada transformação relevante deve ter um revisor cujo input seja o artefato anterior e o artefato produzido. O papel desse revisor é detectar perdas, contradições, ambiguidades e comportamento não fundamentado; ele **não deve aprovar automaticamente nem reescrever decisões de produto**.

O uso de um contexto isolado — e, quando útil, outro agent/modelo — reduz a repetição da mesma hipótese do gerador, mas não produz independência forte nem prova determinística. Por isso, o documento usa “revisão” para análise semântica por LLM e reserva “validação determinística” para schemas, referências, estados e invariantes verificáveis por código. A decisão final para lacunas materiais continua sendo humana ou escalada pela policy.

### 5.2 Gates mínimos propostos

| ID sugerido | Comparação | Verifica | Saída mínima | Ação em falha |
|---|---|---|---|---|
| `GATE-DISC-REQ` | Discovery → Requirements | cobertura de objetivos, atores, restrições e referências; ausência de requisito não autorizado | matriz de cobertura + conflitos | retorna para requirements ou solicita decisão |
| `GATE-REQ-PRD` | Requirements → PRD | PRD preserva escopo, critérios e não cria promessa nova | gaps, contradições, IDs sem destino | retorno ao PRD/requirements |
| `GATE-PRD-SPEC` | PRD + decisões → Technical Spec | cada requisito tem comportamento técnico, caso negativo relevante, critério verificável e fronteiras técnicas aplicáveis | relatório por requisito/decisão | bloqueia aprovação da spec se houver lacuna material |
| `GATE-SPEC-PLAN` | Technical Spec + Work Governance → Plan | todas as seções entregáveis têm task; dependências, ordem e decomposição respeitam a governança | rastreabilidade spec→task + tasks órfãs | bloqueia congelamento dos contratos enquanto o plano estiver incompleto |
| `GATE-PLAN-CONTRACT` | Task + Work Governance → Task Contract | limites de escrita, validação, budget e risco realizam o que a task promete e não excedem o Work | divergências de contrato | exige correção do contrato, replanejamento ou escalação |
| `GATE-DELIVERY` | Task Contract + plan → patch/evidence | entrega e provas atendem ao contrato sem escopo adicional | candidato de aceitação | retorna ao executor ou escala |

### 5.3 Formato de saída recomendado para todos os gates

Para permitir automação, comparação entre runs e decisões consistentes, cada gate — combinando revisão semântica e validações determinísticas aplicáveis — deveria produzir um formato estruturado equivalente a:

```yaml
gate: GATE-PRD-SPEC
work_id: "0037"
input_versions:
  prd: 2
  technical_decisions: 1
  spec: 3
result: blocked # pass | pass_with_notes | blocked
summary:
  covered: 18
  gaps: 2
  conflicts: 1
  ambiguities: 3
findings:
  - id: FIND-001
    severity: high # low | medium | high | critical
    type: coverage_gap # coverage_gap | conflict | ambiguity | unverifiable_acceptance
    source_refs: ["REQ-014", "PRD §4.2"]
    target_refs: []
    description: "A regra de autorização não possui comportamento de erro definido."
    required_resolution: "Definir resposta observável e critério de aceite ou remover a promessa aprovada."
    resolution_owner: product-owner # papel responsável definido pelo pack/policy
    status: open
```

Observações de governança:

- `pass_with_notes` só pode ser aceito se as notas não forem materiais segundo a policy definida.
- A severidade precisa considerar risco. Uma ambiguidade cosmética não é equivalente a uma ambiguidade sobre dados, autorização, dinheiro ou destruição de informação.
- A origem de cada finding deve referenciar IDs/trechos reais, não apenas comentários livres.
- Uma revisão semântica por LLM não deve ser tratada como prova isolada. O gate só pode resultar em `pass` após executar também os checks determinísticos aplicáveis e respeitar as aprovações exigidas pela policy.

### 5.4 Matriz de rastreabilidade recomendada

Manter uma matriz canônica por Work, referenciada por PRD, spec e plano, que permita detectar perdas e acréscimos não autorizados sem duplicar tabelas divergentes:

| Origem | Requisito | Decisão técnica | Seção da spec | Task/sprint | Contrato | Evidência de aceitação | Estado |
|---|---|---|---|---|---|---|---|
| `DISC-007` | `REQ-014` | `TD-003` | `SPEC-API-004` | `TASK-2.3` | `CTR-2.3` | `EVD-2.3-01` | planejado |

Essa tabela deve ter IDs estáveis. A presença de IDs não elimina revisão humana, mas torna possível responder objetivamente:

- “qual necessidade justificou esta task?”;
- “qual requisito ainda não foi planejado?”;
- “qual decisão torna esta task dependente de outra?”;
- “qual evidência demonstrou que a promessa foi atendida?”

### 5.5 Critérios de qualidade para a spec técnica

Além da validação de cobertura, recomenda-se publicar um checklist/validador de qualidade da spec. Para cada requisito relevante, exigir que a spec responda:

1. **Gatilho:** o que inicia a ação/evento?
2. **Pré-condições:** quais estados, permissões ou dados são necessários?
3. **Caminho normal:** qual resultado externo é esperado?
4. **Alternativas e falhas:** que resposta ocorre para entrada inválida, indisponibilidade, conflito de estado, cancelamento ou timeout quando aplicável?
5. **Persistência e efeito:** o que é criado, modificado, enviado ou preservado?
6. **Contratos de fronteira:** quais entradas e saídas são observáveis por UI, API, arquivo, CLI ou evento?
7. **Aceitação:** como alguém demonstra o resultado sem inferir pelo código?
8. **Risco:** o que exige revisão forte/humana, estratégia superior ou escalonamento?
9. **Fora do escopo:** o que está explicitamente proibido para evitar expansão silenciosa?

Essa proposta deriva do foco das transcrições em caminhos alternativos e critérios verificáveis (`stBfp9chHWE`, 00:16:05–00:19:18), mas a transforma em um contrato apropriado ao Piwerness.

---

## 6. Proposta P0 — Enriquecimento cético, com perguntas materiais e resolução controlada

### 6.1 Problema

Uma spec pode estar consistente com o PRD e ainda ser insuficiente: o PRD pode não ter decidido o que acontece em estados concorrentes, falhas, cancelamentos, reprocessamentos, limites ou permissões. O caminho feliz costuma ser o primeiro a aparecer, enquanto os defeitos mais caros ficam nos caminhos laterais.

A primeira transcrição introduz um “enricher” cético para questionar, por exemplo, deleção durante streaming (`9MNKRwKyENs`, 00:40:28–00:42:24). Esse papel é complementar ao gate de cobertura: ele não apenas verifica se a spec preservou a fonte, mas tenta localizar o que as fontes ainda não decidiram.

### 6.2 Proposta de primitiva/papel

Adicionar o papel `spec-enricher` ou `adversarial-reviewer` ao pack `software-engineering`, com as seguintes restrições:

- recebe a spec validada, PRD, decisões e matriz de rastreabilidade; não recebe conversa irrestrita como única fonte;
- classifica cada observação como `ambiguity`, `missing_failure_mode`, `state_transition`, `security/privacy`, `operability`, `UX/accessibility`, `data_lifecycle` ou `testability`;
- formula perguntas curtas, concretas e materialmente relevantes, com as consequências de cada opção;
- **não altera automaticamente** requisito, escopo, risco ou decisão técnica;
- só aplica uma alteração após decisão explícita do operador/owner ou regra política previamente autorizada;
- cria uma nova versão da spec e atualiza a matriz quando uma decisão for incorporada;
- usa limite de questões/rounds, budget e escalonamento como os demais agentes.

### 6.3 Perguntas orientadoras por categoria

O reviewer cético não deve gerar uma lista genérica infinita. Ele deve consultar somente as categorias acionadas pelo domínio e risco:

| Categoria | Perguntas exemplares |
|---|---|
| Estado e concorrência | O que ocorre se a mesma ação for repetida? Pode haver duas execuções simultâneas? Qual operação vence ou é rejeitada? |
| Entrada e erros | O que o consumidor observa com entrada ausente, inválida, fora de limite ou incompatível? |
| Integrações | Há timeout, indisponibilidade, resposta parcial, retry ou duplicação? Que efeito fica persistido? |
| Dados | Há criação, edição, retenção, remoção, exportação, auditoria ou dado sensível? |
| Autorização | Quem pode iniciar, ler, alterar ou aprovar cada ação? O que é visível para não autorizados? |
| UX | Qual estado de carregamento, bloqueio, cancelamento, feedback e recuperação é esperado? |
| Operação | Qual comportamento ocorre se um check falhar, budget acabar, runtime estiver indisponível ou a fila for retomada? |
| Compatibilidade | O que clientes/artefatos existentes precisam continuar consumindo? |

### 6.4 Gate e resultado

A etapa termina em uma de quatro saídas explícitas:

- `resolved`: decisão incorporada à spec, com IDs e versão atualizados;
- `accepted_risk`: owner decidiu não tratar agora; risco e justificativa permanecem visíveis;
- `deferred`: item foi movido para Work futuro, sem contaminar a entrega corrente;
- `blocked`: sem uma decisão, não é seguro/plausível gerar contrato ou executar a task.

Essa distinção evita que uma pergunta não respondida desapareça em texto narrativo e evita que o enriquecedor infle a primeira versão com funcionalidades não solicitadas.

---

## 7. Proposta P1 — Tratar referências de UX/UI como contrato de primeira classe

### 7.1 Oportunidade

A transcrição `9MNKRwKyENs` descreve um fluxo “frontend-first” no qual um mockup/handoff funciona como referência de implementação, e alerta para não substituir decisões de design já definidas por uma interpretação nova do agente (00:05:13–00:08:27; 00:17:19–00:19:32; 00:32:02–00:34:18).

A spec atual já tem `visual-contract`, mas falta especificar como uma referência visual entra no Work, como é versionada e como seus componentes viram requisitos testáveis. Sem isso, há o risco de o pipeline ter screenshots soltas, prompts longos ou uma referência de design contraditória com a spec.

### 7.2 Artefato `UX Handoff Manifest` proposto

Para Works que alteram interface, introduzir um manifesto estruturado que referencia, sem duplicar, o handoff autorizado:

```yaml
ux_handoff:
  id: UX-001
  source:
    type: exported_bundle # exported_bundle | figma | screenshot_set | existing_ui
    reference: "URI ou caminho resolvível para a referência"
    revision: "hash do conteúdo ou revisão do VCS"
  authority: approved_reference # approved_reference | directional_reference
  scope:
    surfaces: [conversation, activity-panel]
    states: [empty, loading, streaming, error, collapsed]
  invariants:
    - "Não redesenhar tokens, paleta ou hierarquia visual aprovados."
    - "O painel pode colapsar sem ocultar o caminho de reabertura."
  behavioral_bindings:
    - visual_state: streaming
      trigger: EVT-STREAM-START
      completion: EVT-STREAM-COMPLETE
  verification:
    required_screenshots:
      - empty
      - streaming
      - error
      - collapsed
    viewport_profiles: [desktop-default]
  exceptions:
    - "Conflitos entre fidelidade visual e requisitos de acessibilidade exigem decisão explícita; acessibilidade normativa não pode ser rebaixada silenciosamente."
```

A implementação precisa manter a referência externa resolvível e não tentar embutir arbitrariamente um bundle enorme na spec. O manifesto aponta a referência, sua revisão, autoridade e escopo.

### 7.3 Expansão de `visual-contract`

A seção 4.3 poderia exigir que `visual-contract` declare:

1. fonte da verdade visual e sua versão;
2. telas/componentes e estados cobertos;
3. viewport, tema e dados determinísticos de demonstração;
4. comportamentos ligados a estados de UI (carregamento, streaming, erro, vazio, seleção, permissão, colapso);
5. expectativas acessíveis observáveis quando aplicáveis;
6. screenshots obrigatórios e inspeção humana direta;
7. política para diferenças permitidas e para divergências bloqueantes.

A captura não é suficiente por si só. A aceitação visual deve combinar screenshot, estado funcional real e inspeção humana nos casos em que a fidelidade visual seja requisito do produto.

### 7.4 Restrições de desempenho observáveis

A primeira transcrição chama atenção para interfaces com updates frequentes e risco de degradação por re-renderização em cascata (`9MNKRwKyENs`, 00:17:34–00:18:47). Em vez de codificar recomendações específicas de framework na spec global, a melhoria recomendada é:

- permitir que a technical spec declare um **orçamento de responsividade** quando o produto tiver streaming, listas extensas, visualizações em tempo real ou eventos de alta frequência;
- definir o método de medição (por exemplo, cenário reproduzível, métricas do navegador ou teste de carga de eventos) somente quando houver uma exigência confirmada;
- ligar esse orçamento a uma estratégia de validação e não aceitar a alegação “otimizado” sem evidência;
- não inventar um valor numérico universal. O valor depende do produto, ambiente e hardware alvo.

---

## 8. Proposta P1 — Revisão de decisões técnicas por especialidade, sem burocracia universal

### 8.1 O que adicionar

A `SPEC.md` descreve sub-agents especializados, mas a fase de decisões anterior à implementação ainda não tem um protocolo explícito para um especialista examinar impactos e opções. As transcrições mostram discussões separadas de banco de dados, backend, frontend e segurança (`9MNKRwKyENs`, 00:28:51–00:36:40).

A recomendação não é tornar todo Work um comitê de arquitetura. É usar uma policy de gatilhos, por exemplo:

| Gatilho no Work | Revisão requerida |
|---|---|
| schema, migração, retenção, consistência ou recuperação de dados | dados/persistência |
| nova fronteira HTTP/evento/arquivo público ou compatibilidade | API/integração |
| identidade, permissão, segredo, dados pessoais ou exposição de rede | segurança/privacidade |
| alteração de fluxo crítico de UI ou contrato visual | UX/acessibilidade + visual |
| novo runtime/adaptador/materialização | compatibilidade de runtime |
| alteração interna localizada e de risco L0/L1 sem gatilho | nenhuma revisão especializada adicional, salvo escalonamento |

### 8.2 Formato recomendado de uma decisão

Adicionar um registro de decisão por Work, diferente do registro global de decisões de `SPEC.md`:

| Campo | Conteúdo obrigatório |
|---|---|
| ID | `TD-001`, estável dentro do Work |
| Contexto | problema e requisito(s) que motivam a decisão |
| Opções consideradas | alternativas concretas e limites conhecidos |
| Decisão | opção escolhida ou decisão de adiar |
| Consequências | impacto em comportamento, risco, compatibilidade, operação e testes |
| Dono/aprovação | papel responsável e data da decisão |
| Evidência | fontes locais, testes, contratos ou decisão explícita |
| Impacto de implementação | seções da spec e tasks afetadas |

A decisão deve ser curta e orientada ao comportamento. Não deve virar uma cópia de discussões longas nem uma justificativa posterior para escolhas já implementadas.

### 8.3 Segurança proporcional ao contexto

A primeira transcrição mostra tanto a utilidade de uma revisão de segurança quanto o risco de aplicar controles genéricos sem pertinência ao produto. A `SPEC.md` já possui Risk Policy L0–L4. A melhoria é tornar explícito que:

- reviews de segurança devem partir da fronteira e do modelo de ameaça declarado, não de uma checklist universal;
- “local” não significa automaticamente “sem risco”; escopo de rede, acesso a filesystem, logs, permissões e dados processados precisam ser considerados quando aplicáveis;
- controles sem objetivo ou risco rastreável não entram na v1 só porque um especialista os sugeriu;
- omitir um controle de alto risco exige `accepted_risk` documentado, não uma remoção silenciosa.

---

## 9. Proposta P1 — Plano/sprints como contrato de entrega verificável

### 9.1 Problema

A `SPEC.md` fala em atomizar tasks e executar `foreach`, mas não define a semântica de uma sprint/plano suficientemente para impedir:

- uma task sem requisito de origem;
- requisito sem task;
- task que muda vários contratos independentes;
- ordem que tenta consumir uma interface ainda não produzida;
- critério de aceite repetido ou ausente;
- executor especializado inadequado para o tipo de alteração;
- Work cujo progresso foi atualizado, mas não tem evidência de conclusão.

### 9.2 Campos mínimos sugeridos por sprint/task

O plano deveria materializar apenas a decomposição e referenciar, sem duplicar, o contrato normativo de cada task:

```yaml
id: "TASK-2.3"
title: "..."
purpose: "Resultado observável entregue por esta unidade."
source_refs: ["REQ-014", "SPEC-API-004", "TD-003"]
depends_on: ["TASK-2.1"]
contract_id: "CTR-2.3"
```

Comportamento, cenários de aceite, casos negativos, agent/routing, risco, validation strategy, budget, allowlist, checks, evidência exigida e `out_of_scope` ficam no contrato por task depois de congelados. Antes disso, `contract_id` é apenas o identificador reservado para a derivação; não indica que o contrato já foi aprovado. Se o planner sugerir campos contratuais, as sugestões devem ser claramente marcadas como draft e removidas do plano canônico após `GATE-PLAN-CONTRACT`. Não é necessário escolher YAML para todos os documentos, mas esses campos devem ser serializáveis e validados. O conteúdo narrativo pode continuar em Markdown.

### 9.3 Definition of Done por task

A seção 4.1 já define Acceptance Contract. Recomenda-se explicitar uma Definition of Done mínima, versionada e não relaxável silenciosamente após o início da execução. Qualquer mudança deve pausar a task, produzir nova versão e passar pelas aprovações aplicáveis:

1. implementação limitada ao Change/Scope Contract aceito;
2. cenários de aceite e casos negativos planejados foram demonstrados ou receberam evidência de N/A com justificativa válida;
3. comandos/checks declarados foram executados e a saída foi registrada;
4. mudanças de contrato, expansão de escrita, tentativa excedida ou limite de budget foram escaladas, não escondidas;
5. auditoria de diff confirma que não houve trabalho fora de escopo;
6. rastreabilidade de `source_refs` até `completion_evidence` está completa;
7. status em `progress` foi atualizado somente após os itens anteriores.

### 9.4 Planejamento por contexto limpo

Manter a recomendação de capsules pequenas, mas explicitar que:

- cada task deve iniciar em sessão isolada ou com contexto controlado pelo adapter;
- o capsule deve incluir apenas as referências necessárias, não a spec inteira quando ela não for relevante;
- decisões e interfaces compartilhadas devem ser apontadas por links/IDs e resumidas no capsule;
- se uma task exigir leitura adicional, a solicitação deve registrar o motivo; se exigir escrita adicional, deve seguir o Change Contract já especificado.

Isso reforça o princípio da seção 10.5 e responde à preocupação das duas transcrições com a perda de precisão em contexto excessivo.

---

## 10. Proposta P2 — Evoluir métricas de economia para métricas de qualidade do processo

### 10.1 Cobertura atual

As métricas atuais capturam muito bem custo, tokens, duração, tentativas, escalonamentos, violações de escrita e pass rate (seções 4.12 e 8.1). Isso é necessário, mas não suficiente para otimizar o processo de planejamento proposto acima.

### 10.2 Métricas adicionais recomendadas

| Métrica | Granularidade | Pergunta respondida |
|---|---|---|
| `requirements_coverage_rate` | Work/versão | Quantos requisitos aprovados chegaram a uma task e evidência? |
| `untraced_change_count` | Work/task | Quantas mudanças não possuem requisito/decisão de origem? |
| `gate_findings_by_stage` | etapa/agent | Em que transformação surgem mais lacunas ou conflitos? |
| `spec_rework_rounds` | spec/Work | Quantas revisões foram necessárias até a aprovação? |
| `question_resolution_time` | finding material | Onde a decisão humana bloqueia o fluxo e por quê? |
| `post_acceptance_defects` | Work/release | Que defeitos escaparam da aceitação e a qual requisito/spec/task se ligam? |
| `acceptance_scenario_pass_rate` | risco/estratégia | A estratégia escolhida evidencia cenários suficientes? |
| `visual_regression_findings` | superfície/UI | Quais estados visuais mais divergem do handoff? |
| `plan_churn_after_execution` | plano/Work | O planejamento foi instável ou o executor expandiu indevidamente o escopo? |
| `human_override_rate` | policy/agent | Onde a automação recomenda decisões que o operador frequentemente rejeita? |

### 10.3 Cuidados de interpretação

- Uma taxa menor de rework não prova qualidade sozinha; pode indicar que gaps não foram encontrados.
- Uma spec mais longa não é automaticamente melhor. A medida relevante é se reduz ambiguidades materiais e melhora a aceitação sem expandir contexto sem necessidade.
- Métricas não devem induzir autoalteração de policy. Assim como a seção 8.2 já propõe, elas devem gerar recomendações revisáveis pelo operador.
- Dados de sessões, prompts ou logs podem conter informação sensível; métricas devem registrar agregados e referências, com promoção manual/sanitizada quando necessário.

---

## 11. Proposta P2 — Capabilities de runtime e afirmações que exigem verificação

### 11.1 Ponto de atenção

A `SPEC.md` contém afirmações específicas sobre invocação e materialização de runtimes, por exemplo flags do Pi, comandos headless de OpenCode/omp e o nível de suporte a sub-agents (seções 4.8 e 6). Como o repositório não contém implementação nem testes dos adapters, essas afirmações devem ser tratadas como requisitos de produto a validar, não como capacidades já comprovadas.

As transcrições reforçam uma lição relevante: uma referência de UI, stack ou ferramenta pode carregar detalhes que não correspondem à decisão final. Um exemplo é a divergência entre um provider mostrado no mockup e o provider escolhido no produto (`9MNKRwKyENs`, 00:23:23–00:27:43).

### 11.2 Melhoria recomendada

Adicionar ao core uma capability matrix por runtime/versão observada:

```yaml
runtime: pi
observed_version: "<versão observada>"
capabilities:
  print_mode:
    status: verified | unsupported | unknown
  system_prompt_override:
    status: verified | unsupported | unknown
  skills:
    status: verified | unsupported | unknown
  extension_loading:
    status: verified | unsupported | unknown
  isolated_session_directory:
    status: verified | unsupported | unknown
  structured_usage_metrics:
    status: verified | unsupported | unknown
  subagent_execution:
    status: verified | unsupported | unknown
    mode: emulated | native | null
verification:
  command_or_fixture: "caminho para teste de contrato"
  executed_at: "timestamp"
```

Regras propostas:

1. Materialização deve falhar ou degradar de forma explícita quando um campo do profile/contrato não for representável pelo target.
2. Nenhum campo de segurança, escopo, budget ou aceitação pode ser descartado silenciosamente na tradução.
3. O `dry-run` deve mostrar quais capacidades foram verificadas, emuladas, não suportadas ou desconhecidas.
4. Testes de contrato do adapter devem confirmar a invocação contra versão instalada ou fixture estável antes de a documentação afirmar suporte completo.
5. A compatibilidade deve ser versionada; “funciona em Pi/OpenCode/omp” é amplo demais sem faixa/versionamento observado.

---

## 12. Ajuste de fases de implementação recomendado

A seção 11.2 poderia ser reorganizada para reduzir o risco de construir executor e contrato antes de saber qual cadeia de entrada ele governa.

### Proposta de sequência

| Fase proposta | Resultado | Relação com as fases atuais |
|---|---|---|
| 1. Port fiel do workflow v3 | Pack independente preserva contratos e evidência existentes | preserva Fase 1 atual |
| 2. CLI `pwn` sobre o pack v3 | Entry points v3 funcionam antes de ampliar o modelo | preserva Fase 2 atual |
| 3. Baseline de artefatos e revisões de Work | Intake, Discovery, Requirements, PRD, decisões, rastreabilidade, schema do plano e contratos dos gates | nova, antes do Contract Engine v4 |
| 4. Contract Engine v4 | `work-governance`, contratos por task derivados do plano, gates Spec→Plan→Contract e validation strategies | Fase 3 atual, com ordem e fontes de verdade explícitas |
| 5. Executor econômico e escalonamento | Worktree, routing, queue, checks e acceptance | Fase 4 atual |
| 6. Adapters e sub-agents multi-runtime | Capability matrix + materialização sem perda silenciosa | Fase 5 atual, reforçada |
| 7. Editor visual | Editor de pipeline offline; opcionalmente navegação de rastreabilidade | Fase 6 atual |
| 8. Métricas e teach skills | Métricas de custo e qualidade do processo; aprendizagem revisável | Fase 7 atual, expandida |

Essa ordem preserva o valor incremental e não condiciona o CLI v3 a um sistema completo de PRD. O objetivo é garantir que as capacidades novas v4 sejam projetadas sobre artefatos e decisões rastreáveis, em vez de aceitar texto livre como contrato definitivo.

---

## 13. Sugestões de comandos CLI — a validar no design do CLI

A lista abaixo é uma proposta de superfície; não deve ser adicionada como contrato final sem definir sintaxe, saídas, erros e compatibilidade com os comandos v3.

```text
# Entrada e descoberta
pwn work intake <source>
pwn work discover <work>
pwn work requirements <work>
pwn work prd <work>
pwn work decision <work>

# Revisão e aprovação
pwn work validate requirements <work>
pwn work validate spec <work>
pwn work enrich <work>
pwn work validate plan <work>
pwn work approve <work> <artifact>
pwn work findings <work> [--stage <stage>]

# Rastreabilidade e evidência
pwn work trace <work> <id>
pwn work coverage <work>
pwn work progress <work>
```

Requisitos mínimos para qualquer um desses comandos:

- deve operar sobre um Work identificado, sem inferir artefato por nome ambíguo;
- deve informar entradas, versões e artefato de saída;
- deve retornar código não zero quando um gate material bloqueia o avanço;
- não deve marcar artefato como aprovado por timeout ou aprovação implícita;
- deve permitir inspeção humana dos findings antes de aplicar correções;
- deve respeitar o princípio atual de não executar instalação, deploy, publicação ou mudança remota como efeito oculto.

---

## 14. Pontos das transcrições que **não** devem ser incorporados literalmente

### 14.1 Remoção de escopo negativo naquele exemplo — não generalizar ao Piwerness

Na transcrição `9MNKRwKyENs` (00:43:04–00:43:52), o narrador considera inútil a seção de escopo negativo daquela spec e a remove para economizar contexto. Aplicar essa escolha ao Piwerness conflitaria diretamente com seu Change/Scope Contract e com o enforcement mecânico de allowlist.

**Recomendação:** preservar `out_of_scope`, `write_allow` e `write_deny`. Para reduzir contexto, o Piwerness pode gerar uma cápsula concisa e estruturada, mas não deve eliminar limites explícitos. Para um executor barato ou autônomo, saber o que não fazer é uma proteção contra expansão de escopo, refactors não solicitados e custo imprevisível.

### 14.2 Números de linhas, duração e thresholds genéricos — não normatizar

As fontes mencionam documentos de centenas de linhas, horas de planejamento e números de rounds. Isso ilustra que planejamento tem custo, mas não estabelece um limiar universal.

**Recomendação:** não adotar regras como “spec acima de cinco arquivos”, “800 linhas” ou “cinco rounds” como política global. Usar risk level, domínio, complexidade de interface, dependências e métricas históricas para calibrar budgets e gates.

### 14.3 JSON como formato superior a Markdown — não adotar como dogma

A segunda transcrição recomenda JSON para sprints como preferência do autor (`stBfp9chHWE`, 00:14:00–00:23:35), mas afirma que Markdown também funciona. A `SPEC.md` já decide corretamente YAML para estrutura e Markdown para texto.

**Recomendação:** preservar DEC-001. Adicionar schema/validação a dados do plano e contratos é mais importante do que mudar todo documento para JSON.

### 14.4 Um agente especializado como garantia de qualidade — qualificar

Especialistas por domínio podem melhorar foco, mas sua qualidade depende de contexto, contratos, capacidade real de tools, avaliações e evidência. Um sub-agent não deve ser considerado “validado pessoalmente” como justificativa suficiente para ignorar checks.

**Recomendação:** manter o pipeline como fonte de controle: role/agent é escolha declarativa; contratos, validação determinística e auditoria continuam obrigatórios conforme risco.

### 14.5 “Tudo é possível” em qualquer runtime — não assumir

Os vídeos citam ferramentas e fluxos como intercambiáveis. O Piwerness precisa, ao contrário, materializar apenas capacidades realmente suportadas e registrar degradação/limites por adapter, conforme a proposta da seção 11 deste documento.

---

## 15. Itens que requerem decisão do produto antes de editar a spec principal

Não são perguntas de implementação; são decisões que mudam a fronteira do Piwerness ou seu modelo de governança. Recomenda-se resolvê-las no registro de decisões antes de consolidar a revisão.

| ID sugerido | Decisão necessária | Alternativas e efeito |
|---|---|---|
| `DEC-022` | O Piwerness passa a ser responsável por gerar/operar Discovery, Requirements e PRD, ou apenas aceita esses artefatos produzidos externamente? | **Nativo:** maior rastreabilidade ponta a ponta, maior escopo do pack. **Importável:** core menor, mas integrações/formato de entrada devem ser definidos. **Híbrido:** gera templates e valida imports, provavelmente o melhor equilíbrio inicial. |
| `DEC-023` | Quais gates exigem aprovação humana obrigatória? | Pelo menos PRD, decisões de alto risco, spec com gaps materiais e mudanças de contrato/escrita parecem candidatos. Exigir aprovação em tudo reduz autonomia; liberar tudo remove a barreira contra invenção. |
| `DEC-024` | Onde ficam os artefatos de Work e como coexistem com o layout de Works v3? | Deve evitar duas fontes de verdade, preservar projetos existentes e permitir que v3 e v4 coexistam sem migração automática. |
| `DEC-025` | Qual o status normativo de um UX handoff? | Pode ser referência obrigatória, direcional ou apenas inspiração. Sem esse status, não há critério para decidir entre fidelidade, redesenho e acessibilidade. |
| `DEC-026` | Como o sistema trata finding material não resolvido? | Bloquear, exigir `accepted_risk`, ou permitir adiar com referência a Work futuro. A decisão deve variar por risco, mas não pode ser implícita. |
| `DEC-027` | Qual é o contrato mínimo e versionado das revisões e validações de planejamento? | Necessário para adapters, métricas e gates interoperarem sem depender de texto livre de um agente. |
| `DEC-028` | Há contrato de governança do Work separado dos contratos por task, ou o plano precede todos os contratos? | Deve resolver a inconsistência `work_contract` antes de `task_plan`, definir a fonte normativa de cada campo e impedir duplicação divergente entre plano e contrato. |

---

## 16. Plano de edição recomendado para a próxima versão da `SPEC.md`

Uma revisão controlada poderia ser feita em duas versões para não misturar decisões de produto com detalhamento de implementação.

### Versão 1.1 — Governança de planejamento

1. Atualizar o resumo executivo para mencionar a cadeia governada Discovery → PRD → Spec → Plan, sem prometer implementação já concluída.
2. Acrescentar princípios de design:
   - separação entre intenção de produto e instrução técnica;
   - rastreabilidade entre artefatos;
   - revisão semântica com contexto isolado e validação determinística quando aplicável;
   - resolução explícita de ambiguidades materiais.
3. Incluir as primitivas/artefatos de planejamento no pack `software-engineering`.
4. Atualizar o pipeline de engenharia da seção 4.8 e o exemplo com outputs e gates anteriores ao plano.
5. Distinguir o contrato de governança do Work dos contratos por task, congelados após a atomização, sem duplicar campos normativos no plano.
6. Acrescentar contratos de `finding`, aprovação e uma matriz canônica de rastreabilidade por Work.
7. Acrescentar a revisão cética e a regra de que ela não altera escopo automaticamente.
8. Atualizar riscos e mitigações para contemplar omissão entre documentos, aprovação implícita e expansão de requisitos por revisor.
9. Registrar as novas decisões resolvidas e os gaps que ainda dependerem de validação.

### Versão 1.2 — UX, capabilities e métricas

1. Introduzir `UX Handoff Manifest` e expandir o `visual-contract`.
2. Adicionar capability matrix e política de materialização sem perda silenciosa.
3. Expandir schema de métricas para qualidade do planejamento e rastreabilidade.
4. Revisar fases de implementação para acomodar revisões e validadores determinísticos antes do Contract Engine v4.
5. Definir fixtures/testes de contrato para os novos formatos e adapters.

### Critérios de aceite da própria revisão de spec

A versão revisada só deve ser considerada pronta quando:

- cada novo artefato possuir finalidade, entrada, saída, owner, versão e gate definidos;
- todo gate tenha resultado estruturado, comportamento de bloqueio e caminho de resolução;
- PRD, spec, plano, contratos por task e evidência tenham rastreabilidade por IDs e fonte normativa inequívoca;
- a policy declare quando se pode pular etapas para tarefas pequenas e quem autoriza isso;
- o enriquecimento não possa introduzir novas features silenciosamente;
- UX handoffs tenham autoridade e modo de verificação definidos quando houver UI;
- nenhuma capability de runtime seja declarada suportada sem prova/fixture/versionamento;
- os contratos v3 permaneçam preservados e v4 não exija migração automática;
- a documentação diferencie claramente comportamento futuro especificado de comportamento já implementado/verificado.

---

## 17. Conclusão

A principal melhoria sugerida não é adicionar mais agentes ou tornar o pipeline mais longo por padrão. É tornar explícito o que pode existir entre `source` e `spec` nos Works de engenharia que exigem descoberta, formando uma **cadeia verificável de decisões** em que cada camada responde uma pergunta distinta:

```text
Discovery:       qual problema, para quem e sob quais restrições?
Requirements:    o que o usuário e o sistema precisam observar?
PRD:             qual resultado de produto foi aprovado?
Spec:            que comportamento técnico entrega esse resultado?
Enrichment:      o que ficou ambíguo fora do caminho feliz?
Work Governance: quais limites globais governam a decomposição?
Plan:            como a entrega será decomposta sem perder cobertura?
Task Contract:   o que cada executor pode fazer e provar?
Evidence:        o que demonstra que a entrega ocorreu dentro dos limites?
Metrics:         como melhorar o processo a partir de resultados reais?
```

Essa ampliação é compatível com a tese central do Piwerness: modelos fortes decidem e auditam; executores baratos trabalham sob contratos restritos; revisões, validações determinísticas e evidências substituem confiança implícita. Ela torna a origem desses contratos tão governada quanto a execução que eles controlam, sem impor Discovery/PRD ao core inteiro.
