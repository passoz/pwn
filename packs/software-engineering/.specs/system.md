# SYSTEM SPEC: AI Engineering Skills Suite

**Status:** Baseline parcial
**Versão:** 1
**Última reconciliação:** 2026-08-19
**Escopo da baseline:** contrato de evidência RED/GREEN, validação estrutural de planos e integridade do fluxo make-*.

## Propósito e resultados sistêmicos

**Problema sistêmico:** Agentes de IA produzem evidências de implementação não verificáveis de forma independente, planos com contratos ambíguos e trabalho que não pode ser auditado mecanicamente.

**Resultado sistêmico:** A suite produz artefatos determinísticos — prompts, planos, evidências RED/GREEN e candidatos de aceitação — que qualquer supervisor externo pode verificar sem repetir o trabalho do agente.

## Fronteira do sistema

### Dentro da fronteira

- Reserva e indexação de Work IDs.
- Criação e validação estrutural de prompts de mudança.
- Criação e validação de planos de tarefas com contrato versionado.
- Captura determinística de evidências baseline, RED, GREEN, verify e audit checks.
- Geração de candidatos de aceitação com hash de plano e evidências.
- Validação do grafo de dependências entre planos.

### Fora da fronteira

- Execução de agentes de IA (Pi, OpenCode, CLI configurável).
- Assinatura criptográfica de candidatos.
- Sincronização com issues externas (GitHub, etc.).
- Deploy, publicação ou push para repositórios remotos.

## Atores e sistemas externos

- **ACT-001 — Agente executor:** executa tarefas, produz evidências e candidatos de aceitação dentro dos contratos da suite. **Evidência:** `adapters/pi/prompts/make-task.md`, `skills/engineering-workflow/references/execute-task.md`.
- **ACT-002 — Operador:** configura projetos, aprova ações perigosas e invoca os adaptadores make-*. **Evidência:** `README.md`, `docs/manual-suite.md`.
- **ACT-003 — Supervisor externo:** verifica evidências e candidatos de forma independente sem acesso ao agente. **Evidência:** `CONTEXT.md` (Acceptance Candidate).

## Capacidades sistêmicas

### CAP-001 — Capturar evidência RED/GREEN verificável

**Valor:** Garante que cada mudança comportamental tenha evidência determinística de que o teste falhou pela assertion nova antes da implementação e passou com ela, suportando verificação independente.

**Atores:** `ACT-001`, `ACT-003`.

**Comportamento:** O agente registra baseline dos arquivos, executa o RED com o teste novo e a implementação no estado anterior, verifica que a falha contém o expect da assertion, congela o teste, implementa, verifica GREEN com teste congelado e diff de produção, e executa mutation check que reverte a implementação e confirma que o expect da assertion reaparece.

**Falhas e limites:** RED que falha por erro de ambiente ou toolchain sem exercitar a assertion nova é rejeitado. Ausência de diff de implementação entre baseline e GREEN é rejeitada. Teste alterado após RED invalida o GREEN.

**Regras relacionadas:** `BR-001`, `BR-002`, `BR-003`.

**Contratos relacionados:** `CON-001`.

**Evidência:** `scripts/task_evidence.js`, `tests/task_evidence.test.js`.

### CAP-002 — Validar estrutura de plano de tarefas

**Valor:** Garante que todo plano seja executável, atômico, rastreável e com contratos sem ambiguidade antes da execução.

**Atores:** `ACT-001`, `ACT-002`.

**Comportamento:** O validador analisa o plano contra o contrato v3 atual: Work ID, contrato de execução, campos obrigatórios, limite de atomicidade, RED único com descrição de failure por assertion, ACs concretos, segurança de comandos e dependências válidas.

**Falhas e limites:** RED com descrição que indica falha de ambiente (ausência de módulo, arquivo não encontrado, toolchain) sem exercitar assertion é rejeitado em planos v3. Plano com RED ausente ou malformado é rejeitado.

**Regras relacionadas:** `BR-001`, `BR-004`.

**Contratos relacionados:** `CON-002`.

**Evidência:** `scripts/validate_tasks.js`, `tests/validate_tasks.test.js`.

### CAP-003 — Gerar candidato de aceitação

**Valor:** Produz um sumário imutável e verificável de que todos os checks de aceitação foram observados com PASS antes de qualquer assinatura externa.

**Atores:** `ACT-001`, `ACT-003`.

**Comportamento:** Após verify PASS e todos os audit checks (AC-*, VISUAL, DOCUMENTATION, REGRESSION) registrados com PASS, gera JSON com hash do plano, snapshots de implementação e testes, digest das evidências e referências a cada audit check.

**Falhas e limites:** Candidato não é gerado se verify falhar, se qualquer audit check exigido estiver ausente ou com FAIL, ou se evidências foram alteradas após registro.

**Regras relacionadas:** `BR-003`.

**Contratos relacionados:** `CON-001`.

**Evidência:** `scripts/task_evidence.js` (candidate), `tests/task_evidence.test.js`.

### CAP-004 — Validar instalação de dependência declarada

**Valor:** Permite preparar o ambiente para executar o SUT quando a própria Spec exige uma dependência, sem transformar instalação arbitrária em permissão ampla.

**Atores:** `ACT-001`, `ACT-002`.

**Comportamento:** O plano pode registrar em `Dependency installations` um comando exato e o caminho da Spec governante. O validador permite a instalação somente quando todos os pacotes nomeados aparecem na declaração estruturada `Dependencies`/`Dependências` dessa Spec; a execução trata esse comando como pré-requisito de ambiente recuperável.

**Falhas e limites:** Pacote ausente da Spec, comando fora do campo explícito, `sudo`, instalação global, download canalizado para shell ou pacote adicional permanecem bloqueantes. A autorização vale somente para o comando exato validado.

**Regras relacionadas:** `BR-005`.

**Contratos relacionados:** `CON-002`.

**Evidência:** `scripts/validate_tasks.js`, `tests/validate_tasks.test.js`, `skills/engineering-workflow/references/execute-task.md`.

## Regras e invariantes globais

- **BR-001:** RED deve falhar pela assertion nova no SUT real, não por erro incidental de ambiente ou toolchain. **Cobertura:** `CAP-001`, `CAP-002`. **Evidência:** `CONTEXT.md` (Behavior Change), `skills/engineering-workflow/references/plan-tasks.md`.
- **BR-002:** O teste não pode ser alterado após o RED. A implementação não pode ser alterada antes do RED. GREEN exige diff de implementação e teste congelado. **Cobertura:** `CAP-001`. **Evidência:** `scripts/task_evidence.js` (red, green).
- **BR-003:** Um candidato de aceitação requer verify PASS, todos os audit checks do plano com PASS e integridade das evidências. **Cobertura:** `CAP-001`, `CAP-003`. **Evidência:** `scripts/task_evidence.js` (candidate).
- **BR-004:** Todo plano v3 declara exatamente um Work ID de quatro dígitos, tem contrato de execução, e cada task tem RED único com comando concreto e descrição de falha por assertion. **Cobertura:** `CAP-002`. **Evidência:** `scripts/validate_tasks.js`.
- **BR-005:** Instalação de dependência só deixa de ser bloqueante quando o plano registra o comando exato em `Dependency installations` e todos os pacotes nomeados constam na Spec governante; demais regras de segurança continuam aplicáveis. **Cobertura:** `CAP-002`, `CAP-004`. **Evidência:** `scripts/validate_tasks.js`, `skills/engineering-workflow/references/execute-task.md`.

## Contratos observáveis

### CON-001 — task_evidence.js

**Consumidores:** `ACT-001`, `ACT-003`.

**Entradas:** ações baseline/red/green/verify/check/candidate com Work ID, task ID, caminhos de arquivos e comandos.

**Saídas e efeitos:** logs namespaced por Work ID em `.todo/evidence/NNNN/`, state JSON em `.todo/evidence/NNNN/state/TASK.json`, candidato em `.todo/attestations/NNNN/TASK-candidate.json`.

**Erros:** baseline rejeitado com arquivos sujos; RED rejeitado se implementação mudou antes ou falha não contém expect; RED rejeitado se falha não exercita assertion (falha de toolchain/ambiente detectável); GREEN rejeitado se teste alterado após RED, implementação não mudou, ou mutation check falha; candidate rejeitado se audit checks ausentes ou evidence adulterada.

**Compatibilidade:** Work ID `legacy` mantém paths legados; IDs numéricos usam subdiretórios por Work ID.

**Evidência:** `scripts/task_evidence.js`, `tests/task_evidence.test.js`.

### CON-002 — validate_tasks.js

**Consumidores:** `ACT-001`, `ACT-002`.

**Entradas:** caminho de arquivo `.todo/NNNN-tasks.md`.

**Saídas e efeitos:** lista de erros e avisos; exit 0 somente sem erros.

**Erros:** contrato v3 exige Work ID, RED com comando concreto e descrição sem falha incidental de ambiente; ausência de campos obrigatórios; comandos inseguros; RED descrevendo falha de toolchain em plano v3 produz erro; instalação declarada cujo pacote não aparece na Spec governante produz erro e permanece classificada como comando inseguro.

**Compatibilidade:** contratos v1 e v2 permanecem legíveis com avisos.

**Evidência:** `scripts/validate_tasks.js`, `tests/validate_tasks.test.js`.

## Modelo conceitual do domínio

- **ENT-001 — Work:** unidade de trabalho com ID de quatro dígitos, manifest, source, prompt, plano e evidências namespaced. **Evidência:** `CONTEXT.md` (Work ID, Work Manifest, Numbered Work Artifacts).
- **ENT-002 — Task:** unidade atômica de implementação dentro de um plano, com RED/GREEN/verify e audit checks independentes. **Evidência:** `CONTEXT.md` (Local Task Plan).
- **ENT-003 — Acceptance Candidate:** sumário determinístico e verificável produzido após todos os checks de aceitação. **Evidência:** `CONTEXT.md` (Acceptance Candidate).

## Dados e ciclo de vida

- Work ID é reservado antes dos demais artefatos e nunca reutilizado.
- State JSON da task acumula baseline → red_tests → green_implementation → audit_checks sequencialmente.
- Candidato é gerado somente após verify PASS e todos os audit checks; é imutável após geração.
- Evidências em `.todo/evidence/NNNN/` são append-only pelo script; adulteração posterior invalida o candidato.

## Segurança, privacidade e autorização

- Nenhuma secret, credencial ou valor de `.env` é registrado em logs ou evidências; linhas sensíveis são redacted.
- Comandos com `sudo`, `eval`, download canalizado para shell, instalação não declarada, deploy, rollback destrutivo ou exposição de ambiente são rejeitados na validação de planos. Instalação declarada mantém todas as demais verificações de segurança.
- Chaves privadas de assinatura nunca estão no workspace; o candidato é unsigned até supervisor externo assinar.

## Qualidades sistêmicas

- **SQR-001:** Determinismo — o mesmo conjunto de arquivos e comandos produz os mesmos logs e hashes. **Cobertura:** `CAP-001`. **Evidência:** `tests/task_evidence.test.js`.
- **SQR-002:** Verificabilidade independente — qualquer supervisor pode re-executar verify e comparar hashes sem acesso ao agente. **Cobertura:** `CAP-001`, `CAP-003`. **Evidência:** `CONTEXT.md` (Acceptance Candidate).
- **SQR-003:** Compatibilidade aditiva — novos contratos não quebram planos legados executáveis. **Cobertura:** `CAP-002`. **Evidência:** `CONTEXT.md` (Workflow Contract Compatibility).

## Integrações externas

- **INT-001 — Git:** usado para baseline clean check, diff de implementação no mutation check e verificação de arquivos tracked. **Evidência:** `scripts/task_evidence.js` (requireCleanBaseline, mutationCheck).

## Restrições e decisões vigentes

- A suite não executa agentes; ela fornece contratos e ferramentas determinísticas.
- Sistema de arquivos local é o único store de artefatos; não há banco de dados.
- Contrato atual é v3; v1 e v2 são legados com janela de compatibilidade.

## Registro de cobertura e drift

| `CAP-001` | Parcial | RED/GREEN capturados determinísticamente, mas falha de toolchain não é distinguida de falha de assertion pelo script | `GAP-001` |
| `CAP-002` | Parcial | Estrutura do plano validada, mas RED descrevendo falha de ambiente não é rejeitado em v3 | `GAP-001` |
| `CAP-003` | Confirmado | Candidato gerado somente após verify e audit checks com PASS | nenhum gap |
| `CAP-004` | Confirmado | Instalação explicitamente registrada só é liberada quando os pacotes aparecem na Spec governante; demais checks de segurança permanecem ativos | nenhum gap |
| `GAP-001` | Lacuna | RED de toolchain/ambiente aceito sem enforcement da regra BR-001 (assertion nova) | BR-001 não enforçado em task_evidence.js nem em validate_tasks.js |

## Rastreabilidade sistêmica

| Capacidade | Atores | Regras | Contratos | Qualidades | Integrações | Evidência |
|------------|--------|--------|-----------|------------|-------------|-----------|
| `CAP-001` | `ACT-001`, `ACT-003` | `BR-001`, `BR-002`, `BR-003` | `CON-001` | `SQR-001`, `SQR-002` | `INT-001` | `scripts/task_evidence.js`, `tests/task_evidence.test.js` |
| `CAP-002` | `ACT-001`, `ACT-002` | `BR-001`, `BR-004` | `CON-002` | `SQR-003` | nenhuma | `scripts/validate_tasks.js`, `tests/validate_tasks.test.js` |
| `CAP-003` | `ACT-001`, `ACT-003` | `BR-003` | `CON-001` | `SQR-001`, `SQR-002` | nenhuma | `scripts/task_evidence.js`, `tests/task_evidence.test.js` |
| `CAP-004` | `ACT-001`, `ACT-002` | `BR-005` | `CON-002` | `SQR-003` | nenhuma | `scripts/validate_tasks.js`, `tests/validate_tasks.test.js`, `skills/engineering-workflow/references/execute-task.md` |

## Política de evolução

- Mudanças em contratos de evidência (task_evidence.js) seguem o fluxo make-prompt → make-todo → make-task com testes antes do merge.
- Mudanças em validate_tasks.js que rejeitem novos formatos incrementam CURRENT_TASK_CONTRACT_VERSION somente quando há breaking change; adições backward-compatible não precisam de bump.
- GAP-001 é o defeito normativo desta baseline: BR-001 não é enforçado mecanicamente; esta work resolve o gap.
