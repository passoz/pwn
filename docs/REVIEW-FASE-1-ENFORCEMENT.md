# Revisão das Alterações — Fase 1 de Enforcement

**Projeto:** PWN  
**Branch analisado:** `master`  
**Escopo:** revisão das alterações implementadas após a auditoria técnica anterior  
**Conclusão:** a direção está correta e houve evolução substancial, mas ainda existem pontos de segurança que devem ser corrigidos antes de considerar o enforcement pronto para execução AFK.

---

## 1. Resumo executivo

As alterações implementaram boa parte das recomendações da auditoria anterior:

- criação do `Policy Engine`;
- integração inicial do Policy Engine ao runtime;
- remoção do fallback do sandbox para o `rootDir`;
- melhoria do glob matching;
- expansão do `Contract Engine` com risco e políticas de execução;
- `BudgetController` efetivamente conectado ao runner;
- traceability/provenance entre artefatos;
- routing orientado a risco;
- eventos e telemetria do runtime.

**Avaliação geral: ~7,5/10.**

A arquitetura continua boa e a implementação agora já possui um núcleo real de:

```text
Contract → Policy → Sandbox → Budget → Execution → Verification
```

Entretanto, há uma diferença importante entre **ter um Policy Engine** e **obrigar toda superfície de execução a passar pelo Policy Engine**. Essa integração ainda não está completa.

---

## 2. 🟢 Sandbox — problema crítico anterior corrigido

A auditoria anterior identificou como crítico o fallback que permitia executar no diretório principal caso a criação do worktree falhasse.

Isso foi corrigido.

Agora `createGitWorktreeSandbox()` lança `SandboxError` quando `git worktree add` falha, e o `initRunContext()` aborta a execução em vez de continuar no `rootDir`.

Fluxo atual:

```text
git worktree add
       │
       ├── sucesso → sandbox
       │
       └── falha → SandboxError → ABORT
```

### Veredito

**🟢 Aprovado.**

Essa mudança está alinhada diretamente com o requisito de isolamento e elimina um risco grave.

---

## 3. 🟢 Glob / Contract Guard — correção adequada

O matcher artesanal baseado em `startsWith()` foi substituído por uma implementação de glob dedicada (`glob-utils.ts`), acompanhada de testes.

Isso é uma evolução importante porque padrões como:

```text
src/**
src/*.ts
```

não devem ser tratados simplesmente como prefixos de strings.

### Veredito

**🟢 Aprovado.**

A recomendação da auditoria foi atendida de forma coerente.

---

## 4. 🟢 Contract Engine — evolução significativa

O contrato passou a incorporar melhor o contexto de execução, incluindo:

- nível de risco;
- `writeAllow`;
- `writeDeny`;
- invariantes;
- cenários customizados;
- orçamento relacionado ao risco;
- tentativas máximas;
- política de escalada.

Isso aproxima o contrato de uma especificação executável, em vez de deixá-lo como documentação declarativa.

Ainda assim, o próximo passo deve ser garantir que **cada campo normativo do contrato tenha um enforcement correspondente no runtime**.

### Veredito

**🟢/🟡 Aprovado com ressalva.**

---

## 5. 🟢 BudgetController — bom avanço, mas a semântica de `attempt` precisa ser definida

O budget agora participa efetivamente do runtime:

```text
checkBudget()
      ↓
execução
      ↓
recordAttempt()
```

Isso é muito melhor do que apenas armazenar limites no contrato.

Porém, `recordAttempt()` é chamado após a execução de um comando shell. Portanto, hoje `max_attempts` pode acabar significando número de execuções de ferramentas/comandos, e não necessariamente número de tentativas do agente.

Recomenda-se distinguir explicitamente:

```text
agent_attempts
llm_calls
tool_calls
shell_executions
```

Assim, o contrato pode definir exatamente qual unidade está sendo limitada.

### Veredito

**🟢 Implementação boa / 🟡 semântica a esclarecer.**

Não é bloqueador imediato, mas deve ser resolvido para evitar comportamento surpreendente.

---

## 6. 🔴 Policy Engine — problema de fail-closed

Este é o principal problema encontrado na revisão.

A documentação da política de rede afirma que uma allowlist vazia significa:

```text
allowedDomains = []
→ tudo negado
```

Porém, a implementação faz o contrário: quando `allowedDomains` está vazia, a operação é permitida, desde que não esteja explicitamente negada.

O mesmo ocorre com shell:

```text
allowedCommands = []
→ tudo permitido, exceto denies explícitos
```

Isso é incompatível com uma política de enforcement orientada a segurança e também contradiz o comentário/documentação da configuração de rede.

### Recomendação

Adotar comportamento **fail closed**:

```text
allowlist vazia
      ↓
DENY ALL
```

Caso seja necessário permitir tudo deliberadamente, isso deve ser uma opção explícita, por exemplo:

```text
allowAllShell: true
allowAllNetwork: true
```

Assim não existe ambiguidade entre "nenhuma regra configurada" e "permitir tudo".

### Veredito

**🔴 Corrigir antes de considerar o Policy Engine seguro.**

---

## 7. 🔴 Policy Engine — integração preventiva ainda incompleta

A criação do Policy Engine foi correta:

```text
Contract
   ↓
Policy Engine
   ↓
ALLOW / DENY
```

O runner também consulta a política antes de executar comandos shell.

O problema é que isso ainda não significa que **todas as operações do agente** sejam obrigadas a passar por essa camada.

Existe uma API para avaliar operações de filesystem:

```text
write_file
 delete_file
 create_dir
```

mas o runtime não demonstra, por si só, que chamadas reais de filesystem feitas pelo processo do agente sejam interceptadas pelo Policy Engine.

Por exemplo, se um agente puder executar:

```bash
python script.py
```

ou:

```bash
echo foo > package.json
```

o processo filho pode modificar arquivos diretamente. Nesse caso, o Policy Engine não necessariamente vê a operação `write_file`.

O `Diff Guard` posterior ainda pode detectar a consequência, mas isso é **detecção pós-fato**, não prevenção.

### Recomendação

Introduzir uma camada obrigatória de execução de ferramentas:

```text
Agent
  ↓
Tool API
  ↓
Policy Engine
  ↓
Execution Adapter
  ↓
filesystem / shell / network
```

Ou, para uma arquitetura mais forte, executar o agente em um ambiente onde filesystem, shell e rede sejam efetivamente controlados por mecanismos externos ao processo do agente.

### Veredito

**🔴 Ainda incompleto para a promessa de "preventive interception".**

---

## 8. 🟡 Shell policy — matching permissivo

A política de shell utiliza comparação textual por prefixo para allowlist e `includes()`/prefixo para denylist.

Isso é simples, mas frágil para uma camada de segurança.

Uma política como:

```text
allowed = "bun test"
```

não deveria ser interpretada apenas como:

```text
fullCommand.startsWith("bun test")
```

O ideal é trabalhar estruturalmente com:

```text
command = "bun"
args = ["test"]
```

permitindo regras sobre comando e argumentos.

Também é importante tratar corretamente operadores e composição de comandos quando uma shell real estiver envolvida:

```text
&&
;
|
>
>>
$(...)
`...`
```

Se o executor não utiliza uma shell intermediária, melhor ainda: manter `spawn(command, args)` sem interpretar uma string de shell.

### Veredito

**🟡 Funciona para o caso básico, mas precisa endurecimento antes de ser considerado uma boundary de segurança.**

---

## 9. 🟢 Runner — evolução importante

O runner agora possui um `RunContext` contendo:

```text
contract
rootDir
runId
sandbox
budget
policy
events
status
```

Além disso, foram adicionados:

- inicialização governada pelo contrato;
- criação obrigatória do sandbox;
- avaliação de operações;
- checks de budget;
- execução no sandbox;
- verificação de diff;
- finalização;
- limpeza do sandbox;
- telemetria JSONL.

Isso transforma o runner em uma base real para um runtime de agentes.

### Veredito

**🟢 Aprovado.**

Ainda não é um harness completo de agente, mas a fundação está correta.

---

## 10. 🟢 Traceability / Provenance

A introdução da matriz de traceability atende uma das recomendações mais importantes da auditoria anterior.

A arquitetura passa a poder representar relações do tipo:

```text
REQ
 ↓
PRD
 ↓
SPEC
 ↓
TASK
 ↓
CONTRACT
 ↓
TEST
 ↓
EVIDENCE
```

Isso é particularmente importante para o modelo AFK, pois permite saber não apenas se uma tarefa passou, mas **por que ela existe e qual evidência comprova seu cumprimento**.

### Veredito

**🟢 Boa direção e aprovado conceitualmente.**

O próximo passo é garantir que os vínculos sejam semanticamente verificados, e não apenas que IDs estejam presentes.

---

## 11. 🟢 Router / Risk-based execution

O routing passou a considerar risco, o que está alinhado com a estratégia de autonomia progressiva.

A arquitetura recomendada é:

```text
L0 → cheap
L1 → cheap
L2 → cheap + review
L3 → strong
L4 → human
```

O ponto importante é que o risco determine não apenas o modelo, mas também a **política de execução e o grau de autonomia**.

### Veredito

**🟢 Aprovado.**

---

# 12. Estado atual da arquitetura

Depois dessas alterações, o PWN já possui uma arquitetura significativamente mais concreta:

```text
                    CONTRACT
                       │
                       ▼
                 POLICY ENGINE
                       │
                ┌──────┼──────┐
                ▼      ▼      ▼
            filesystem shell network
                │      │      │
                └──────┼──────┘
                       ▼
                    SANDBOX
                       │
                       ▼
                    AGENT
                       │
                       ▼
                     TESTS
                       │
                       ▼
                  DIFF GUARD
                       │
                       ▼
                   EVIDENCE
```

A principal diferença para a versão anterior é que agora existe uma tentativa real de transformar o contrato em **controle de execução**.

---

# 13. Prioridades recomendadas

## P0 — corrigir antes de avançar

### 1. Fail closed

Corrigir shell e network para que allowlist vazia não resulte em `ALLOW` implícito.

### 2. Garantir enforcement real

Impedir que o agente contorne o Policy Engine executando diretamente operações de filesystem/rede por meio de subprocessos ou ferramentas auxiliares.

---

## P1 — próxima rodada

### 3. Tornar shell policy estrutural

Evitar matching puramente textual de comandos.

### 4. Separar unidades de budget

Distinguir tentativas do agente, chamadas de LLM, tool calls e execuções de shell.

### 5. Fortalecer traceability

Validar relações semânticas entre artefatos, e não somente existência de IDs.

---

# 14. Veredito final

### Arquitetura

**8,5/10**

Continua sendo o ponto mais forte do projeto.

### Implementação

**~7,5/10**

A evolução foi substancial e as principais recomendações da auditoria anterior foram atacadas.

### Segurança do enforcement

**Ainda não pronta para receber o selo "AFK seguro".**

O motivo principal é simples:

> Um Policy Engine só é uma boundary de segurança se o agente não tiver uma rota alternativa para executar operações fora dele.

### Recomendação

**Não fazer rollback. Não reescrever. Continuar evoluindo a arquitetura atual.**

O próximo grande marco deve ser tornar o Policy Engine uma boundary obrigatória e adotar fail-closed por padrão.

Depois disso, o PWN estará muito mais próximo de ser um verdadeiro **runtime de engenharia para agentes autônomos**, e não apenas um orquestrador de chamadas de agentes.
