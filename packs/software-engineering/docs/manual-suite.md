# AI Engineering Skills — Manual Completo do Usuário

Este manual detalha o funcionamento, as regras de segurança e o uso no dia a dia da suíte **AI Engineering Skills**. Ele foi desenhado para ser independente de plataforma, embora forneça *adapters* otimizados (como o `/make-task`) para o Pi.

Seu objetivo principal é impor o **Test-Driven Development (TDD) Estrito** e a **Rastreabilidade Absoluta** (da Especificação de Negócio até o binário compilado), impedindo que a IA alucine requisitos ou pule etapas de qualidade.

---

## 1. O Modelo Operacional (Pipeline)

O processo de engenharia imposto pelo repositório flui sempre da seguinte maneira:

```text
/make-spec      → Elicita ou atualiza a Baseline do Sistema (.specs/system.md)
   ↓
/make-prompt    → Levanta Requisitos de Mudança e mapeia para a Spec (.prompts/NNNN-change.md)
   ↓
/make-todo      → Planeja as Tarefas Atômicas TDD baseadas no Prompt (.todo/NNNN-tasks.md)
   ↓
/make-task      → Executa as tarefas 1 a 1 (Baseline → RED → GREEN → Refactor)
   ↓
/make-ac        → Audita as entregas isoladamente contra as Regras de Negócio
```

Para cada ciclo de trabalho, a suíte emite e bloqueia um **Work ID** sequencial de quatro dígitos (ex: `0007`). Todos os artefatos desse pacote de trabalho ficarão associados a esse ID.

---

## 2. Exemplo Prático (Ponta a Ponta)

Vamos supor que você queira adicionar um recurso de "Recuperação de Senha" em um projeto web.

### Passo 1: Garantir a Especificação do Sistema
Se o seu projeto ainda não tem um `.specs/system.md`, crie-o.
```text
/make-spec "Gere a system spec inicial desse repositório focado em autenticação"
```

### Passo 2: Iniciar o Ciclo da Nova Funcionalidade
Peça a mudança. O sistema reservará um *Work ID* (ex: `0008`) e fará o mapeamento contra a system spec.
```text
/make-prompt "Adicionar recuperação de senha por email"
```
* **O que acontece:** O agente lê a `system.md`, entende onde a recuperação entra (gaps afetados, capacidades, regras), salva o seu pedido bruto em `.sources/0008-request.md` e gera um documento normativo impecável em `.prompts/0008-change.md`. Os scripts do repositório vão matematicamente **validar** se o que o agente escreveu condiz com a Spec.

### Passo 3: Criar o Plano de Execução (TDD)
```text
/make-todo 0008
```
* **O que acontece:** O agente gera o `.todo/0008-tasks.md`. Ele mapeia cada Criteiro de Aceite do prompt para um teste (AC) e um teste falho (RED).
* **Segurança Semântica:** A instrução do `/make-todo` **exige** que o comando `RED` gerado teste explicitamente a regra de negócio do cenário, evitando "testes vazios".

### Passo 4: Executar o Código
Você pode rodar tarefa a tarefa:
```text
/make-task 0008 1.1
```
* **O que acontece:** O agente obedece o *Engineering Workflow*.
  1. Cria os arquivos e o teste inicial.
  2. Roda o script de **RED** (`task_evidence.js`). **Atenção:** Se o código não compilar (ex: *SyntaxError*, *undefined*), o script **REJEITA O RED**. O teste precisa rodar e falhar pela Regra de Negócio (Assertion), não por erro de ambiente!
  3. Escreve a lógica do programa.
  4. Roda o **GREEN**. O script testa com o código novo (deve passar) e sem o código novo (testes de mutação), garantindo que não houve fraude.

### Passo 5: Auditoria de Aceite (Quality Assurance)
```text
/make-ac 0008 1.1
```
* **O que acontece:** Em vez de ser a IA programadora, o modelo assume o chapéu de Revisor (QA). O `/make-ac` não apenas checa *exit codes*, ele cruza a implementação com o `.specs/system.md` para garantir que o comportamento obedece estritamente a especificação. Se passar, assina um `candidate.json` na pasta de atestados.

---

## 3. Automação Total (Unattended Mode)

Se o plano já foi gerado e as regras estão perfeitamente delineadas no `.todo/NNNN-tasks.md`, você não precisa pedir para o agente rodar uma a uma.

```text
/make-all 0008 all
```

O `/make-all` é o orquestrador autônomo:
- Pega a Task 1.1, chama o `/make-task`.
- Limpa o contexto. Puxa a Task 1.1 e chama o `/make-ac` para auditar.
- Passou? Vai para a 1.2, e assim por diante.
- Se houver dependências de ferramentas externas (timeout), ele aborta graciosamente e não inventa respostas infinitas.

> **Regra de Segurança:** Nem no modo autônomo a IA tem permissão de executar instalações cegas, manipulações destrutivas, expor variáveis (`.env`) ou dar "Deploy". A exceção estreita é uma dependência do produto declarada na Spec governante e registrada no plano como `Dependency installations`; o validador confere o pacote e libera somente o comando exato. Instalações não declaradas continuam bloqueando e exigindo aprovação humana explícita.

---

## 4. Auditoria Contínua e TDD Rigoroso

O `ai-engineering-skills` combate dois problemas massivos de IA de programação:
1. **Vacuous Changes (Mutações Vazias):** Quando o agente altera um comentário só para o teste passar. A **Mutation Check** intrínseca no repositório faz stash da alteração e prova matematicamente que foi a linha de código implementada que acendeu o teste no GREEN.
2. **Falsos REDs (Incidental Failures):** Se o agente chamar `funcaoQueNaoExiste()` e isso cuspir um `ReferenceError` ou `undefined` em Node/Go, muitas IAs diriam *"Olha, o RED passou!"*. **Nós não**. As heurísticas expandidas no `task_evidence.js` barram *Syntax Errors* e *Type Mismatches*, forçando a IA a criar um arquivo mínimo estruturalmente viável (Greenfield) para então a *assertion* falhar organicamente.

---

## 5. Recuperação Inteligente de Bloqueios

O sistema classifica falhas em **4 categorias** com ações específicas para cada uma, permitindo resolver automaticamente o que é seguro e bloquear imediatamente o que não é:

| Categoria | Exemplos | Resolução Automática? |
|---|---|---|
| **A — Processo/Ambiente** | Porta ocupada, timeout, lock de arquivo, diretório faltando, instalação de dependência declarada na Spec | ✅ Sim — retry, matar processo órfão, limpar cache, executar comando declarado |
| **B — Implementação/Teste** | Assertion falhando, lint quebrado, regressão | ✅ Sim — corrigir dentro dos arquivos declarados |
| **C — Plano/Escopo** | Arquivo não declarado, AC impossível | ⚠️ Parcial — ajustar metadados + revalidar plano |
| **D — Segurança/Decisão** | `sudo`, instalação não declarada, deploy, secrets, decisão ambígua | ❌ Nunca — bloqueio terminal imediato |

**Regras:**
- Categorias A–C têm até 3 tentativas; a mesma falha sem progresso em 2 ciclos encerra.
- Categoria D bloqueia na **primeira ocorrência** sem consumir tentativas.
- Tasks dependentes de uma bloqueada são **puladas** (marker `[ ]`), não bloqueadas (`[!]`). Tasks independentes no mesmo plano continuam normalmente.

---

## 6. Skills Adicionais

Você não está limitado apenas a criar código novo.

- **`/make-status`**: Lista todos os pacotes de trabalho (Works) da máquina, onde pararam, e quais evidências já têm atestados criptográficos gerados. Exemplo: `/make-status 0008`.
- **`code-review`**: Se você estiver em uma Branch diferente e quiser saber se está seguindo o repositório, rode a skill `code-review`. Ela não usa os scripts locais (útil para auditoria externa); ela levanta 2 sub-agentes. O primeiro checa se o seu código segue os **Padrões e Code Smells** e o segundo checa se atende fielmente à **System Spec**.

---

## 7. Projetos Legados e Guia de Conformidade (Migração para V3)

Se o projeto já usava uma versão antiga do layout (`.todo/tasks.md` fixo) ou contratos V1/V2, o sistema continuará aceitando os comandos via modo de compatibilidade legada:
```text
/make-task legacy 1.2
/make-status legacy
```

Para colocar o projeto em **100% de conformidade com os novos contratos (V3)** e habilitar o TDD estrito e a recuperação inteligente de falhas, siga o passo a passo:

### Passo 1: Migrar a Estrutura de Arquivos (Layout)
Mova o arquivo de tarefas central para o formato isolado com *Work ID* de quatro dígitos:
```bash
# 1. Preview da migração
node ~/.agents/skills/engineering-workflow/scripts/work_artifacts.js migrate-legacy

# 2. Aplicar a migração
node ~/.agents/skills/engineering-workflow/scripts/work_artifacts.js migrate-legacy --write
```
*Isso renomeia `.todo/tasks.md` para `.todo/0001-tasks.md` e gera o manifesto `.work/0001.json`.*

### Passo 2: Atualizar o Contrato das Tarefas para v3
Injeta metadados de dependência e tolerâncias atômicas necessárias:
```bash
# 1. Preview das mudanças de contrato
node ~/.agents/skills/engineering-workflow/scripts/validate_tasks.js --migrate --work 0001 .todo/0001-tasks.md

# 2. Aplicar no arquivo
node ~/.agents/skills/engineering-workflow/scripts/validate_tasks.js --migrate --work 0001 --write .todo/0001-tasks.md

# 3. Validar conformidade estrita (sem warnings)
node ~/.agents/skills/engineering-workflow/scripts/validate_tasks.js --strict .todo/0001-tasks.md
```

### Passo 3: Limpeza Semântica dos REDs
Revise as descrições dos comandos `**RED:**` no plano `.todo/0001-tasks.md`:
- Remova menções a ferramentas ou arquivos faltantes (ex: *"module not found"*, *"syntax error"*).
- Garanta que o RED aponte para a falha lógica de uma *assertion* no código do teste.
- Se for código novo (greenfield), certifique-se de que a implementação inicial seja compilável (ex: retornando zero ou valor padrão incorreto).

### Passo 4: Criar ou Reconciliar a System Spec
Se o repositório ainda não possuir o arquivo de governança central:
```text
/make-spec "Gere a baseline com base no código e arquitetura atual"
```
Valide o arquivo:
```bash
node ~/.agents/skills/system-specification/scripts/validate_system_spec.js .specs/system.md
```

---

## 8. Instalação e Requisitos

- Node.js 18+ (O script validador e a inteligência de orquestração rodam sem pacotes npm extras).
- Git na pasta do projeto (Obrigatoriedade para Mutation Checks).

Para instalar a suíte de skills globalmente de forma que o Pi (ou outro terminal via *Agent Skills*) a entenda:

```bash
git clone git@github.com:passoz/ai-engineering-skills.git ~/dev/ai-engineering-skills
~/dev/ai-engineering-skills/install.sh
```

Nenhum arquivo nocivo é despejado na sua branch. Artefatos temporários devem constar no seu `.gitignore`:

```gitignore
.todo/evidence/
.todo/diagnostics/
.todo/screenshots/
.todo/attestations/
```
(Atenção: Não adicione as pastas `.work`, `.sources`, `.prompts` nem o `.todo/NNNN-tasks.md` no `.gitignore`. Eles são o DNA técnico do seu desenvolvimento e devem fazer parte do seu pull request/commit).