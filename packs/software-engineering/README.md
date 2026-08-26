# ai-engineering-skills

Skills e adapters mínimos para um processo de engenharia de software assistido por IA. O repositório é independente do runtime: skills contêm o processo, o projeto trabalhado mantém seu estado e o Pi é apenas um host opcional.

## Responsabilidades

```text
Pi/runtime             → carrega skills e expõe adapters opcionais
ai-engineering-skills  → define workflows, contratos e ferramentas determinísticas
projeto trabalhado     → mantém Works numerados, prompts, planos e evidências locais
```

O núcleo não impõe linguagem, framework ou arquitetura. Skills especializadas podem conter referências de stack, mas devem ceder às instruções e convenções do repositório.

## Estrutura

```text
ai-engineering-skills/
├── skills/
│   ├── engineering-workflow/
│   │   ├── SKILL.md
│   │   ├── references/
│   │   └── scripts/              # links relativos para as ferramentas testadas
│   └── ...
├── scripts/
│   ├── validate_tasks.js
│   ├── task_evidence.js
│   ├── project_status.js
│   └── unattended_exec.js
├── tests/
├── adapters/pi/prompts/          # wrappers mínimos; não contêm o processo
├── install.sh
└── uninstall.sh
```

## Engineering workflow

A skill `engineering-workflow` carrega apenas a etapa necessária:

```text
/make-spec → .specs/system.md
                 ↓
/make-prompt → Work ID + source + prompt → /make-todo → .todo/NNNN-tasks.md
                                                    ↘ /make-status
                                                    ↘ /make-task → /make-ac
                                                    ↘ /make-all
```

- `make-spec`: cria ou reconcilia a baseline comportamental do sistema inteiro, com capacidades, regras, contratos, evidências e gaps explícitos;
- `make-prompt`: reserva um Work ID, preserva a fonte em `.sources/NNNN-*` e descreve o delta WHAT/WHY em `.prompts/NNNN-change.md`;
- `make-todo`: descobre comandos reais e cria `.todo/NNNN-tasks.md` rigorosamente atomizado — um requisito primário, um comportamento e um RED por task. O planejamento é estritamente amarrado aos cenários Given/When/Then;
- `make-status`: sem alvo mostra todos os Works; com `NNNN`, caminho canônico ou `legacy`, mostra tasks, dependências, evidência e ponto de parada;
- `make-task`: exige plano explícito e executa BASELINE → RED → GREEN → REFACTOR → ACs → gates locais. Impede falsos positivos (falsos REDs) filtrando heurísticas de erros sintáticos (SyntaxError, undefined, ReferenceError);
- `make-all`: exige plano explícito e supervisiona `/make-task` → nova sessão de `/make-ac` para cada task, com timeouts, retomada, checkpoints e limpeza;
- `make-ac`: audita de forma independente cruzando a intenção de negócios do System Spec com a implementação. Emite candidato mecânico em `.todo/attestations/NNNN/`;
- `make-doc`: audita ou sincroniza documentação afetada.

`validate_system_spec.js` valida a baseline sistêmica. `validate_prompt.js` valida prompts numerados e rastreáveis. `work_artifacts.js` reserva Work IDs, resolve alvos canônicos e migra layout legado com preview. `validate_tasks.js` aplica o contrato v3, atomização e dependências qualificadas; `validate_work_graph.js` verifica referências e ciclos entre planos do mesmo repositório. `task_evidence.js` namespacifica RED/GREEN/verify por Work e emite candidatos determinísticos de aceitação. `project_status.js` lista todos os Works ou detalha um plano explícito. `unattended_exec.js` fecha stdin, desabilita prompts/pagers do Git e impõe timeout com encerramento do grupo de processos.

O manual operacional completo, incluindo instalação, fluxo ponta a ponta, retomada, validação estrita, migração e exemplos, está em [`docs/manual-suite.md`](docs/manual-suite.md).

## Requisitos

- Node.js 18 ou posterior;
- Git para o runner de evidências;
- o harness e as ferramentas do projeto trabalhado.

Não há dependências npm de runtime para os scripts principais. A skill `webapp-testing` usa o Playwright já instalado no ambiente ou no projeto; este repositório não o instala automaticamente.

## Instalação compartilhada

Clone o repositório e execute seu instalador:

```bash
git clone git@github.com:passoz/ai-engineering-skills.git ~/dev/ai-engineering-skills
~/dev/ai-engineering-skills/install.sh
```

O instalador cria links individuais em:

- `~/.agents/skills/<skill>` — biblioteca compartilhada compatível com Pi, OpenCode e outros runtimes que implementam Agent Skills;
- `~/.pi/agent/prompts/<adapter>.md` — somente os atalhos `/make-*` específicos do Pi.

Nenhuma skill deste repositório é instalada diretamente em `~/.pi/agent/skills`, `~/.config/opencode/skills` ou outro diretório específico de runtime. Em upgrades, o instalador remove links Pi-locais legados que apontem para este repositório. Ele não remove nem sobrescreve skills compartilhadas preexistentes que pertençam a outra origem: preserva a versão compartilhada já instalada e segue com as demais.

Defina `AGENT_SKILLS_DIR` para trocar o diretório compartilhado e `PI_AGENT_DIR` para trocar o destino dos adapters Pi. O instalador não altera `SYSTEM.md`, `settings.json`, extensions ou temas e recusa sobrescrever caminhos existentes que não pertençam a este repositório.

Para remover somente os links compartilhados e adapters pertencentes a esta instalação:

```bash
~/dev/ai-engineering-skills/uninstall.sh
```

## Portabilidade e adapters

As skills seguem o formato Agent Skills e são consumidas da biblioteca compartilhada. Adapters continuam específicos de runtime porque a passagem de argumentos e a descoberta de slash commands não são padronizadas. Atualmente este repositório instala adapters apenas no Pi; outros agentes podem usar as skills por descoberta/intenção mesmo sem os aliases `/make-*`.

## Adapters Pi

Os adapters preservam comandos explícitos como `/make-task 0007 1.2`, mas são intencionalmente mínimos. Cada adapter apenas:

1. solicita o carregamento da skill correspondente;
2. repassa `$@` sem alteração;
3. deixa ajuda, descoberta, execução e evidência sob responsabilidade da skill.

Assim, o processo não pertence ao Pi e pode receber outros adapters no futuro.

### Execução unattended

Depois que `.todo/0007-tasks.md` estiver pronto, use:

```text
/make-all 0007 all
```

O supervisor processa um ID por vez no plano explícito: conclui `/make-task 0007 ID`, audita/corrige em nova sessão com `/make-ac 0007 ID` e só então avança. Bloqueios recuperáveis são diagnosticados e corrigidos sem perguntas. Prompts, pagers, editores, watch mode e processos sem timeout são proibidos; decisões locais reversíveis usam a solução mínima comprovada pelo repositório.

A autonomia não amplia permissões de segurança: instalação não declarada, deploy, publish, mudanças remotas, ações destrutivas, secrets ou decisões de produto indeterminadas continuam proibidos sem autorização concreta. Uma dependência do produto explicitamente listada em `Dependencies`/`Dependências` na Spec governante pode ser registrada como `Dependency installations` no plano e executada sem prompt somente após validação mecânica do pacote e do comando exato. Nos demais casos, a task recebe bloqueio terminal, tasks dependentes são puladas e o processo encerra com relatório em vez de ficar aguardando resposta.

## Desenvolvimento

```bash
npm test
npm run check
```

Os testes usam `node:test` e diretórios Git temporários. Nenhuma instalação de pacote é necessária para validar os scripts centrais.

## Segurança operacional

As ferramentas rejeitam comandos perigosos no contrato de tarefas e sanitizam saídas potencialmente sensíveis. Elas não substituem as políticas do runtime ou do projeto: deploy, publish, instalação não declarada, alterações remotas e ações destrutivas continuam exigindo autorização concreta. A exceção estreita é o comando exato de dependência declarado no plano e comprovado pela Spec governante; ela nunca autoriza `sudo`, instalação global ou pacote adicional.
