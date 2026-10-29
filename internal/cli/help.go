package cli

// Version é a versão exibida por `pwn --version`. A fonte é VERSION na raiz.
const Version = "0.1.0"

const helpText = `
PWN — Policy Work Norms CLI (pwn) v%s — Contract-Governed Agent Harness

USO:
  pwn <comando> <subcomando> [opções]

COMANDOS DISPONÍVEIS:
  init                Inicializa o PWN no projeto; pergunta pela configuração do decisor
                      (--decider <provedor:modelo> | --no-decider para não perguntar)
  decider <ação>      Configuração e registro do decisor do projeto (show, set, remove, log)
  work <subcomando>   Gerencia a cadeia de planejamento e execução de Works
                      (init, import, scaffold, reconcile, gate, specify, contract, plan, run, run-all, batch, audit, status, sync)
  task <subcomando>   Gerencia tarefas atômicas isoladas
                      (run, capsule)
  target <subcomando> Gerencia runtimes e materialização de targets
                      (list, materialize)
  metrics <subcomando>Exibe métricas de execução e recomendações de otimização
                      (list, optimize)
  queue <subcomando>  Gerencia a fila de revisão humana assíncrona (AFK)
                      (list, approve, reject)
  verify <subcomando> Aceitação independente: aprova critérios, executa checks isolados
                      e emite o recibo assinado (init, approve, run, run-all, status, show)
  validate [--work NNNN]  Valida documentos normativos JSON do projeto contra JSON Schemas
  self-check [--mutate [--work NNNN]]
                      Valida os documentos normativos do framework
                      (--mutate roda mutation testing nos próprios gates)

OPÇÕES:
  --help, -h          Exibe esta mensagem de ajuda
  --version, -v       Exibe a versão do pwn
  --operator <modo>   human: decisões do operador ficam com você nesta execução;
                      decider: exige o decisor do projeto (padrão: decisor se configurado)

EXEMPLOS:
  pwn self-check
  pwn self-check --mutate
  pwn validate --work 0001
  pwn work gate --all --work 0001
  pwn work run --dry-run --work 0001 -- bun test
  pwn work reconcile --dry-run              (lista o que mudou fora do pwn)
  pwn work reconcile --title "Ajuste X" --tests tests/x.test.ts
  pwn work status --coverage 0001
  pwn work run --work 0001 -- bun test
  pwn work run-all --works 0001,0002 --jobs 2 -- bun test
  pwn work batch prepare --work 0001 --jobs 3
  pwn task capsule 1.1 0001
  pwn verify init
  pwn verify approve --work 0001 --task 1.1 --by operador
  pwn verify approve --work 0001 --task 1.1          (o decisor do projeto decide)
  pwn verify run --work 0001 --task 1.1
  pwn verify run-all --work 0001 --jobs 4

`
