import { handleWorkCommand } from './commands/work.js';
import { handleTaskCommand } from './commands/task.js';
import { handleValidateCommand, handleSelfCheckCommand } from './commands/validate.js';
import { handleQueueCommand } from './commands/queue.js';
import { handleTargetCommand } from './commands/target.js';
import { handleMetricsCommand } from './commands/metrics.js';

const VERSION = '0.1.0';

function showHelp(): void {
  console.log(`
Piwerness CLI (pwn) v${VERSION} — Contract-Governed Agent Harness

USO:
  pwn <comando> <subcomando> [opções]

COMANDOS DISPONÍVEIS:
  work <subcomando>   Gerencia a cadeia de planejamento e execução de Works
                      (init, import, scaffold, gate, specify, contract, plan, run, audit, status, sync)
  task <subcomando>   Gerencia tarefas atômicas isoladas
                      (run, capsule)
  target <subcomando> Gerencia runtimes e materialização de targets
                      (list, materialize)
  metrics <subcomando>Exibe métricas de execução e recomendações de otimização
                      (list, optimize)
  queue <subcomando>  Gerencia a fila de revisão humana assíncrona (AFK)
                      (list, approve, reject)
  validate [--work NNNN]  Valida documentos normativos JSON do projeto contra JSON Schemas
  self-check          Valida os documentos normativos do próprio framework

OPÇÕES:
  --help, -h          Exibe esta mensagem de ajuda
  --version, -v       Exibe a versão do pwn

EXEMPLOS:
  pwn self-check
  pwn validate --work 0001
  pwn work status 0001
  pwn work run --work 0001 -- bun test
  pwn task capsule 1.1 0001
`);
}

export function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    showHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(`pwn v${VERSION}`);
    process.exit(0);
  }

  const command = args[0];
  const subcommand = args[1] || '';
  const commandArgs = args.slice(2);

  switch (command) {
    case 'work':
      handleWorkCommand(subcommand, commandArgs);
      break;

    case 'task':
      handleTaskCommand(subcommand, commandArgs);
      break;

    case 'validate':
      handleValidateCommand(args.slice(1));
      break;

    case 'self-check':
      handleSelfCheckCommand();
      break;

    case 'queue':
      handleQueueCommand(subcommand, commandArgs);
      break;

    case 'target':
      handleTargetCommand(subcommand, commandArgs);
      break;

    case 'metrics':
      handleMetricsCommand(subcommand, commandArgs);
      break;

    default:
      console.error(`Comando desconhecido: '${command}'`);
      showHelp();
      process.exit(1);
  }
}

main();
