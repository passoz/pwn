import { handleWorkCommand } from './commands/work.js';
import { handleTaskCommand } from './commands/task.js';
import { handleValidateCommand } from './commands/validate.js';
import { handleSkillCommand } from './commands/skill.js';
import { handlePackCommand } from './commands/pack.js';

const VERSION = '0.1.0';

function showHelp(): void {
  console.log(`
Piwerness CLI (pwn) v${VERSION} — Contract-Governed Agent Harness

USO:
  pwn <comando> <subcomando> [opções]

COMANDOS DISPONÍVEIS:
  work <subcomando>   Gerencia a cadeia de planejamento e execução de Works
                      (specify, contract, plan, run, audit, status)
  task <subcomando>   Gerencia tarefas atômicas isoladas
                      (run, capsule)
  validate [path]     Valida documentos normativos JSON contra JSON Schemas
  skill <subcomando>  Descobre, lista e vincula skills do harness
                      (list, discover, link)
  pack <subcommand>   Gerencia packs de domínio (ex: software-engineering)
                      (list, diff)

OPÇÕES:
  --help, -h          Exibe esta mensagem de ajuda
  --version, -v       Exibe a versão do pwn

EXEMPLOS:
  pwn validate
  pwn work status
  pwn work plan
  pwn task capsule
  pwn skill list
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

    case 'skill':
      handleSkillCommand(subcommand, commandArgs);
      break;

    case 'pack':
      handlePackCommand(subcommand, commandArgs);
      break;

    default:
      console.error(`Comando desconhecido: '${command}'`);
      showHelp();
      process.exit(1);
  }
}

main();
