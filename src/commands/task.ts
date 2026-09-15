import { generateContextCapsule } from '../core/capsule.js';
import { getLatestWorkId } from '../core/work-artifacts.js';
import { loadTaskContract } from '../core/task-contract.js';
import { runOrchestrated } from '../core/run-orchestrator.js';

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

export function handleTaskCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'run':
      console.log('=== [pwn task run] Executando task atômica sob contrato ===');
      {
        const workId = flagValue(args, '--work');
        const taskId = flagValue(args, '--task');
        const timeoutSeconds = Number(flagValue(args, '--timeout-seconds') ?? '600');
        const noIsolation = args.includes('--no-isolation');
        const separator = args.indexOf('--');
        const command = separator === -1 ? [] : args.slice(separator + 1);

        if (!workId || !taskId || command.length === 0) {
          console.error('Uso: pwn task run --work NNNN --task 1.1 --timeout-seconds N -- <comando>');
          process.exit(1);
        }

        const result = runOrchestrated({ workId, taskId, command, timeoutSeconds, isolated: !noIsolation });
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        if (result.diffViolations.length > 0) {
          console.error('\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:');
          result.diffViolations.forEach((v) => console.error(`  - ${v}`));
        }
        if (result.suspended) {
          console.error(`\n[SUSPENDED] A task ${taskId} do Work ${workId} não foi executada: aguarda decisão humana na fila AFK.`);
          console.error(`Use 'pwn queue approve ${result.runId}' para destravar (exit code ${result.status}).`);
        }
        process.exit(result.status);
      }
      break;

    case 'capsule':
      {
        const taskId = args[0];
        const workId = args[1] || getLatestWorkId();
        console.log(`=== [pwn task capsule] Context Capsule (contrato congelado V4) para ${taskId ?? '(task-id)'} ===\n`);

        if (!taskId) {
          console.error('Uso: pwn task capsule <task-id> [work-id]');
          process.exit(1);
        }

        try {
          const contract = loadTaskContract(workId, taskId);
          console.log(generateContextCapsule({ task: contract }));
          process.exit(0);
        } catch (err) {
          console.error(`✗ Não foi possível gerar a cápsula: ${(err as Error).message}`);
          console.error('  O contrato V4 deve estar congelado em .piwerness/work/<id>/<contract_id>.json.');
          process.exit(1);
        }
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn task': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn task run      Executa uma tarefa atômica isolada');
      console.log('  pwn task capsule  Gera a cápsula de contexto mínima para a task');
      process.exit(1);
  }
}
