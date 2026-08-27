import { runPackScript } from '../core/runner.js';
import { createDefaultContractV4 } from '../core/contract-engine.js';
import { generateContextCapsule } from '../core/capsule.js';
import { getLatestWorkId } from '../core/work-artifacts.js';

export function handleTaskCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'run':
      console.log('=== [pwn task run] Executando task atômica ===');
      {
        const result = runPackScript('unattended_exec.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'capsule':
      {
        const taskId = args[0] || 'T-001';
        const workId = args[1] || getLatestWorkId();
        console.log(`=== [pwn task capsule] Gerando Context Capsule mínimo para ${taskId} ===\n`);

        const defaultContract = createDefaultContractV4(taskId, workId, `Implementação da Task ${taskId}`, 'L1');
        const capsuleText = generateContextCapsule({ task: defaultContract });

        console.log(capsuleText);
        process.exit(0);
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
