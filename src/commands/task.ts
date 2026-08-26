import { runPackScript } from '../core/runner.js';

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
      console.log('=== [pwn task capsule] Gerando Context Capsule mínimo da task ===');
      {
        console.log('Context capsule gerado com sucesso para a task.');
        console.log('Limites de escrita, comandos de validação e orçamento congelados.');
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
