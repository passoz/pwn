import { runPackScript } from '../core/runner.js';
import fs from 'node:fs';
import path from 'node:path';

export function handleWorkCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'specify':
      console.log('=== [pwn work specify] Especificando mudança / baseline ===');
      {
        const result = runPackScript('validate_prompt.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'contract':
      console.log('=== [pwn work contract] Gerenciando contrato de Work ===');
      {
        const result = runPackScript('validate_prompt.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'plan':
      console.log('=== [pwn work plan] Planejando / Validando Grafo de Tarefas ===');
      {
        const result = runPackScript('validate_tasks.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'run':
      console.log('=== [pwn work run] Executando Work via Pipeline ===');
      {
        const result = runPackScript('unattended_exec.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'audit':
      console.log('=== [pwn work audit] Auditando Evidências e Aceitação ===');
      {
        const result = runPackScript('task_evidence.js', ['--audit', ...args]);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    case 'status':
      console.log('=== [pwn work status] Relatório de Status do Work ===');
      {
        const result = runPackScript('project_status.js', args);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        process.exit(result.status);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn work': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn work specify   Especifica mudanças no baseline');
      console.log('  pwn work contract  Valida/gera contratos de trabalho');
      console.log('  pwn work plan      Valida o grafo e o plano de tarefas');
      console.log('  pwn work run       Executa tarefas do work de forma autônoma');
      console.log('  pwn work audit     Audita aceitação e evidência TDD');
      console.log('  pwn work status    Exibe o status do progresso do projeto');
      process.exit(1);
  }
}
