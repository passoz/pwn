import { listQueueItems, updateQueueStatus } from '../core/queue.js';

export function handleQueueCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'list':
      console.log('=== [pwn queue list] Fila de Revisão Humana (AFK) ===\n');
      {
        const items = listQueueItems();
        if (items.length === 0) {
          console.log('Nenhuma tarefa pendente na fila de revisão queue/review/.');
        } else {
          items.forEach(item => {
            console.log(`[${item.status.toUpperCase()}] Run: ${item.runId} | Work: ${item.workId} | Task: ${item.taskId}`);
            console.log(`  Título: ${item.title}`);
            console.log(`  Motivo: ${item.reason} (Risco: ${item.riskLevel})`);
            console.log(`  Pausado em: ${item.pausedAtStep} | Criado em: ${item.createdAt}\n`);
          });
        }
        process.exit(0);
      }
      break;

    case 'approve':
      {
        const runId = args[0];
        if (!runId) {
          console.error('Uso: pwn queue approve <run-id>');
          process.exit(1);
        }
        const updated = updateQueueStatus(runId, 'approved');
        if (updated) {
          console.log(`✓ Run ${runId} aprovada com sucesso! O pipeline pode ser retomado.`);
          process.exit(0);
        } else {
          console.error(`Run ${runId} não encontrada na fila de revisão.`);
          process.exit(1);
        }
      }
      break;

    case 'reject':
      {
        const runId = args[0];
        if (!runId) {
          console.error('Uso: pwn queue reject <run-id>');
          process.exit(1);
        }
        const updated = updateQueueStatus(runId, 'rejected');
        if (updated) {
          console.log(`✗ Run ${runId} rejeitada. A execução foi cancelada.`);
          process.exit(0);
        } else {
          console.error(`Run ${runId} não encontrada na fila de revisão.`);
          process.exit(1);
        }
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn queue': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn queue list      Lista itens em aguardo na fila de revisão AFK');
      console.log('  pwn queue approve   Aprova um item suspenso na fila');
      console.log('  pwn queue reject    Rejeita um item suspenso na fila');
      process.exit(1);
  }
}
