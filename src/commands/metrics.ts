import { readMetrics, generateOptimizationSuggestions } from '../core/metrics.js';

export function handleMetricsCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'list':
      console.log('=== [pwn metrics list] Telemetria e Consumo de Métricas ===\n');
      {
        const entries = readMetrics();
        if (entries.length === 0) {
          console.log('Nenhuma métrica registrada em .pwn/metrics.jsonl ainda.');
        } else {
          let totalCost = 0;
          let totalTokens = 0;

          entries.forEach(e => {
            totalCost += e.costUSD;
            totalTokens += e.tokensInput + e.tokensOutput;
            console.log(`[${e.status.toUpperCase()}] Run: ${e.runId} | Task: ${e.taskId} | Role: ${e.agentRole} (${e.model})`);
            console.log(`  Tokens: ${e.tokensInput + e.tokensOutput} | Custo: $${e.costUSD.toFixed(4)} | Duração: ${e.durationMs}ms | Tentativas: ${e.attempts} | Sandbox: ${e.isolated ? 'sim' : 'NÃO (--no-isolation)'}\n`);
          });

          console.log('--------------------------------------------------------------------------------');
          console.log(`Total de Execuções: ${entries.length}`);
          console.log(`Consumo Total de Tokens: ${totalTokens}`);
          console.log(`Custo Total Estimado: $${totalCost.toFixed(4)} USD`);
        }
        process.exit(0);
      }
      break;

    case 'optimize':
      console.log('=== [pwn metrics optimize] Sugestões Declarativas de Otimização de Routing ===\n');
      {
        const suggestions = generateOptimizationSuggestions();
        if (suggestions.length === 0) {
          console.log('Sem histórico de métricas suficiente para recomendar otimização de routing.');
          console.log('Rode tarefas com "pwn work run" primeiro; as sugestões aparecem quando houver execuções registradas.');
          process.exit(0);
        }
        suggestions.forEach((s, idx) => {
          console.log(`[Sugestão #${idx + 1}] Papel Atual: ${s.agentRole} (${s.currentModel}) -> Recomendado: ${s.recommendedRole}`);
          console.log(`  Motivo: ${s.reason}`);
          console.log(`  Economia Estimada: ${s.estimatedSavingsPercent}%\n`);
        });
        console.log('NOTA: Nenhuma alteração de arquivo é feita automaticamente. As recomendações são apenas consultivas.');
        process.exit(0);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn metrics': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn metrics list       Exibe o histórico de métricas e custos registrados');
      console.log('  pwn metrics optimize   Gera sugestões de otimização de routing de modelos');
      process.exit(1);
  }
}
