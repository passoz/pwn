import { TARGET_CAPABILITY_MATRIX, TargetRuntime } from '../core/target-materializer.js';
import { materializePiTarget } from '../targets/pi.js';
import { materializeOpenCodeTarget } from '../targets/opencode.js';
import { materializeOmpTarget } from '../targets/omp.js';
import path from 'node:path';

export function handleTargetCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'list':
      console.log('=== [pwn target list] Runtimes e Matriz de Capacidades ===\n');
      Object.values(TARGET_CAPABILITY_MATRIX).forEach(cap => {
        console.log(`• Target: ${cap.target.toUpperCase()} (${cap.name})`);
        console.log(`  System Prompt:       ${cap.supportsSystemPrompt ? '✓' : '✗'}`);
        console.log(`  Subagents:           ${cap.supportsSubagents ? '✓' : '✗'}`);
        console.log(`  Skills:              ${cap.supportsSkills ? '✓' : '✗'}`);
        console.log(`  Tool Calling:        ${cap.supportsToolCalling ? '✓' : '✗'}`);
        console.log(`  Contratos V4:        ${cap.supportsContractV4 ? '✓' : '✗'}`);
        console.log(`  Worktree Sandbox:    ${cap.supportsWorktreeSandbox ? '✓' : '✗'}`);
        console.log(`  Formato Principal:   ${cap.promptFileFormat}\n`);
      });
      process.exit(0);
      break;

    case 'materialize':
      {
        const targetIdx = args.indexOf('--target');
        const targetName = (targetIdx !== -1 && args[targetIdx + 1]) ? args[targetIdx + 1] as TargetRuntime : 'pi';

        const outIdx = args.indexOf('--out');
        const outDir = (outIdx !== -1 && args[outIdx + 1]) ? args[outIdx + 1] : path.resolve(process.cwd(), `.piwerness/targets/${targetName}`);

        console.log(`=== [pwn target materialize] Materializando artefatos para ${targetName.toUpperCase()} ===`);

        let result;
        if (targetName === 'pi') {
          result = materializePiTarget(outDir);
        } else if (targetName === 'opencode') {
          result = materializeOpenCodeTarget(outDir);
        } else if (targetName === 'omp') {
          result = materializeOmpTarget(outDir);
        } else {
          console.error(`Target desconhecido ou não suportado para materialização automática: ${targetName}`);
          process.exit(1);
        }

        console.log(`✓ Materialização concluída com sucesso em: ${outDir}`);
        console.log('Arquivos Gerados:');
        result.generatedFiles.forEach(f => console.log(`  + ${f}`));

        if (result.notes.length > 0) {
          console.log('\nNotas de Adaptação:');
          result.notes.forEach(n => console.log(`  ! ${n}`));
        }

        if (result.unsupportedCapabilities.length > 0) {
          console.log('\nCapacidades Não Suportadas (Degradação Graciosa):');
          result.unsupportedCapabilities.forEach(c => console.log(`  - ${c}`));
        }

        process.exit(0);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn target': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn target list                           Exibe a matriz de capacidades');
      console.log('  pwn target materialize --target <target>  Materializa artefatos no diretório target');
      process.exit(1);
  }
}
