import { runPackScript } from '../core/runner.js';
import { initWorkDirectory, getWorkArtifactsPaths } from '../core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec } from '../core/gates.js';
import fs from 'node:fs';
import path from 'node:path';

export function handleWorkCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'init':
      {
        const workId = args[0] || '0001';
        console.log(`=== [pwn work init] Inicializando estrutura de artefatos para Work ${workId} ===`);
        const paths = initWorkDirectory(workId);
        console.log(`✓ Estrutura criada em: ${paths.workDir}`);
        console.log('Artefatos gerados: intake.json, discovery.json, requirements.json, prd.json, traceability-matrix.json');
        process.exit(0);
      }
      break;

    case 'gate':
      {
        const gateId = args[0] || 'GATE-DISC-REQ';
        const workIdIdx = args.indexOf('--work');
        const workId = (workIdIdx !== -1 && args[workIdIdx + 1]) ? args[workIdIdx + 1] : '0001';

        console.log(`=== [pwn work gate] Executando Gate ${gateId} para Work ${workId} ===`);
        const paths = getWorkArtifactsPaths(workId);

        let output;
        if (gateId === 'GATE-DISC-REQ') {
          output = evaluateGateDiscReq(workId, paths.workDir);
        } else if (gateId === 'GATE-REQ-PRD') {
          output = evaluateGateReqPrd(workId, paths.workDir);
        } else if (gateId === 'GATE-PRD-SPEC') {
          output = evaluateGatePrdSpec(workId, paths.workDir);
        } else {
          console.error(`Gate desconhecido: ${gateId}. Opções: GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC`);
          process.exit(1);
        }

        console.log(JSON.stringify(output, null, 2));

        if (output.result === 'blocked') {
          console.error(`\n[GATE RESULT]: BLOCKED — Existem lacunas ou conflitos materiais no Work ${workId}.`);
          process.exit(1);
        } else {
          console.log(`\n[GATE RESULT]: ${output.result.toUpperCase()} — Gate aprovado.`);
          process.exit(0);
        }
      }
      break;
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
      console.log('  pwn work init <id>  Inicializa diretório de artefatos sob .piwerness/work/<id>/');
      console.log('  pwn work gate <id>  Executa gate determinístico (GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC)');
      console.log('  pwn work specify   Especifica mudanças no baseline');
      console.log('  pwn work contract  Valida/gera contratos de trabalho');
      console.log('  pwn work plan      Valida o grafo e o plano de tarefas');
      console.log('  pwn work run       Executa tarefas do work de forma autônoma');
      console.log('  pwn work audit     Audita aceitação e evidência TDD');
      console.log('  pwn work status    Exibe o status do progresso do projeto');
      process.exit(1);
  }
}
