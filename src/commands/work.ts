import { runPackScript } from '../core/runner.js';
import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId } from '../core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec, evaluateGateSpecPlan, evaluateGatePlanContract, GateOutput } from '../core/gates.js';
import fs from 'node:fs';
import path from 'node:path';

export function handleWorkCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'init':
      {
        const requestedId = args[0] && !args[0].startsWith('--') ? args[0] : getNextWorkId();
        const paths = initWorkDirectory(requestedId);
        const resolvedId = path.basename(paths.workDir);

        console.log(`=== [pwn work init] Inicializando estrutura de artefatos para Work ${resolvedId} ===`);
        console.log(`✓ Estrutura criada em: ${paths.workDir}`);
        console.log('Artefatos gerados: intake.json, discovery.json, requirements.json, prd.json, traceability-matrix.json');
        process.exit(0);
      }
      break;

    case 'gate':
      {
        const gateId = args[0] || 'GATE-DISC-REQ';
        const workIdIdx = args.indexOf('--work');
        const workId = (workIdIdx !== -1 && args[workIdIdx + 1]) ? args[workIdIdx + 1] : getLatestWorkId();

        console.log(`=== [pwn work gate] Executando Gate ${gateId} para Work ${workId} ===`);
        const paths = getWorkArtifactsPaths(workId);

        let output;
        if (gateId === 'GATE-DISC-REQ') {
          output = evaluateGateDiscReq(workId, paths.workDir);
        } else if (gateId === 'GATE-REQ-PRD') {
          output = evaluateGateReqPrd(workId, paths.workDir);
        } else if (gateId === 'GATE-PRD-SPEC') {
          output = evaluateGatePrdSpec(workId, paths.workDir);
        } else if (gateId === 'GATE-SPEC-PLAN') {
          output = evaluateGateSpecPlan(workId, paths.workDir);
        } else if (gateId === 'GATE-PLAN-CONTRACT') {
          output = evaluateGatePlanContract(workId, paths.workDir);
        } else {
          console.error(`Gate desconhecido: ${gateId}. Opções: GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC, GATE-SPEC-PLAN, GATE-PLAN-CONTRACT`);
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
        const hasNoGate = args.includes('--no-gate');
        const workIdIdx = args.indexOf('--work');
        const workId = (workIdIdx !== -1 && args[workIdIdx + 1] && !args[workIdIdx + 1].startsWith('--'))
          ? args[workIdIdx + 1]
          : getLatestWorkId();
        const taskIdIdx = args.indexOf('--task');
        const taskId = (taskIdIdx !== -1 && args[taskIdIdx + 1] && !args[taskIdIdx + 1].startsWith('--'))
          ? args[taskIdIdx + 1]
          : null;

        // Remove flags de controle antes de delegar ao executor.
        const execArgs: string[] = [];
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--no-gate') continue;
          if ((args[i] === '--work' || args[i] === '--task') && i + 1 < args.length && !args[i + 1].startsWith('--')) {
            i++;
            continue;
          }
          execArgs.push(args[i]);
        }

        // ── Pré-condição obrigatória: cadeia determinística de 5 gates ──
        if (!hasNoGate) {
          const paths = getWorkArtifactsPaths(workId);
          if (!fs.existsSync(paths.workDir)) {
            console.error(`\n[GATE BLOCKED] Work ${workId} não existe em ${paths.workDir}. Rode 'pwn work init ${workId}' e complete a cadeia de artefatos antes de 'pwn work run'.`);
            process.exit(1);
          }

          const gateChain: Array<[string, () => GateOutput]> = [
            ['GATE-DISC-REQ', () => evaluateGateDiscReq(workId, paths.workDir)],
            ['GATE-REQ-PRD', () => evaluateGateReqPrd(workId, paths.workDir)],
            ['GATE-PRD-SPEC', () => evaluateGatePrdSpec(workId, paths.workDir)],
            ['GATE-SPEC-PLAN', () => evaluateGateSpecPlan(workId, paths.workDir)],
            ['GATE-PLAN-CONTRACT', () => evaluateGatePlanContract(workId, paths.workDir)],
          ];

          let blocked = false;
          for (const [gateId, evalGate] of gateChain) {
            const gate = evalGate();
            console.log(JSON.stringify(gate, null, 2));
            if (gate.result === 'blocked') {
              console.error(`\n[GATE BLOCKED] ${gateId} bloqueou o Work ${workId}. Resolva os findings ou use --no-gate somente se o risco for aceito por humano.`);
              blocked = true;
              break;
            }
            console.log(`✓ ${gateId}: ${gate.result}`);
          }
          if (blocked) process.exit(1);
          console.log('✓ Todos os gates determinísticos aprovados — Work elegível para execução.');
        } else {
          console.warn('⚠  Gates bypassados (--no-gate): execução sem validação da cadeia determinística.');
        }

        // ── Execução ──
        const result = runPackScript('unattended_exec.js', execArgs);
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        if (taskId && result.status !== 0) {
          console.error(`[RUN FAILED] Execução terminou com status ${result.status} para a task ${taskId} (work ${workId}).`);
        }

        process.exit(result.status);
      }
      break;

    case 'audit':
      console.log('=== [pwn work audit] Auditando Evidências e Aceitação ===');
      {
        const knownActions = ['baseline', 'red', 'green', 'verify', 'check', 'candidate'];
        // Compat: sem ação explícita, o audit roda a verificação de evidência (verify).
        const auditArgs = args.length > 0 && knownActions.includes(args[0])
          ? [...args]
          : ['verify', ...args];
        const result = runPackScript('task_evidence.js', auditArgs);
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
