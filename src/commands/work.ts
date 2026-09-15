import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId } from '../core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec, evaluateGateSpecPlan, evaluateGatePlanContract, GateOutput } from '../core/gates.js';
import { loadPlan, renderTasksMarkdown, planMatchesMarkdown, tasksMarkdownPath } from '../core/plan-renderer.js';
import { loadTaskContract } from '../core/task-contract.js';
import { importV3Work, listV3WorkIds } from '../core/v3-import.js';
import { scaffoldWork } from '../core/scaffold.js';
import type { RiskLevel } from '../core/contract-engine.js';
import { runOrchestrated } from '../core/run-orchestrator.js';
import { syncWorkManifest } from '../core/manifest-sync.js';
import { main as validatePromptMain } from '../core/validate_prompt.js';
import { main as validateTasksMain } from '../core/validate_tasks.js';
import { main as taskEvidenceMain } from '../core/task_evidence.js';
import { main as projectStatusMain } from '../core/project_status.js';
import fs from 'node:fs';
import path from 'node:path';

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

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
      process.exit(validatePromptMain(args));

    case 'contract':
      console.log('=== [pwn work contract] Validando contratos V4 congelados do Work ===');
      {
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const plan = loadPlan(workId);
        if (!plan) {
          console.error(`Nenhum plan.json encontrado em .piwerness/work/${workId}/. Rode 'pwn work init ${workId}' e defina as tasks antes de validar os contratos.`);
          process.exit(1);
        }

        console.log(`Work ${workId} — ${plan.tasks.length} task(s) no plano\n`);
        let failures = 0;
        for (const task of plan.tasks) {
          try {
            const contract = loadTaskContract(workId, task.id);
            if (!contract.risk?.level) throw new Error('risk.level ausente no contrato');
            if (!contract.scope_contract?.write_allow?.length) throw new Error('scope_contract.write_allow vazio');
            if (!contract.acceptance_contract?.commands?.length) {
              throw new Error('acceptance_contract.commands vazio (fail-closed: nenhuma execução seria autorizada)');
            }
            console.log(`✓ ${task.id} — ${task.contract_id} | risco ${contract.risk.level} | ${contract.validation_strategy}`);
            console.log(`    write_allow: ${contract.scope_contract.write_allow.join(', ')}`);
            console.log(`    aceitação:   ${contract.acceptance_contract.commands.join(' ; ')}`);
          } catch (err) {
            failures += 1;
            console.error(`✗ ${task.id} — ${(err as Error).message}`);
          }
        }

        if (failures > 0) {
          console.error(`\n[CONTRACT RESULT]: FAIL — ${failures} contrato(s) inválido(s) ou ausente(s). A execução ficaria bloqueada.`);
          process.exit(1);
        }
        console.log('\n[CONTRACT RESULT]: PASS — todos os contratos V4 estão congelados e utilizáveis.');
        process.exit(0);
      }
      break;

    case 'import':
      console.log('=== [pwn work import] Importando Works do layout v3 para o layout canônico ===');
      {
        const rootDir = path.resolve(flagValue(args, '--dir') ?? process.cwd());
        const requested = flagValue(args, '--work');
        const all = args.includes('--all');
        const force = args.includes('--force');
        const gateChain = args.includes('--gate-chain');
        const riskArg = flagValue(args, '--risk') ?? 'L2';

        const validRisks = ['auto', 'L0', 'L1', 'L2', 'L3', 'L4'];
        if (!validRisks.includes(riskArg)) {
          console.error(`--risk inválido: ${riskArg}. Opções: ${validRisks.join(', ')}`);
          process.exit(1);
        }
        const risk = riskArg as RiskLevel | 'auto';

        const available = listV3WorkIds(rootDir);
        if (available.length === 0) {
          console.error(`Nenhum Work v3 encontrado em ${path.join(rootDir, '.todo')} (esperado NNNN-tasks.md).`);
          process.exit(1);
        }

        const targets = requested ? [requested] : available;
        if (requested && !available.includes(requested) && !all) {
          console.warn(`⚠  Work ${requested} não está em .todo/ (${available.join(', ')}); tentando mesmo assim.`);
        }

        console.log(`Raiz: ${rootDir}`);
        console.log(`Works: ${targets.join(', ')} | risco: ${risk} | gate-chain: ${gateChain ? 'sim' : 'não'} | force: ${force ? 'sim' : 'não'}\n`);

        for (const workId of targets) {
          console.log(`── Work ${workId} ──`);
          try {
            const result = importV3Work({ rootDir, workId, force, risk, gateChain });
            console.log(`✓ ${result.generated.length} artefato(s) em .piwerness/work/${workId}/: ${result.generated.join(', ')}`);
            for (const skip of result.skipped) console.log(`  · ignorado ${skip.file}: ${skip.reason}`);
            for (const warning of result.warnings) console.warn(`  ! ${warning}`);
            const mapped = result.capabilityMapping.filter((entry) => entry.score > 0);
            if (mapped.length > 0) {
              console.log(`  capability mapping: ${mapped.map((entry) => `${entry.task}→${entry.capability}`).join(', ')}`);
            }
            const risks = [...new Set(result.riskMapping.map((entry) => entry.risk))].sort();
            if (risk === 'auto') {
              console.log(`  risco por task: ${result.riskMapping.map((entry) => `${entry.task}=${entry.risk}`).join(', ')}`);
            } else {
              console.log(`  risco congelado: ${risks.join(', ')}`);
            }
          } catch (err) {
            console.error(`✗ Work ${workId}: ${(err as Error).message}`);
            process.exit(1);
          }
          console.log('');
        }

        console.log('ℹ  Os artefatos v3 (.work/, .todo/, .prompts/, .sources/, .specs/) não foram alterados.');
        console.log('   Próximos passos: pwn work contract --work <id> | pwn work plan --work <id> | pwn validate');
        process.exit(0);
      }
      break;

    case 'scaffold':
      console.log('=== [pwn work scaffold] Criando cadeia completa e válida de Work ===');
      {
        const rootDir = path.resolve(flagValue(args, '--dir') ?? process.cwd());
        const title = flagValue(args, '--title');
        const workId = flagValue(args, '--work') ?? undefined;
        const sourcePath = flagValue(args, '--source') ?? undefined;
        const force = args.includes('--force');
        const risk = (flagValue(args, '--risk') ?? 'L2') as RiskLevel;

        if (!title) {
          console.error('Uso: pwn work scaffold --title "<titulo>" [--work NNNN] [--source spec.md] [--risk Lx] [--dir PATH] [--force]');
          process.exit(1);
        }
        const validRisks: RiskLevel[] = ['L0', 'L1', 'L2', 'L3', 'L4'];
        if (!validRisks.includes(risk)) {
          console.error(`--risk inválido: ${risk}. Opções: ${validRisks.join(', ')}`);
          process.exit(1);
        }

        try {
          const result = scaffoldWork({ rootDir, title, workId, sourcePath, risk, force });
          console.log(`✓ Work ${result.workId} criado em ${result.workDir}`);
          console.log(`Artefatos gerados (${result.generated.length}):`);
          for (const file of result.generated) console.log(`  + ${file}`);
          for (const skip of result.skipped) console.log(`  · ignorado ${skip.file}: ${skip.reason}`);
          console.log('\nRevisão obrigatória antes de implementar:');
          for (const note of result.review) console.log(`  ! ${note}`);
          console.log(`\nPróximos passos:\n  pwn work contract --work ${result.workId}\n  pwn work gate GATE-PLAN-CONTRACT --work ${result.workId}\n  pwn validate --work ${result.workId}\n  pwn task capsule 1.1 ${result.workId}`);
        } catch (err) {
          console.error(`✗ ${(err as Error).message}`);
          process.exit(1);
        }
        process.exit(0);
      }
      break;

    case 'plan':
      console.log('=== [pwn work plan] Planejando / Validando Grafo de Tarefas ===');
      {
        const hasForce = args.includes('--force');
        const workIdIdx = args.indexOf('--work');
        const flagWorkId = (workIdIdx !== -1 && args[workIdIdx + 1] && !args[workIdIdx + 1].startsWith('--'))
          ? args[workIdIdx + 1]
          : null;
        const positional = args.filter((a) => !a.startsWith('--') && a !== flagWorkId);
        const pathArg = positional[0] ?? null;
        const filenameMatch = pathArg ? path.basename(pathArg).match(/^(\d{4})-tasks\.md$/) : null;

        const workId = flagWorkId ?? (filenameMatch ? filenameMatch[1] : getLatestWorkId());
        const plan = loadPlan(workId);

        if (plan) {
          const rendered = renderTasksMarkdown(plan);
          const target = pathArg ?? tasksMarkdownPath(workId);

          if (!fs.existsSync(target)) {
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, rendered, 'utf8');
            console.log(`✓ Plano gerado a partir de plan.json em: ${target}`);
          } else if (hasForce) {
            fs.writeFileSync(target, rendered, 'utf8');
            console.log(`✓ Plano regenerado (--force) em: ${target}`);
          } else if (!planMatchesMarkdown(plan, fs.readFileSync(target, 'utf8'))) {
            console.warn('⚠  DRIFT: o markdown diverge de plan.json (edição manual ou fora de sincronia).');
            console.warn(`   Regenere com: pwn work plan --work ${workId} --force`);
          }

          process.exit(validateTasksMain([target]));
        }

        if (!pathArg) {
          console.error(`Nenhum plan.json encontrado para o Work ${workId}. Rode 'pwn work init' e crie .piwerness/work/${workId}/plan.json, ou informe um caminho de plano markdown.`);
          process.exit(1);
        }
        process.exit(validateTasksMain([pathArg]));
      }
      break;

    case 'run':
      console.log('=== [pwn work run] Executando Work via Pipeline ===');
      {
        const hasNoGate = args.includes('--no-gate');
        const noIsolation = args.includes('--no-isolation');
        const noSync = args.includes('--no-sync');
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const taskId = flagValue(args, '--task');
        const timeoutSeconds = Number(flagValue(args, '--timeout-seconds') ?? '600');
        const separator = args.indexOf('--');
        const command = separator === -1 ? [] : args.slice(separator + 1);

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

          // ── Guarda de drift: plan.json é a fonte única; o markdown derivado não pode divergir ──
          const runPlan = loadPlan(workId);
          if (runPlan) {
            const mdPath = tasksMarkdownPath(workId);
            if (fs.existsSync(mdPath) && !planMatchesMarkdown(runPlan, fs.readFileSync(mdPath, 'utf8'))) {
              console.error(`\n[DRIFT BLOCKED] .todo/${workId}-tasks.md diverge de plan.json. Regenere com 'pwn work plan --work ${workId} --force' ou resolva a divergência.`);
              process.exit(1);
            }
          }

          console.log('✓ Todos os gates determinísticos aprovados — Work elegível para execução.');
        } else {
          console.warn('⚠  Gates bypassados (--no-gate): execução sem validação da cadeia determinística.');
        }

        if (noIsolation) {
          console.warn('⚠  Sandbox desabilitado (--no-isolation): execução no diretório de trabalho, sem diff guard.');
        }

        if (command.length === 0) {
          console.error('Nenhum comando informado. Uso: pwn work run --work NNNN --timeout-seconds N -- <comando>');
          process.exit(1);
        }

        // ── Execução sob contrato (sandbox + diff guard + budget + métricas) ──
        const result = runOrchestrated({ workId, taskId: taskId ?? undefined, command, timeoutSeconds, isolated: !noIsolation });
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        if (result.diffViolations.length > 0) {
          console.error('\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:');
          result.diffViolations.forEach((v) => console.error(`  - ${v}`));
        }
        if (taskId && result.status !== 0 && !result.suspended) {
          console.error(`[RUN FAILED] Execução terminou com status ${result.status} para a task ${taskId} (work ${workId}).`);
        }
        if (result.suspended) {
          console.error(`\n[SUSPENDED] A task ${taskId ?? '(work)'} do Work ${workId} não foi executada: aguarda decisão humana na fila AFK.`);
          console.error(`Use 'pwn queue approve ${result.runId}' para destravar (exit code ${result.status}).`);
          // Suspensão L4 não altera estado de governança.
        } else if (noSync) {
          console.log(`· Manifest .work/${workId}.json não sincronizado (--no-sync).`);
        } else {
          const syncState = syncWorkManifest(workId);
          if (syncState !== 'manifest-ausente') {
            console.log(`✓ Manifest .work/${workId}.json → state: ${syncState}`);
          }
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
        process.exit(taskEvidenceMain(auditArgs));
      }
      break;

    case 'status':
      console.log('=== [pwn work status] Relatório de Status do Work ===');
      process.exit(projectStatusMain(args));

    case 'sync':
      console.log('=== [pwn work sync] Sincronizando estado do manifest .work/NNNN.json ===');
      {
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const state = syncWorkManifest(workId);
        if (state === 'manifest-ausente') {
          console.error(`Manifest .work/${workId}.json não encontrado. Nada a sincronizar.`);
          process.exit(1);
        }
        console.log(`✓ Manifest .work/${workId}.json → state: ${state}`);
        process.exit(0);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn work': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn work init <id>  Inicializa diretório de artefatos sob .piwerness/work/<id>/');
      console.log('  pwn work import    Importa Works do layout v3 (.work/, .todo/) para o layout canônico');
      console.log('  pwn work scaffold  Cria um Work novo com cadeia completa (discovery→prd→spec→plan+CTR)');
      console.log('  pwn work gate <id>  Executa gate determinístico (GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC)');
      console.log('  pwn work specify   Especifica mudanças no baseline');
      console.log('  pwn work contract  Valida os contratos V4 congelados (.piwerness/work/<id>/CTR-*.json)');
      console.log('  pwn work plan      Valida o grafo e o plano de tarefas');
      console.log('  pwn work run       Executa tarefas do work de forma autônoma (--no-gate, --no-isolation, --no-sync)');
      console.log('  pwn work audit     Audita aceitação e evidência TDD');
      console.log('  pwn work status    Exibe o status do progresso do projeto');
      console.log('  pwn work sync      Sincroniza o estado do manifest .work/NNNN.json com o plano');
      process.exit(1);
  }
}
