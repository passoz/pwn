import { initWorkDirectory, getWorkArtifactsPaths, getNextWorkId, getLatestWorkId } from '../core/work-artifacts.js';
import { evaluateGateDiscReq, evaluateGateReqPrd, evaluateGatePrdSpec, evaluateGateSpecPlan, evaluateGatePlanContract, evaluateAllGates, computeWorkCoverage, GateOutput } from '../core/gates.js';
import { readGateCache, writeGateCache, clearGateCache } from '../core/gate-cache.js';
import { loadPlan, renderTasksMarkdown, planMatchesMarkdown, tasksMarkdownPath } from '../core/plan-renderer.js';
import { freezeAcceptanceTests, loadTaskContract } from '../core/task-contract.js';
import { importV3Work, listV3WorkIds } from '../core/v3-import.js';
import { scaffoldWork } from '../core/scaffold.js';
import { reconcileChanges } from '../core/reconcile.js';
import type { RiskLevel } from '../core/contract-engine.js';
import { runOrchestrated } from '../core/run-orchestrator.js';
import { syncWorkManifest } from '../core/manifest-sync.js';
import { reportAutoVerification, verifyAfterRun, type AutoVerification } from '../core/acceptance-flow.js';
import { main as validatePromptMain } from '../core/validate_prompt.js';
import { main as validateTasksMain } from '../core/validate_tasks.js';
import { main as taskEvidenceMain } from '../core/task_evidence.js';
import { main as projectStatusMain } from '../core/project_status.js';
import { handleBatchCommand } from './batch.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listWorks } from '../core/work-manifest.js';
import { loadWorkContracts } from '../core/task-contract.js';
import { globsMayOverlap } from '../core/scope-overlap.js';
import { defaultConcurrency, runPool, type PoolJob, type PoolResult } from '../core/process-pool.js';

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

// ── run-all: pool de subprocessos `pwn work run`, um por Work ──────────────────
// O core é síncrono; a paralelização é na camada de PROCESSO. Cada subprocesso cria
// o próprio worktree (RUN-<id único>) e roda o Diff Guard; Works distintos têm
// árvores de artefatos separadas.

const CLI_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'cli.ts');
const EXIT_TIMEOUT = 124;

export interface RunAllOptions {
  /** `--works` explícito; `null` = todos os Works com plano. */
  works: string[] | null;
  jobs: number | null;
  timeoutSeconds: number;
  noGate: boolean;
  /** Comando de aceitação após `--` (vazio se ausente). */
  command: string[];
}

/** Interpreta os argumentos de `pwn work run-all`; lança `Error` (pt-BR) em uso inválido. */
export function parseRunAllArgs(args: string[]): RunAllOptions {
  const separator = args.indexOf('--');
  const own = separator === -1 ? args : args.slice(0, separator);
  const command = separator === -1 ? [] : args.slice(separator + 1);

  const worksRaw = flagValue(own, '--works');
  if (own.includes('--works') && worksRaw === null) throw new Error('--works exige uma lista separada por vírgula (ex.: --works 0001,0002)');
  const works = worksRaw === null
    ? null
    : [...new Set(worksRaw.split(',').map((id) => id.trim()).filter(Boolean))];
  if (works && works.length === 0) throw new Error('--works está vazio');

  const jobsRaw = flagValue(own, '--jobs');
  if (own.includes('--jobs') && jobsRaw === null) throw new Error('--jobs exige um inteiro positivo');
  const jobs = jobsRaw === null ? null : Number(jobsRaw);
  if (jobs !== null && (!Number.isInteger(jobs) || jobs < 1)) throw new Error(`--jobs inválido: '${jobsRaw}' (esperado inteiro >= 1)`);

  const timeoutRaw = flagValue(own, '--timeout-seconds');
  if (own.includes('--timeout-seconds') && timeoutRaw === null) throw new Error('--timeout-seconds exige um número positivo');
  const timeoutSeconds = timeoutRaw === null ? 600 : Number(timeoutRaw);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) throw new Error(`--timeout-seconds inválido: '${timeoutRaw}' (esperado número > 0)`);

  return { works, jobs, timeoutSeconds, noGate: own.includes('--no-gate'), command };
}

/** Monta um job `bun cli.ts work run --work W …` por Work, repassando flags e o `--`. */
export function buildRunAllJobs(args: string[], works: string[]): PoolJob[] {
  const options = parseRunAllArgs(args);
  return works.map((workId) => ({
    id: workId,
    command: [
      process.execPath,
      CLI_PATH,
      'work',
      'run',
      '--work',
      workId,
      ...(options.noGate ? ['--no-gate'] : []),
      '--timeout-seconds',
      String(options.timeoutSeconds),
      '--',
      ...options.command,
    ],
  }));
}

export interface ScopeOverlap {
  works: [string, string];
  /** Pares de globs (um de cada Work) que podem casar o mesmo arquivo. */
  patterns: Array<[string, string]>;
}

export interface ScopedContract {
  scope_contract: { write_allow: string[] };
}

/** Detecta, para cada par de Works, globs de `write_allow` (união dos contratos) que se sobrepõem. */
export function findScopeOverlaps(contractsByWork: Record<string, ScopedContract[]>): ScopeOverlap[] {
  const unions = Object.entries(contractsByWork).map(([workId, contracts]) => ({
    workId,
    patterns: [...new Set(contracts.flatMap((contract) => contract.scope_contract?.write_allow ?? []))],
  }));
  const overlaps: ScopeOverlap[] = [];
  for (let i = 0; i < unions.length; i++) {
    for (let j = i + 1; j < unions.length; j++) {
      const patterns: Array<[string, string]> = [];
      for (const a of unions[i].patterns) {
        for (const b of unions[j].patterns) {
          if (globsMayOverlap(a, b)) patterns.push([a, b]);
        }
      }
      if (patterns.length > 0) overlaps.push({ works: [unions[i].workId, unions[j].workId], patterns });
    }
  }
  return overlaps;
}

/** Exit code agregado: 0 só se todos 0; senão o maior exit code não-zero (timeout conta 124). */
export function aggregateExitCodes(results: Array<Pick<PoolResult, 'status' | 'timedOut'>>): number {
  let worst = 0;
  for (const result of results) {
    const code = result.timedOut ? EXIT_TIMEOUT : result.status;
    if (code !== 0 && code > worst) worst = code;
  }
  return worst;
}

function prefixLines(workId: string, text: string): string[] {
  return text.replace(/\n+$/, '').split('\n').map((line) => `[${workId}] ${line}`);
}

function parseRunId(result: PoolResult): string | null {
  return /\bRUN-[A-Za-z0-9_-]+/.exec(`${result.stdout}\n${result.stderr}`)?.[0] ?? null;
}

async function runAllCommand(args: string[]): Promise<number> {
  console.log('=== [pwn work run-all] Executando Works em paralelo (um subprocesso por Work) ===');
  let options: RunAllOptions;
  try {
    options = parseRunAllArgs(args);
  } catch (err) {
    console.error(`✗ ${(err as Error).message}`);
    console.error('Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando de aceitação>');
    return 1;
  }
  if (options.command.length === 0) {
    console.error('Nenhum comando informado. Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando>');
    return 1;
  }

  const rootDir = process.cwd();
  const works = options.works
    ?? listWorks(rootDir).filter((work) => work.work_id !== 'legacy' && work.plan_exists).map((work) => work.work_id);
  if (works.length === 0) {
    console.error('Nenhum Work com plano encontrado. Informe --works NNNN,NNNN ou rode `pwn work scaffold`.');
    return 1;
  }

  // Pré-checagem (não bloqueia): escopos sobrepostos entre Works podem conflitar no merge.
  const contractsByWork: Record<string, ScopedContract[]> = {};
  for (const workId of works) {
    try {
      contractsByWork[workId] = loadWorkContracts(workId, rootDir);
    } catch (err) {
      console.warn(`⚠  Work ${workId}: contratos não carregados para a checagem de escopo (${(err as Error).message}).`);
    }
  }
  for (const overlap of findScopeOverlaps(contractsByWork)) {
    const sample = overlap.patterns.slice(0, 3).map(([a, b]) => `${a} ↔ ${b}`).join('; ');
    console.warn(`⚠  Possível conflito de merge entre Works ${overlap.works[0]} e ${overlap.works[1]}: write_allow sobreposto (${sample}${overlap.patterns.length > 3 ? '; …' : ''}). Cada um roda em worktree isolado.`);
  }

  const jobs = buildRunAllJobs(args, works);
  const concurrency = options.jobs ?? defaultConcurrency();
  console.log(`· ${jobs.length} Work(s): ${works.join(', ')} | jobs=${Math.min(concurrency, jobs.length)}`);

  const results = await runPool(jobs, {
    concurrency,
    // Rede de segurança acima do timeout do comando (gates + sandbox + verificação).
    timeoutMs: options.timeoutSeconds * 1000 + 60_000,
    onResult: (result) => {
      for (const line of prefixLines(result.id, result.stdout)) console.log(line);
      for (const line of prefixLines(result.id, result.stderr)) console.error(line);
      if (result.timedOut) console.error(`[${result.id}] ✗ Subprocesso excedeu o tempo limite e foi encerrado.`);
    },
  });

  console.log('\n── Resumo run-all ──');
  for (const result of results) {
    const code = result.timedOut ? EXIT_TIMEOUT : result.status;
    const runId = parseRunId(result);
    console.log(`${code === 0 ? '✓' : '✗'} Work ${result.id}: exit ${code}${result.timedOut ? ' (timeout)' : ''} | ${(result.durationMs / 1000).toFixed(1)}s${runId ? ` | ${runId}` : ''}`);
  }
  const exitCode = aggregateExitCodes(results);
  const failed = results.filter((result) => (result.timedOut ? EXIT_TIMEOUT : result.status) !== 0).length;
  console.log(exitCode === 0 ? `[RUN-ALL]: ${results.length} Work(s) concluído(s) com sucesso.` : `[RUN-ALL]: ${failed}/${results.length} Work(s) falharam (exit ${exitCode}).`);
  return exitCode;
}

/** Mapa canônico gate → avaliador determinístico. */
const GATE_EVALUATORS: Record<string, (workId: string, workDir: string) => GateOutput> = {
  'GATE-DISC-REQ': evaluateGateDiscReq,
  'GATE-REQ-PRD': evaluateGateReqPrd,
  'GATE-PRD-SPEC': evaluateGatePrdSpec,
  'GATE-SPEC-PLAN': evaluateGateSpecPlan,
  'GATE-PLAN-CONTRACT': evaluateGatePlanContract,
};

const KNOWN_GATES = Object.keys(GATE_EVALUATORS);

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
        const rootDir = process.cwd();
        const noCache = args.includes('--no-cache');
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const paths = getWorkArtifactsPaths(workId);

        if (args.includes('--clear-cache')) {
          console.log('=== [pwn work gate] Limpando cache de gates ===');
          const removed = clearGateCache(rootDir);
          console.log(`✓ ${removed} arquivo(s) de cache removido(s) de .pwn/gate-cache/.`);
          process.exit(0);
        }

        if (args.includes('--all')) {
          console.log(`=== [pwn work gate] Executando todos os gates para Work ${workId} ===`);
          const outputs = evaluateAllGates(workId, paths.workDir);

          for (const gate of outputs) {
            console.log(`\n── ${gate.gate} ──`);
            if (gate.findings.length === 0) {
              console.log('  (nenhum finding)');
              continue;
            }
            for (const finding of gate.findings) {
              console.log(`  [${finding.severity}] ${finding.id} · ${finding.type} · ${finding.status}`);
              console.log(`      ${finding.description}`);
              console.log(`      resolução: ${finding.required_resolution} (owner: ${finding.resolution_owner})`);
            }
          }

          console.log('\n── Resumo por gate ──');
          for (const gate of outputs) {
            console.log(`${gate.gate}: ${gate.result} (${gate.findings.length} findings)`);
          }

          const blockedGates = outputs.filter((gate) => gate.result === 'blocked');
          if (blockedGates.length > 0) {
            console.error(`\n[GATE RESULT]: BLOCKED — ${blockedGates.length} gate(s) bloqueado(s): ${blockedGates.map((gate) => gate.gate).join(', ')}.`);
            process.exit(1);
          }
          console.log('\n[GATE RESULT]: PASS — todos os gates aprovados.');
          process.exit(0);
        }

        const gateId = args[0] && !args[0].startsWith('--') ? args[0] : 'GATE-DISC-REQ';
        const evaluator = GATE_EVALUATORS[gateId];
        if (!evaluator) {
          console.error(`Gate desconhecido: ${gateId}. Opções: ${KNOWN_GATES.join(', ')}`);
          process.exit(1);
        }

        // A chave do cache deriva do próprio GateOutput (input_versions), portanto a
        // avaliação antecede a consulta; um hit reutiliza o veredicto gravado.
        const fresh = evaluator(workId, paths.workDir);
        const cached = noCache ? null : readGateCache(gateId, rootDir, fresh.input_versions);
        const output = cached ?? fresh;

        console.log(`=== [pwn work gate] Executando Gate ${gateId} para Work ${workId}${cached ? ' (cache)' : ''} ===`);
        console.log(JSON.stringify(output, null, 2));

        if (!cached && !noCache) writeGateCache(fresh, rootDir);

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
      if (args.includes('--freeze-tests')) {
        console.log('=== [pwn work contract --freeze-tests] Congelando testes de aceitação no contrato ===');
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const taskId = flagValue(args, '--task');
        const start = args.indexOf('--freeze-tests') + 1;
        const end = args.findIndex((arg, index) => index >= start && arg.startsWith('--'));
        const paths = args.slice(start, end === -1 ? args.length : end);
        if (!taskId) {
          console.error('Uso: pwn work contract --work NNNN --task 1.1 --freeze-tests <arquivo-de-teste>...');
          process.exit(1);
        }
        try {
          const result = freezeAcceptanceTests({ workId, taskId, paths });
          console.log(`✓ ${result.frozen.length} teste(s) congelado(s) em ${result.contractId}:`);
          for (const entry of result.frozen) console.log(`  ${entry.sha256.slice(0, 12)}  ${entry.path}`);
          console.log('\nAo menos um AC da task precisa exercitar cada arquivo; o audit recusa a atestação se algum deles mudar.');
          process.exit(0);
        } catch (err) {
          console.error(`✗ ${(err as Error).message}`);
          process.exit(1);
        }
      }
      console.log('=== [pwn work contract] Validando contratos V4 congelados do Work ===');
      {
        const workId = flagValue(args, '--work') ?? getLatestWorkId();
        const plan = loadPlan(workId);
        if (!plan) {
          console.error(`Nenhum plan.json encontrado em .pwn/work/${workId}/. Rode 'pwn work init ${workId}' e defina as tasks antes de validar os contratos.`);
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
            const frozenTests = contract.acceptance_contract.frozen_tests ?? [];
            if (frozenTests.length) console.log(`    congelados:  ${frozenTests.map((entry) => entry.path).join(', ')}`);
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
            console.log(`✓ ${result.generated.length} artefato(s) em .pwn/work/${workId}/: ${result.generated.join(', ')}`);
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

    case 'reconcile':
      console.log('=== [pwn work reconcile] Conciliando mudanças feitas fora do pwn ===');
      {
        const rootDir = path.resolve(flagValue(args, '--dir') ?? process.cwd());
        const risk = (flagValue(args, '--risk') ?? 'L2') as RiskLevel;
        const dryRun = args.includes('--dry-run');
        const list = (name: string): string[] | undefined => flagValue(args, name)?.split(',').map((item) => item.trim()).filter(Boolean);

        const validRisks: RiskLevel[] = ['L0', 'L1', 'L2', 'L3', 'L4'];
        if (!validRisks.includes(risk)) {
          console.error(`--risk inválido: ${risk}. Opções: ${validRisks.join(', ')}`);
          process.exit(1);
        }

        try {
          const result = reconcileChanges({
            rootDir,
            since: flagValue(args, '--since') ?? undefined,
            paths: list('--paths'),
            tests: list('--tests'),
            title: flagValue(args, '--title') ?? undefined,
            workId: flagValue(args, '--work') ?? undefined,
            risk,
            force: args.includes('--force'),
            dryRun,
          });
          console.log(`Referência: ${result.baseCommit.slice(0, 12)} | HEAD: ${result.headCommit.slice(0, 12)}`);
          console.log(`Mudanças a conciliar (${result.changes.length}):`);
          for (const change of result.changes) console.log(`  ${change.status} ${change.kind === 'test' ? 'teste ' : 'código'} ${change.path}`);
          for (const skip of result.skipped) console.log(`  · ignorado ${skip.path}: ${skip.reason}`);
          console.log(`Tasks (${result.tasks.length}): ${result.tasks.map((task) => `${task.id} [${task.implementationFiles.length} arquivo(s)]`).join(', ')}`);

          if (result.dryRun) {
            console.log('\n(--dry-run) nada foi criado. Rode sem --dry-run para criar o Work.');
            process.exit(0);
          }

          const workId = result.workId!;
          console.log(`\n✓ Work ${workId} criado em .pwn/work/${workId}/ (${result.generated.length} artefato(s))`);
          if (result.frozen.length > 0) console.log(`✓ Testes congelados no contrato: task(s) ${result.frozen.join(', ')}`);
          for (const pending of result.pendingFreeze) {
            const task = result.tasks.find((entry) => entry.id === pending.task)!;
            if (task.testsToWrite) {
              console.warn(`! task ${task.id}: a mudança não tem teste — escrever depois: ${task.testFiles.join(' ')}`);
              console.warn(`  O contrato já autoriza esse arquivo. O teste deve FALHAR com ${task.implementationFiles.join(', ')} no commit-base ${result.baseCommit.slice(0, 7)}.`);
              console.warn(`  Escreva e commite o teste; depois: pwn work contract --work ${workId} --task ${task.id} --freeze-tests ${task.testFiles.join(' ')}`);
              continue;
            }
            console.warn(`! task ${task.id}: testes ainda não congelados — ${pending.reason}`);
            console.warn(`  Comite os testes e rode: pwn work contract --work ${workId} --task ${task.id} --freeze-tests ${task.testFiles.join(' ')}`);
          }
          console.log(`\nA conciliação não conclui nada: sem RED/GREEN observado, a prova é o recibo do verificador.`);
          console.log(`Próximos passos:`);
          console.log(`  pwn work gate --all --work ${workId}`);
          for (const task of result.tasks) {
            console.log(`  pwn verify approve --work ${workId} --task ${task.id} --by <nome> && pwn verify run --work ${workId} --task ${task.id}`);
          }
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
          console.error(`Nenhum plan.json encontrado para o Work ${workId}. Rode 'pwn work init' e crie .pwn/work/${workId}/plan.json, ou informe um caminho de plano markdown.`);
          process.exit(1);
        }
        process.exit(validateTasksMain([pathArg]));
      }
      break;

    case 'batch': {
      // Flags valem só ANTES do `--`; depois dele vem o comando de regressão do operador, intacto.
      const separator = args.indexOf('--');
      const own = separator === -1 ? args : args.slice(0, separator);
      const timeoutSeconds = Number(flagValue(own, '--timeout-seconds') ?? '600');
      if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
        console.error(`--timeout-seconds inválido: '${flagValue(own, '--timeout-seconds')}' (esperado número > 0)`);
        process.exit(1);
      }
      process.exit(handleBatchCommand(own[0] ?? '', {
        workId: flagValue(own, '--work'),
        jobs: flagValue(own, '--jobs'),
        tasks: flagValue(own, '--tasks'),
        taskArg: own[1] && !own[1].startsWith('--') ? own[1] : null,
        command: separator === -1 ? [] : args.slice(separator + 1),
        timeoutSeconds,
      }));
    }

    case 'run-all':
      runAllCommand(args).then(
        (code) => process.exit(code),
        (err: unknown) => {
          console.error(`✗ run-all falhou: ${(err as Error).message}`);
          process.exit(1);
        },
      );
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

        // ── --dry-run: valida a cadeia inteira e reporta impedimentos sem executar nada ──
        if (args.includes('--dry-run')) {
          console.log(`=== [pwn work run] Simulação (--dry-run) do Work ${workId} — nada será executado ===`);
          const paths = getWorkArtifactsPaths(workId);
          const impediments: string[] = [];

          const gateOutputs = evaluateAllGates(workId, paths.workDir);
          console.log('\n── Gates ──');
          for (const gate of gateOutputs) {
            console.log(`${gate.gate}: ${gate.result} (${gate.findings.length} findings)`);
            if (gate.result !== 'blocked') continue;
            const material = gate.findings.filter((f) => f.status === 'open' && (f.severity === 'critical' || f.severity === 'high'));
            const detail = material.length > 0 ? material.map((f) => f.id).join(', ') : `${gate.findings.length} finding(s)`;
            impediments.push(`${gate.gate}: blocked — ${detail}`);
          }

          console.log('\n── Contratos ──');
          const plan = loadPlan(workId);
          if (!plan) {
            console.log('  (plan.json ausente)');
            impediments.push(`plan.json ausente para o Work ${workId}.`);
          } else {
            for (const task of plan.tasks) {
              try {
                const contract = loadTaskContract(workId, task.id);
                const problems: string[] = [];
                if (!contract.risk?.level) problems.push('risk.level ausente');
                if (!contract.scope_contract?.write_allow?.length) problems.push('scope_contract.write_allow vazio');
                if (!contract.acceptance_contract?.commands?.length) problems.push('acceptance_contract.commands vazio');
                if (problems.length > 0) {
                  for (const problem of problems) impediments.push(`Task ${task.id} (${task.contract_id}): ${problem}`);
                  console.error(`✗ ${task.id} — ${problems.join('; ')}`);
                } else {
                  console.log(`✓ ${task.id} — ${task.contract_id} | risco ${contract.risk.level} | ${contract.scope_contract.write_allow.length} write_allow | ${contract.acceptance_contract.commands.length} comando(s)`);
                }
              } catch (err) {
                impediments.push(`Task ${task.id}: ${(err as Error).message}`);
                console.error(`✗ ${task.id} — ${(err as Error).message}`);
              }
            }
          }

          console.log('\n── Impedimentos ──');
          if (impediments.length === 0) {
            console.log('(nenhum) — Work elegível para execução.');
            process.exit(0);
          }
          for (const impediment of impediments) console.error(`  - ${impediment}`);
          console.error(`\n[DRY-RUN]: ${impediments.length} impedimento(s). A execução ficaria bloqueada.`);
          process.exit(1);
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
        let verification: AutoVerification | null = null;
        if (result.suspended) {
          console.error(`\n[SUSPENDED] A task ${taskId ?? '(work)'} do Work ${workId} não foi executada: aguarda decisão humana na fila AFK.`);
          console.error(`Use 'pwn queue approve ${result.runId}' para destravar (exit code ${result.status}).`);
          // Suspensão L4 não altera estado de governança.
        } else if (!taskId) {
          console.log('· Aceitação independente exige --task (ou use: pwn verify run --work NNNN --task T).');
        } else if (result.status === 0) {
          // A execução terminou: a aceitação independente roda SEM depender do agente.
          verification = verifyAfterRun({ rootDir: process.cwd(), workId, taskId, timeoutSeconds });
          reportAutoVerification(verification);
        }
        if (result.suspended) {
          // nada a fazer
        } else if (noSync) {
          console.log(`· Manifest .work/${workId}.json não sincronizado (--no-sync).`);
        } else {
          const syncState = syncWorkManifest(workId);
          if (syncState !== 'manifest-ausente') {
            console.log(`✓ Manifest .work/${workId}.json → state: ${syncState}`);
          }
        }

        if (verification && verification.attempted && verification.outcome !== 'pass') {
          process.exit(1);
        }
        process.exit(result.status);
      }
      break;

    case 'audit':
      console.log('=== [pwn work audit] Auditando Evidências e Aceitação ===');
      {
        const knownActions = ['baseline', 'red', 'green', 'verify', 'check'];
        // Compat: sem ação explícita, o audit roda a verificação de evidência (verify).
        const auditArgs = args.length > 0 && knownActions.includes(args[0])
          ? [...args]
          : ['verify', ...args];
        process.exit(taskEvidenceMain(auditArgs));
      }
      break;

    case 'status':
      {
        // --coverage: relatório determinístico de cobertura do Work (requisitos →
        // capabilities → tasks → contratos → ACs), derivado dos artefatos normativos.
        if (args.includes('--coverage')) {
          const workId = flagValue(args, '--work')
            ?? args.find((a) => /^\d{4}$/.test(a))
            ?? getLatestWorkId();
          const paths = getWorkArtifactsPaths(workId);
          if (!fs.existsSync(paths.workDir)) {
            console.error(`Work ${workId} não encontrado em ${paths.workDir}.`);
            process.exit(1);
          }
          const cov = computeWorkCoverage(paths.workDir);
          console.log(`=== [pwn work status --coverage] Cobertura do Work ${workId} ===\n`);
          const line = (label: string, value: number, total: number) => {
            const mark = total === 0 ? '·' : value === total ? '✓' : '⚠';
            console.log(`  ${mark} ${label.padEnd(34)} ${value}/${total}`);
          };
          line('requisitos aceitos', cov.accepted_requirements, cov.requirements);
          line('capabilities com regras', cov.capabilities_with_rules, cov.capabilities);
          line('tasks com contrato congelado', cov.tasks_with_contract, cov.tasks);
          line('tasks com critérios de aceite', cov.tasks_with_acs, cov.tasks);
          const gaps =
            (cov.requirements - cov.accepted_requirements)
            + (cov.capabilities - cov.capabilities_with_rules)
            + (cov.tasks - cov.tasks_with_contract)
            + (cov.tasks - cov.tasks_with_acs);
          console.log(`\n[COVERAGE RESULT]: ${gaps === 0 ? 'COMPLETO' : `${gaps} lacuna(s)`}`);
          process.exit(gaps === 0 ? 0 : 1);
        }
        console.log('=== [pwn work status] Relatório de Status do Work ===');
        process.exit(projectStatusMain(args));
      }

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
      console.log('  pwn work init <id>  Inicializa diretório de artefatos sob .pwn/work/<id>/');
      console.log('  pwn work import    Importa Works do layout v3 (.work/, .todo/) para o layout canônico');
      console.log('  pwn work scaffold  Cria um Work novo com cadeia completa (discovery→prd→spec→plan+CTR)');
      console.log('  pwn work gate <id>  Executa gate determinístico (GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC)');
      console.log('  pwn work gate --all [--work NNNN] [--no-cache]  Executa os 5 gates e resume por gate');
      console.log('  pwn work gate --clear-cache  Remove o cache de veredictos (.pwn/gate-cache/)');
      console.log('  pwn work specify   Especifica mudanças no baseline');
      console.log('  pwn work contract  Valida os contratos V4 congelados (.pwn/work/<id>/CTR-*.json)');
      console.log('  pwn work contract --task <t> --freeze-tests <arquivos>  Congela testes de aceitação antes da implementação');
      console.log('  pwn work plan      Valida o grafo e o plano de tarefas');
      console.log('  pwn work run       Executa tarefas do work de forma autônoma (--no-gate, --no-isolation, --no-sync, --dry-run)');
      console.log('  pwn work run-all   Executa vários Works em paralelo, um subprocesso `work run` por Work (--works 0001,0002 --jobs N --timeout-seconds S --no-gate -- <comando>)');
      console.log('  pwn work batch     Lotes paralelos de tasks de um Work em worktrees: plan|prepare|integrate|rebase|abort (--work NNNN --jobs N --tasks 1.2,1.3 -- <regressão do plano>)');
      console.log('  pwn work audit     Diagnóstico TDD local: baseline|red|green|verify|check (NÃO conclui a task — a aceitação é do pwn verify)');
      console.log('  pwn work status    Exibe o status do progresso do projeto');
      console.log('  pwn work sync      Sincroniza o estado do manifest .work/NNNN.json com o plano');
      process.exit(1);
  }
}
