import {
  abortBatch,
  collectSchedulableTasks,
  integrateBatch,
  planNextBatch,
  prepareBatch,
  readBatch,
  rebaseTask,
  type Deferral,
  type HoldKind,
  type IntegrationResult,
  type RebaseResult,
} from '../core/batch.js';
import { describeDecision, governance, recordRuleDecision } from '../core/decider/engine.js';
import { defaultConcurrency } from '../core/process-pool.js';
import { getLatestWorkId } from '../core/work-artifacts.js';

export interface BatchCommandOptions {
  /** `--work` explícito; plan/prepare caem no último Work, integrate/abort usam o do lote ativo. */
  workId: string | null;
  jobs: string | null;
  tasks: string | null;
  /** Argumento posicional de `rebase`. */
  taskArg: string | null;
  /** Comando de regressão após `--` (vazio = sem gate). */
  command: string[];
  timeoutSeconds: number;
}

const USAGE = [
  'pwn work batch plan [--work NNNN] [--jobs N]        Mostra o próximo lote paralelo e por que cada task ficou de fora',
  'pwn work batch prepare [--work NNNN] [--jobs N] [--tasks 1.2,1.3]',
  '                                                    Cria um worktree por task do lote (um agente por worktree)',
  'pwn work batch integrate [--work NNNN] [--timeout-seconds S] [-- <regressão do plano>]',
  '                                                    Integra as entregas prontas: um commit por task + evidência local;',
  '                                                    com o comando de regressão, cada entrega é testada sobre o HEAD integrado antes de entrar',
  'pwn work batch rebase <task>                        Refaz uma task retida sobre o HEAD atual (3-way); conflito fica no worktree',
  'pwn work batch abort                                Descarta o lote ativo (worktrees e branches)',
].join('\n');

function printDeferred(deferred: Deferral[], log: (line: string) => void = console.log): void {
  if (!deferred.length) return;
  log('\nFora do lote:');
  for (const entry of deferred) log(`  ${entry.id} — ${entry.reason}`);
}

function parseJobs(raw: string | null): number {
  if (raw === null) return defaultConcurrency();
  const jobs = Number(raw);
  if (!Number.isInteger(jobs) || jobs < 1) throw new Error(`--jobs inválido: '${raw}' (esperado inteiro >= 1)`);
  return jobs;
}

function finalStep(workId: string): string {
  return `todas as tasks do Work ${workId} estão integradas: rode 'pwn verify run-all --work ${workId}' (uma verificação, na árvore final) e marque [x] em ordem de plano`;
}

function printRebase(result: RebaseResult): void {
  console.log(`=== [pwn work batch rebase] ${result.taskId} refeita sobre ${result.base.slice(0, 12)} ===`);
  console.log(`  worktree: ${result.worktree}`);
  if (result.conflicts.length) {
    console.log(`\nConflitos em ${result.conflicts.length} arquivo(s) — resolva no worktree (o harness não escolhe a resolução):`);
    for (const file of result.conflicts) console.log(`  ${file}`);
    console.log('Edite os marcadores, depois: git add <arquivos>');
  } else {
    console.log('\nEntrega reaplicada sem conflitos.');
  }
  const valid = result.evidence.stage === 'VERIFIED' && !result.evidence.stale;
  if (valid && !result.conflicts.length) {
    console.log(`Evidência local preservada (${result.evidence.stage}). Rode: pwn work batch integrate`);
  } else {
    console.log(`\nEvidência local caducou (${result.evidence.stage}${result.evidence.stale ? ', STALE' : ''}): um arquivo declarado mudou na mescla.`);
    console.log(`Refaça no worktree: audit baseline → red → green → verify. A entrega original está em ${result.patchFile}.`);
  }
}

/** Retenções que `rebase` resolve: a entrega está certa, só a base ficou para trás. */
const REBASABLE: Partial<Record<HoldKind, true>> = { clash: true, stale_base: true };

/**
 * Com decisor no projeto, o `rebase` que o operador rodaria à mão vira regra: task
 * retida só por base desatualizada é refeita sobre o HEAD integrado. Conflito de 3-way
 * continua com o agente; regressão e entrega incompleta continuam retidas.
 */
function autoRebase(root: string, result: IntegrationResult): void {
  const rebasable = result.failed.filter((entry) => REBASABLE[entry.kind]);
  if (!rebasable.length || !result.integrated.length || !governance(root, 'batch').config) return;
  console.log('\n[DECISOR] tasks retidas só por base desatualizada: refazendo sobre o HEAD integrado.');
  for (const entry of rebasable) {
    try {
      const rebased = rebaseTask({ root, taskId: entry.id });
      const record = recordRuleDecision({
        rootDir: root,
        workId: result.workId,
        taskId: entry.id,
        point: 'batch',
        action: 'rebase',
        reasons: [`retida por ${entry.kind}: ${entry.reasons[0]}`, rebased.conflicts.length ? `conflitos para o agente: ${rebased.conflicts.join(', ')}` : 'reaplicada sem conflitos'],
      });
      for (const line of describeDecision(record)) console.log(line);
      printRebase(rebased);
    } catch (error) {
      console.error(`✗ rebase automático de ${entry.id} falhou: ${(error as Error).message}`);
    }
  }
}

export function handleBatchCommand(action: string, options: BatchCommandOptions): number {
  const root = process.cwd();
  try {
    switch (action) {
      case 'plan': {
        const workId = options.workId ?? getLatestWorkId();
        console.log(`=== [pwn work batch plan] Work ${workId} ===`);
        const active = readBatch(root);
        if (active) {
          console.log(`Lote ativo ${active.batch_id} (Work ${active.work_id}, base ${active.base.slice(0, 12)}):`);
          for (const task of active.tasks) console.log(`  ${task.id} — ${task.title}\n      worktree: ${task.worktree}`);
          console.log("\nIntegre com 'pwn work batch integrate' ou descarte com 'pwn work batch abort' antes do próximo lote.");
          return 0;
        }
        const schedule = planNextBatch(collectSchedulableTasks(workId, root), parseJobs(options.jobs), workId);
        console.log(`Integradas: ${schedule.integrated.length ? schedule.integrated.join(', ') : 'nenhuma'}`);
        if (schedule.batch.length) {
          console.log('\nPróximo lote:');
          for (const task of schedule.batch) console.log(`  ${task.id} — ${task.title}`);
        } else if (!schedule.deferred.length) {
          console.log(`\n${finalStep(workId)}`);
        } else {
          console.log('\nNenhuma task pronta para lote.');
        }
        printDeferred(schedule.deferred);
        return 0;
      }

      case 'prepare': {
        const workId = options.workId ?? getLatestWorkId();
        const only = options.tasks === null ? undefined : options.tasks.split(',').map((id) => id.trim()).filter(Boolean);
        const { manifest, schedule } = prepareBatch({ root, workId, jobs: parseJobs(options.jobs), only });
        if (!manifest) {
          console.log(`=== [pwn work batch prepare] Work ${workId} ===`);
          if (!schedule.deferred.length) {
            console.log(finalStep(workId));
            return 0;
          }
          console.error('Nenhuma task pronta para lote; nada foi criado.');
          printDeferred(schedule.deferred, console.error);
          return 1;
        }
        console.log(`=== [pwn work batch prepare] Work ${workId} — lote ${manifest.batch_id} (base ${manifest.base.slice(0, 12)}) ===`);
        for (const task of manifest.tasks) console.log(`  ${task.id} — ${task.title}\n      worktree: ${task.worktree}`);
        printDeferred(schedule.deferred);
        console.log('\nUm agente por worktree (cwd = worktree):');
        console.log(`  pwn task capsule <task> ${workId}`);
        console.log(`  pwn work audit baseline|red|green|verify --work ${workId} --task <task> -- <comando do plano>`);
        console.log('Não rode pwn verify nos worktrees: o recibo amarra a árvore inteira e a integração a muda.');
        console.log("Quando todos terminarem: pwn work batch integrate -- <comando de regressão do plano>");
        return 0;
      }

      case 'integrate': {
        const regression = options.command.length ? { command: options.command, timeoutSeconds: options.timeoutSeconds } : undefined;
        const result = integrateBatch({ root, workId: options.workId, regression });
        console.log(`=== [pwn work batch integrate] Lote ${result.batchId} (Work ${result.workId}) ===`);
        for (const entry of result.integrated) {
          console.log(`✓ ${entry.id} → commit ${entry.commit.slice(0, 12)} (${entry.files.length} arquivo(s))`);
        }
        for (const entry of result.failed) {
          console.error(`✗ ${entry.id}`);
          for (const reason of entry.reasons) console.error(`    ${reason}`);
        }
        for (const warning of result.warnings) console.warn(`⚠  ${warning}`);
        autoRebase(root, result);
        if (result.remaining.length) {
          console.error(`\nContinuam no lote: ${result.remaining.join(', ')} — corrija nos worktrees e rode integrate de novo, ou descarte com 'pwn work batch abort'.`);
        } else {
          const schedule = planNextBatch(collectSchedulableTasks(result.workId, root), 1, result.workId);
          console.log(schedule.batch.length || schedule.deferred.length
            ? `\nLote concluído. Próximo: pwn work batch plan --work ${result.workId}`
            : `\nLote concluído; ${finalStep(result.workId)}.`);
        }
        return result.failed.length ? 1 : 0;
      }

      case 'rebase': {
        if (!options.taskArg) throw new Error("informe a task: pwn work batch rebase <task>");
        const result = rebaseTask({ root, taskId: options.taskArg });
        printRebase(result);
        return result.conflicts.length ? 1 : 0;
      }

      case 'abort': {
        const manifest = abortBatch(root);
        if (!manifest) {
          console.log('Nenhum lote ativo.');
          return 0;
        }
        console.log(`Lote ${manifest.batch_id} descartado; trabalho não integrado perdido em: ${manifest.tasks.map((task) => task.id).join(', ')}`);
        return 0;
      }

      default:
        console.error(`Ação desconhecida para 'pwn work batch': ${action || '(vazia)'}\n\nUso:\n${USAGE}`);
        return 1;
    }
  } catch (error) {
    console.error(`✗ ${(error as Error).message}`);
    return 1;
  }
}
