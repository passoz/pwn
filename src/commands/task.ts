import { existsSync, readFileSync } from 'node:fs';

import { allowedCheckCommands, parseGlobalGates, parsePlanTask, requiredAuditChecks } from '../core/acceptance.js';
import { generateContextCapsule, type CapsulePlanContext } from '../core/capsule.js';
import { tasksMarkdownPath } from '../core/plan-renderer.js';
import { getLatestWorkId } from '../core/work-artifacts.js';
import { loadTaskContract } from '../core/task-contract.js';
import { runOrchestrated } from '../core/run-orchestrator.js';
import { reportAutoVerification, verifyAfterRun } from '../core/acceptance-flow.js';

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

/**
 * Comandos que o plano v3 exige da task (`AC-1`, `REGRESSION`, gates globais).
 * A cápsula é a superfície de instrução do agente: mostrar só a allowlist do
 * contrato faria o agente usar um comando que o audit recusa.
 */
function planContextFor(workId: string, taskId: string): CapsulePlanContext | undefined {
  const planPath = tasksMarkdownPath(workId);
  if (!existsSync(planPath)) return undefined;
  const planText = readFileSync(planPath, 'utf8');
  const task = parsePlanTask(planText, taskId);
  if (!task) return undefined;
  return {
    redCommand: task.red?.command ?? null,
    checks: requiredAuditChecks(task).map((name) => ({ name, ...allowedCheckCommands(planText, task, name) })),
    globalGates: (parseGlobalGates(planText) ?? []).map((gate) => gate.command).filter((command): command is string => Boolean(command)),
  };
}

/**
 * Aceitação independente após a execução: o agente entrega código; quem decide que
 * a task está concluída é o verificador, executando os critérios aprovados.
 */
function ctxVerify(workId: string, taskId: string, timeoutSeconds: number): ReturnType<typeof verifyAfterRun> {
  try {
    return verifyAfterRun({ rootDir: process.cwd(), workId, taskId, timeoutSeconds });
  } catch (error) {
    return { attempted: true, outcome: 'blocked', reason: (error as Error).message };
  }
}

export function handleTaskCommand(subcommand: string, args: string[]): void {
  switch (subcommand) {
    case 'run':
      console.log('=== [pwn task run] Executando task atômica sob contrato ===');
      {
        const workId = flagValue(args, '--work');
        const taskId = flagValue(args, '--task');
        const timeoutSeconds = Number(flagValue(args, '--timeout-seconds') ?? '600');
        const noIsolation = args.includes('--no-isolation');
        const separator = args.indexOf('--');
        const command = separator === -1 ? [] : args.slice(separator + 1);

        if (!workId || !taskId || command.length === 0) {
          console.error('Uso: pwn task run --work NNNN --task 1.1 --timeout-seconds N -- <comando>');
          process.exit(1);
        }

        const result = runOrchestrated({ workId, taskId, command, timeoutSeconds, isolated: !noIsolation });
        if (result.stdout) console.log(result.stdout);
        if (result.stderr) console.error(result.stderr);
        if (result.diffViolations.length > 0) {
          console.error('\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:');
          result.diffViolations.forEach((v) => console.error(`  - ${v}`));
        }
        let verification: ReturnType<typeof verifyAfterRun> | null = null;
        if (result.suspended) {
          console.error(`\n[SUSPENDED] A task ${taskId} do Work ${workId} não foi executada: aguarda decisão humana na fila AFK.`);
          console.error(`Use 'pwn queue approve ${result.runId}' para destravar (exit code ${result.status}).`);
        } else if (result.status === 0) {
          // A execução terminou: a aceitação independente roda sem depender do agente.
          verification = ctxVerify(workId, taskId, timeoutSeconds);
          reportAutoVerification(verification);
        }
        if (verification && verification.attempted && verification.outcome !== 'pass') process.exit(1);
        process.exit(result.status);
      }
      break;

    case 'capsule':
      {
        const taskId = args[0];
        const workId = args[1] || getLatestWorkId();
        console.log(`=== [pwn task capsule] Context Capsule (contrato congelado V4) para ${taskId ?? '(task-id)'} ===\n`);

        if (!taskId) {
          console.error('Uso: pwn task capsule <task-id> [work-id]');
          process.exit(1);
        }

        try {
          const contract = loadTaskContract(workId, taskId);
          console.log(generateContextCapsule({ task: contract, plan: planContextFor(workId, taskId) }));
          process.exit(0);
        } catch (err) {
          console.error(`✗ Não foi possível gerar a cápsula: ${(err as Error).message}`);
          console.error('  O contrato V4 deve estar congelado em .pwn/work/<id>/<contract_id>.json.');
          process.exit(1);
        }
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
