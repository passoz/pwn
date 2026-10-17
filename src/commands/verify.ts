import path from "node:path";
import { defaultConcurrency, runPool, type PoolJob, type PoolResult } from "../core/process-pool.js";
import {
  createApproval,
  currentApproval,
  GLOBAL_TASK_ID,
  listApprovals,
  type Approval,
} from "../core/acceptance-approval.js";
import {
  buildReceipt,
  evaluateAcceptance,
  latestReceipt,
  receiptOutcome,
  storeReceipt,
} from "../core/verification-receipt.js";
import { runVerification, sandboxPolicy } from "../core/verification-runner.js";
import {
  initializeVerifierHome,
  requireVerifierReady,
  VerificationUnavailable,
  verifierRoot,
} from "../core/verifier-home.js";
import { getLatestWorkId } from "../core/work-artifacts.js";

/** Monta um job `verify run` por aprovação vigente do Work (gates globais incluídos). */
export function buildVerifyJobs(
  approvals: Array<Pick<Approval, "work_id" | "task_id" | "kind">>,
  workId: string,
  cli: { execPath: string; cliPath: string; timeoutSeconds: number },
  isCurrent: (taskId: string) => boolean = () => true,
): PoolJob[] {
  const seen = new Set<string>();
  const jobs: PoolJob[] = [];
  for (const approval of approvals) {
    if (approval.work_id !== workId || seen.has(approval.task_id) || !isCurrent(approval.task_id)) continue;
    seen.add(approval.task_id);
    const isGlobal = /^G-\d+$/.test(approval.task_id);
    jobs.push({
      id: approval.task_id,
      command: [
        cli.execPath,
        cli.cliPath,
        "verify",
        "run",
        "--work",
        workId,
        isGlobal ? "--global" : "--task",
        approval.task_id,
        "--timeout-seconds",
        String(cli.timeoutSeconds),
      ],
    });
  }
  return jobs;
}

export type VerifyVerdict = "ACCEPTED" | "NOT ACCEPTED" | "BLOCKED";

export function verdictOf(result: Pick<PoolResult, "status" | "timedOut">): VerifyVerdict {
  if (result.status === 0 && !result.timedOut) return "ACCEPTED";
  if (result.status === 2) return "BLOCKED";
  return "NOT ACCEPTED";
}

/** 0 se todas passaram; 2 se alguma BLOCKED; senão 1. */
export function aggregateExit(results: Array<Pick<PoolResult, "status" | "timedOut">>): number {
  const verdicts = results.map(verdictOf);
  if (verdicts.includes("BLOCKED")) return 2;
  if (verdicts.includes("NOT ACCEPTED")) return 1;
  return 0;
}

async function runAll(args: string[]): Promise<never> {
  const workId = requireWorkId(args);
  const timeoutSeconds = Number(flagValue(args, "--timeout-seconds") ?? "600");
  const concurrency = Number(flagValue(args, "--jobs") ?? defaultConcurrency());
  if (!Number.isInteger(concurrency) || concurrency < 1) throw new Error("--jobs deve ser inteiro >= 1");
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) throw new Error("--timeout-seconds inválido");
  const jobs = buildVerifyJobs(
    listApprovals(),
    workId,
    { execPath: process.execPath, cliPath: path.resolve(import.meta.dirname, "../cli.ts"), timeoutSeconds },
    (taskId) => currentApproval(workId, taskId) !== null,
  );
  console.log(`=== [pwn verify run-all] Work ${workId}: ${jobs.length} task(s), jobs=${concurrency} ===`);
  if (!jobs.length) {
    console.error(`[VERIFICATION BLOCKED] nenhuma aprovação vigente para o Work ${workId}.`);
    process.exit(2);
  }
  const results = await runPool(jobs, {
    concurrency,
    timeoutMs: (timeoutSeconds + 60) * 1000 * 2,
    onResult: (r) => console.log(`  ${verdictOf(r).padEnd(12)} ${r.id.padEnd(8)} ${(r.durationMs / 1000).toFixed(1)}s${r.timedOut ? " (timeout)" : ""}`),
  });
  const counts = { ACCEPTED: 0, "NOT ACCEPTED": 0, BLOCKED: 0 };
  for (const r of results) counts[verdictOf(r)]++;
  console.log(`\nResumo: ${counts.ACCEPTED} accepted, ${counts["NOT ACCEPTED"]} not accepted, ${counts.BLOCKED} blocked`);
  for (const r of results) {
    if (verdictOf(r) !== "ACCEPTED") console.error(`\n--- ${r.id} ---\n${(r.stderr || r.stdout).trim()}`);
  }
  process.exit(aggregateExit(results));
}

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith("--")) return null;
  return args[index + 1];
}

const USAGE = [
  "pwn verify init                            Inicializa a raiz protegida do verificador (chaves Ed25519, runtime, isolamento)",
  "pwn verify approve --work NNNN --task T --by NOME",
  "                                           Aprova os critérios de uma task (exige testes de aceitação congelados)",
  "pwn verify approve --work NNNN --global G-1 --by NOME",
  "                                           Aprova um item de ## Global gates",
  "pwn verify run --work NNNN --task T        Executa a aceitação independente e emite o recibo assinado",
  "pwn verify run --work NNNN --global G-1    Executa a aceitação independente de um gate global",
  "pwn verify run-all --work NNNN [--jobs N] [--timeout-seconds S]",
  "                                           Executa em paralelo (subprocessos) todas as aprovações vigentes do Work",
  "pwn verify status --work NNNN --task T     Informa se a árvore atual tem aceitação independente válida",
  "pwn verify show --work NNNN [--task T]     Mostra a aprovação vigente e o último recibo",
].join("\n");

function requireWorkId(args: string[]): string {
  const workId = flagValue(args, "--work") ?? getLatestWorkId();
  if (!workId) throw new Error("informe --work NNNN (nenhum Work encontrado)");
  return workId;
}

function describeApproval(approval: Approval): string {
  const lines = [
    `Aprovação ${approval.approval_id.slice(0, 16)}… (${approval.kind})`,
    `  Work/task:    ${approval.work_id}/${approval.task_id}`,
    `  Aprovada por: ${approval.approved_by} em ${approval.created_at}`,
    `  Baseline:     ${approval.baseline_commit.slice(0, 12)}`,
    `  Plano sha256: ${approval.plan_sha256.slice(0, 16)}…`,
    `  Contrato:     ${approval.contract_id ?? "(nenhum)"}`,
    `  Arquivos de aceitação aprovados: ${approval.approved_files.length}`,
    ...approval.approved_files.map((entry) => `    = ${entry.path}`),
    `  Checks:`,
    ...approval.checks.map(
      (check) =>
        `    ${check.id.padEnd(13)} ${check.command.join(" ")}${check.require_baseline_failure ? "  [exige falha no baseline]" : ""}`,
    ),
  ];
  return lines.join("\n");
}

export function handleVerifyCommand(subcommand: string, args: string[]): void | Promise<void> {
  if (subcommand === "run-all") {
    return runAll(args).catch(reportError);
  }
  return handleVerifySync(subcommand, args);
}

function reportError(error: unknown): never {
  if (error instanceof VerificationUnavailable) {
    console.error(`[VERIFICATION BLOCKED] ${error.message}`);
    console.error(`  ${error.detail}`);
    process.exit(2);
  }
  console.error(`[VERIFY ERROR] ${(error as Error).message}`);
  process.exit(1);
}

function handleVerifySync(subcommand: string, args: string[]): void {
  try {
    switch (subcommand) {
      case "init": {
        const { root, config, created } = initializeVerifierHome();
        console.log(`=== [pwn verify init] Raiz protegida do verificador ===`);
        console.log(`  Raiz:      ${root}`);
        console.log(`  Estado:    ${created ? "criada agora" : "já existia"}`);
        console.log(`  Verifier:  ${config.verifier_id}`);
        console.log(`  Runtime:   ${config.runtime.bun}`);
        console.log(`  bwrap:     ${config.isolation.bwrap ?? "(não encontrado — aceitação ficará bloqueada)"}`);
        try {
          const readiness = requireVerifierReady(root);
          console.log(`  Isolamento: bwrap disponível; política de sandbox:`);
          console.log(`    ${JSON.stringify(sandboxPolicy(readiness.runtime))}`);
          console.log(`  Chave pública (fingerprint): ${readiness.publicKeyFingerprint}`);
          console.log(`\nVerificador pronto. O código avaliado nunca recebe esta raiz.`);
        } catch (error) {
          console.error(`\n[VERIFICATION BLOCKED] ${(error as Error).message}`);
          process.exit(2);
        }
        process.exit(0);
      }

      case "approve": {
        const workId = requireWorkId(args);
        const global = flagValue(args, "--global");
        const taskId = flagValue(args, "--task");
        const approvedBy = flagValue(args, "--by");
        if (!global && !taskId) throw new Error("informe --task T ou --global G-n");
        if (!approvedBy) throw new Error("informe --by <responsável> (a aprovação é ato do operador)");
        const approval = createApproval({
          rootDir: process.cwd(),
          workId,
          taskId: taskId ?? GLOBAL_TASK_ID,
          approvedBy,
          global,
        });
        console.log(`=== [pwn verify approve] Critérios aprovados ===`);
        console.log(describeApproval(approval));
        console.log(`\nA avaliação executará EXATAMENTE isso. O agente não pode alterar o pacote.`);
        process.exit(0);
      }

      case "run": {
        const workId = requireWorkId(args);
        const global = flagValue(args, "--global");
        const taskId = global ?? flagValue(args, "--task");
        if (!taskId) throw new Error("informe --task T ou --global G-n");
        const timeoutSeconds = Number(flagValue(args, "--timeout-seconds") ?? "600");
        const approval = currentApproval(workId, taskId);
        if (!approval) {
          console.error(`[VERIFICATION BLOCKED] não existe aprovação vigente para ${workId}/${taskId}.`);
          console.error(`Aprove antes: pwn verify approve --work ${workId} ${global ? `--global ${global}` : `--task ${taskId}`} --by <nome>`);
          process.exit(2);
        }
        console.log(`=== [pwn verify run] Aceitação independente de ${workId}/${taskId} ===`);
        const result = runVerification({ rootDir: process.cwd(), approval, timeoutSeconds });
        for (const check of result.checks) {
          const baseline = check.baseline
            ? ` | baseline exit ${check.baseline.exit_code}${check.baseline.suspect_environmental ? " (suspeito de ambiente)" : ""}`
            : "";
          console.log(`  ${check.outcome.toUpperCase().padEnd(7)} ${check.id.padEnd(13)} exit ${check.exit_code}${baseline}`);
          if (check.reason) console.log(`          → ${check.reason}`);
        }
        const receipt = buildReceipt({ approval, result });
        const written = storeReceipt(receipt, process.cwd());
        console.log(`\nRecibo: ${receipt.receipt_id} (${receipt.outcome})`);
        for (const file of written) console.log(`  gravado: ${file}`);
        if (receipt.outcome !== "pass") {
          console.error(`\n[NOT ACCEPTED] ${receipt.outcome}: a entrega não satisfez a aceitação independente.`);
          process.exit(1);
        }
        console.log(`\n[ACCEPTED] entrega verificada independentemente; o status conta esta task como concluída.`);
        process.exit(0);
      }

      case "status": {
        const workId = requireWorkId(args);
        const global = flagValue(args, "--global");
        const taskId = global ?? flagValue(args, "--task");
        if (!taskId) throw new Error("informe --task T ou --global G-n");
        const evaluation = evaluateAcceptance({ rootDir: process.cwd(), workId, taskId });
        if (evaluation.accepted) {
          console.log(`ACCEPTED ${workId}/${taskId} — recibo ${evaluation.receipt!.receipt_id}`);
          process.exit(0);
        }
        console.log(`NOT ACCEPTED ${workId}/${taskId} — ${evaluation.reason}`);
        process.exit(1);
      }

      case "show": {
        const workId = requireWorkId(args);
        const taskId = flagValue(args, "--task");
        const approvals = listApprovals().filter((approval) => approval.work_id === workId);
        console.log(`=== [pwn verify show] Verificador em ${verifierRoot()} ===`);
        if (!approvals.length) console.log("  (nenhuma aprovação registrada para este Work)");
        for (const approval of approvals) {
          if (taskId && approval.task_id !== taskId) continue;
          console.log("");
          console.log(describeApproval(approval));
          const receipt = latestReceipt(workId, approval.task_id);
          if (receipt) {
            console.log(`  Último recibo: ${receipt.receipt_id} (${receipt.outcome}) em ${receipt.created_at}`);
            console.log(`    snapshot avaliado: ${receipt.candidate_snapshot_digest.slice(0, 16)}…`);
          } else {
            console.log("  Último recibo: (nenhum)");
          }
        }
        process.exit(0);
      }

      default:
        console.error(`Subcomando desconhecido para 'pwn verify': ${subcommand || "(vazio)"}`);
        console.error(`\nUso:\n${USAGE}`);
        process.exit(1);
    }
  } catch (error) {
    if (error instanceof VerificationUnavailable) {
      console.error(`[VERIFICATION BLOCKED] ${error.message}`);
      console.error(`  ${error.detail}`);
      process.exit(2);
    }
    console.error(`[VERIFY ERROR] ${(error as Error).message}`);
    process.exit(1);
  }
}
