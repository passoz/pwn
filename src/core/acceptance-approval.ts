import { existsSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

import {
  allowedCheckCommands,
  canonicalJson,
  parseGlobalGates,
  parsePlanTask,
  requiredAuditChecks,
  splitCommandLine,
  type PlanTaskDefinition,
} from "./acceptance.js";
import { loadTaskContract } from "./task-contract.js";
import { loadPlan, tasksMarkdownPath } from "./plan-renderer.js";
import {
  approvalFilesDir,
  assertProtectedOutsideRepository,
  approvalsDir,
  digestOfFile,
  digestOfText,
  initializeVerifierHome,
  writeFileAtomic,
  writeJsonAtomic,
  verifierRoot,
} from "./verifier-home.js";

/**
 * Pacote de aceitação aprovado.
 *
 * É o que o agente NÃO pode alterar: os comandos avaliados, a árvore de referência
 * e — principalmente — o conteúdo dos testes de aceitação aprovados, guardados na
 * raiz protegida do verificador. A avaliação restaura esses arquivos por cima da
 * entrega candidata, então enfraquecer o teste no repositório não muda o que é
 * executado.
 */

export const GLOBAL_TASK_ID = "GLOBAL";

export interface ApprovedCheck {
  /** `AC-n`, `VISUAL`, `DOCUMENTATION`, `REGRESSION` ou `G-n`. */
  id: string;
  command: string[];
  /** Texto que precisa aparecer na saída do candidato; `null` quando não declarado. */
  expect_output: string | null;
  /** AC: o mesmo check precisa falhar com a implementação revertida ao baseline. */
  require_baseline_failure: boolean;
}

export interface ApprovedFile {
  path: string;
  sha256: string;
}

export interface Approval {
  version: 1;
  approval_id: string;
  work_id: string;
  task_id: string;
  kind: "task" | "global";
  approved_by: string;
  created_at: string;
  plan_path: string;
  plan_sha256: string;
  contract_id: string | null;
  contract_sha256: string | null;
  baseline_commit: string;
  implementation_files: string[];
  checks: ApprovedCheck[];
  approved_files: ApprovedFile[];
}

export interface ApprovalIndex {
  version: 1;
  current: Record<string, string>;
}

function indexPath(root: string): string {
  return path.join(approvalsDir(root), "index.json");
}

function readIndex(root: string): ApprovalIndex {
  const file = indexPath(root);
  if (!existsSync(file)) return { version: 1, current: {} };
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as ApprovalIndex;
    return parsed?.version === 1 && parsed.current ? parsed : { version: 1, current: {} };
  } catch {
    return { version: 1, current: {} };
  }
}

export function approvalPath(approvalId: string, root: string = verifierRoot()): string {
  return path.join(approvalsDir(root), `${approvalId}.json`);
}

export function readApproval(approvalId: string, root: string = verifierRoot()): Approval | null {
  const file = approvalPath(approvalId, root);
  if (!existsSync(file)) return null;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as Approval;
    return parsed?.version === 1 ? parsed : null;
  } catch {
    return null;
  }
}

/** Aprovação vigente de um par Work/task, ou `null` quando nunca houve aprovação. */
export function currentApproval(
  workId: string,
  taskId: string,
  root: string = verifierRoot(),
): Approval | null {
  const index = readIndex(root);
  const id = index.current[`${workId}:${taskId}`];
  return id ? readApproval(id, root) : null;
}

export function listApprovals(root: string = verifierRoot()): Approval[] {
  const index = readIndex(root);
  return Object.values(index.current)
    .map((id) => readApproval(id, root))
    .filter((approval): approval is Approval => approval !== null);
}

/** Conteúdo aprovado de um arquivo de aceitação, lido da raiz protegida. */
export function approvedFileContent(
  approval: Approval,
  relative: string,
  root: string = verifierRoot(),
): string | null {
  const file = path.join(approvalFilesDir(approval.approval_id, root), relative);
  if (!existsSync(file)) return null;
  return readFileSync(file, "utf8");
}

function git(rootDir: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: rootDir, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} falhou: ${(result.stderr || result.error?.message || "").trim()}`);
  }
  return (result.stdout ?? "").trim();
}

export interface CreateApprovalOptions {
  rootDir: string;
  workId: string;
  taskId: string;
  approvedBy: string;
  /** Aprovação de um item de `## Global gates` em vez de uma task. */
  global?: string | null;
  verifierRootDir?: string;
}

function checksForTask(planText: string, task: PlanTaskDefinition): ApprovedCheck[] {
  const checks: ApprovedCheck[] = [];
  for (const name of requiredAuditChecks(task)) {
    const allowed = allowedCheckCommands(planText, task, name);
    if (allowed.error) throw new Error(`${name}: ${allowed.error}`);
    const command = splitCommandLine(allowed.commands[0]) ?? allowed.commands[0].trim().split(/\s+/);
    if (!command.length || !command[0]) throw new Error(`${name}: comando vazio no plano`);
    checks.push({
      id: name,
      command,
      expect_output: null,
      require_baseline_failure: name.startsWith("AC-"),
    });
  }
  if (!checks.length) throw new Error(`a task ${task.id} não declara checks de aceitação no plano`);
  return checks;
}

function checksForGlobal(planText: string, gateName: string): ApprovedCheck[] {
  const gates = parseGlobalGates(planText) ?? [];
  const index = Number(gateName.replace(/^G-/, "")) - 1;
  const gate = gates[index];
  if (!gate) throw new Error(`${gateName} não existe no plano: ## Global gates declara ${gates.length} item(ns)`);
  if (!gate.command) throw new Error(`${gateName} não declara comando executável em ## Global gates`);
  const command = splitCommandLine(gate.command) ?? gate.command.trim().split(/\s+/);
  return [{ id: gateName, command, expect_output: null, require_baseline_failure: false }];
}

/**
 * Cria e registra o pacote aprovado. Exige:
 * - plano e contrato presentes;
 * - árvore de aceitação commitada e limpa (a referência fica no histórico);
 * - testes de aceitação congelados no contrato — é o conteúdo que a avaliação
 *   restaura, então uma aprovação sem eles não teria o que proteger.
 */
export function createApproval(options: CreateApprovalOptions): Approval {
  const { rootDir, workId, approvedBy } = options;
  const isGlobal = Boolean(options.global);
  const taskId = isGlobal ? options.global! : options.taskId;
  const root = options.verifierRootDir ?? verifierRoot();
  if (!approvedBy || !approvedBy.trim()) throw new Error("a aprovação exige --by <responsável>");

  initializeVerifierHome(root);
  assertProtectedOutsideRepository(root, rootDir);

  const planPath = tasksMarkdownPath(workId, rootDir);
  if (!existsSync(planPath)) throw new Error(`plano não encontrado: ${planPath}`);
  const planText = readFileSync(planPath, "utf8");

  const baselineCommit = git(rootDir, "rev-parse", "HEAD");
  if (!baselineCommit) throw new Error("não foi possível resolver o commit de referência da aprovação");

  let implementationFiles: string[] = [];
  let checks: ApprovedCheck[];
  let contractId: string | null = null;
  let contractSha: string | null = null;
  const approvedFiles: ApprovedFile[] = [];
  /** Conteúdo aprovado, lido do repositório e gravado na raiz protegida após calcular o id. */
  const approvedContents = new Map<string, string>();

  if (isGlobal) {
    checks = checksForGlobal(planText, options.global!);
  } else {
    const task = parsePlanTask(planText, options.taskId);
    if (!task) throw new Error(`task ${options.taskId} não encontrada em ${planPath}`);
    implementationFiles = task.implementationFiles;
    checks = checksForTask(planText, task);
    if (!implementationFiles.length) throw new Error(`a task ${options.taskId} não declara arquivos de implementação`);

    const canonical = loadPlan(workId, rootDir);
    const contractIdOfTask = canonical?.tasks.find((entry) => entry.id === options.taskId)?.contract_id;
    if (!contractIdOfTask) {
      throw new Error(`a task ${options.taskId} não vincula contract_id no plan.json do Work ${workId}`);
    }

    const contract = loadTaskContract(workId, options.taskId, rootDir);
    contractId = contractIdOfTask;
    contractSha = digestOfFile(path.resolve(rootDir, ".pwn", "work", workId, `${contractIdOfTask}.json`));

    const frozen = contract.acceptance_contract.frozen_tests ?? [];
    if (!frozen.length) {
      throw new Error(
        `a task ${options.taskId} não tem testes de aceitação congelados; congele-os antes de aprovar ` +
          `('pwn work contract --work ${workId} --task ${options.taskId} --freeze-tests <arquivo>)`,
      );
    }
    for (const entry of frozen) {
      const absolute = path.resolve(rootDir, entry.path);
      if (!existsSync(absolute) || !statSync(absolute).isFile()) {
        throw new Error(`teste de aceitação aprovado ausente no repositório: ${entry.path}`);
      }
      const current = digestOfFile(absolute);
      if (current !== entry.sha256) {
        throw new Error(`teste de aceitação aprovado diverge do congelado no contrato: ${entry.path}`);
      }
      // A versão aprovada vive na raiz protegida: a avaliação restaura deste conteúdo.
      approvedContents.set(entry.path, readFileSync(absolute, "utf8"));
      approvedFiles.push({ path: entry.path, sha256: current });
    }
  }

  const content = {
    version: 1 as const,
    work_id: workId,
    task_id: taskId,
    kind: isGlobal ? ("global" as const) : ("task" as const),
    approved_by: approvedBy.trim(),
    created_at: new Date().toISOString(),
    plan_path: path.relative(rootDir, planPath),
    plan_sha256: digestOfText(planText),
    contract_id: contractId,
    contract_sha256: contractSha,
    baseline_commit: baselineCommit,
    implementation_files: implementationFiles,
    checks,
    approved_files: approvedFiles,
  };
  const approvalId = digestOfText(canonicalJson(content));
  const approval: Approval = { approval_id: approvalId, ...content };

  // Os arquivos aprovados vivem dentro do pacote: a avaliação restaura ESTE conteúdo
  // por cima da entrega candidata, então alterar o teste no repositório não muda o
  // que é executado.
  for (const [relative, content] of approvedContents) {
    writeFileAtomic(path.join(approvalFilesDir(approvalId, root), relative), content, 0o600);
  }
  writeJsonAtomic(approvalPath(approvalId, root), approval);

  const index = readIndex(root);
  index.current[`${workId}:${taskId}`] = approvalId;
  writeJsonAtomic(indexPath(root), index);

  return approval;
}
