import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { placeholderPathReason } from './acceptance.js';
import type { TaskContractV4 } from './contract-engine.js';
import { loadPlan } from './plan-renderer.js';

/**
 * Load the frozen V4 contract for a task inside a work directory.
 * The plan.json maps task id → contract id; the contract lives at `<contract_id>.json`.
 */
export function loadTaskContract(workId: string, taskId: string, rootDir: string = process.cwd()): TaskContractV4 {
  const plan = loadPlan(workId, rootDir);
  if (!plan) {
    throw new Error(`plan.json não encontrado para o Work ${workId} em .pwn/work/${workId}/`);
  }

  const task = plan.tasks.find((t) => t.id === taskId);
  if (!task) {
    throw new Error(`Task ${taskId} não encontrada no plano do Work ${workId}`);
  }
  if (!task.contract_id) {
    throw new Error(`Task ${taskId} não vincula contract_id no plano do Work ${workId}`);
  }

  const contractPath = path.resolve(rootDir, '.pwn/work', workId, `${task.contract_id}.json`);
  if (!fs.existsSync(contractPath)) {
    throw new Error(`Contrato ${task.contract_id} não encontrado em ${contractPath}`);
  }

  let contract: unknown;
  try {
    contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  } catch (err) {
    throw new Error(`Erro ao ler o contrato ${task.contract_id}: ${(err as Error).message}`);
  }

  const typed = contract as TaskContractV4;
  if (!typed || typed.contract_version !== '4.0') {
    throw new Error(`Contrato ${task.contract_id} não é V4 (contract_version: ${String((typed as { contract_version?: string })?.contract_version ?? 'ausente')})`);
  }

  return typed;
}

/**
 * Congela testes de aceitação no contrato da task (`acceptance_contract.frozen_tests`).
 *
 * O ponto é a ordem: os testes precisam existir, estar commitados e limpos ANTES
 * do baseline da task — quem implementa não consegue mais ajustá-los ao código,
 * porque o audit recusa a atestação se algum hash mudar.
 */
export function freezeAcceptanceTests(options: {
  workId: string;
  taskId: string;
  paths: string[];
  rootDir?: string;
}): { contractId: string; frozen: Array<{ path: string; sha256: string }> } {
  const rootDir = options.rootDir ?? process.cwd();
  const plan = loadPlan(options.workId, rootDir);
  const task = plan?.tasks.find((entry) => entry.id === options.taskId);
  if (!plan || !task) throw new Error(`Task ${options.taskId} não encontrada no plan.json do Work ${options.workId}`);
  if (!task.contract_id) throw new Error(`Task ${options.taskId} não vincula contract_id`);
  if (options.paths.length === 0) throw new Error('informe ao menos um arquivo de teste após --freeze-tests');

  const evidenceState = path.resolve(rootDir, '.todo', 'evidence', options.workId, 'state', `${options.taskId}.json`);
  if (fs.existsSync(evidenceState)) {
    throw new Error(`a task ${options.taskId} já tem baseline (${path.relative(rootDir, evidenceState)}): testes de aceitação se congelam antes da implementação`);
  }

  const frozen: Array<{ path: string; sha256: string }> = [];
  for (const filePath of [...new Set(options.paths)]) {
    const reason = placeholderPathReason(filePath);
    if (reason) throw new Error(`${filePath} ${reason}`);
    if (task.implementation_files.includes(filePath)) throw new Error(`${filePath} é arquivo de implementação da task, não teste de aceitação`);
    const absolute = path.resolve(rootDir, filePath);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) throw new Error(`teste de aceitação não encontrado: ${filePath}`);
    const tracked = spawnSync('git', ['ls-files', '--error-unmatch', '--', filePath], { cwd: rootDir, encoding: 'utf8' });
    const status = spawnSync('git', ['status', '--porcelain=v1', '--', filePath], { cwd: rootDir, encoding: 'utf8' });
    if (tracked.status !== 0 || status.status !== 0 || (status.stdout ?? '').trim()) {
      throw new Error(`${filePath} precisa estar commitado e sem alterações para ser congelado (a versão aprovada fica no histórico)`);
    }
    frozen.push({ path: filePath, sha256: crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex') });
  }

  const contractPath = path.resolve(rootDir, '.pwn/work', options.workId, `${task.contract_id}.json`);
  const contract = loadTaskContract(options.workId, options.taskId, rootDir);
  contract.acceptance_contract.frozen_tests = frozen;
  fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`, 'utf8');
  return { contractId: task.contract_id, frozen };
}

/**
 * Load every frozen contract referenced by the plan, in plan order.
 */
export function loadWorkContracts(workId: string, rootDir: string = process.cwd()): TaskContractV4[] {
  const plan = loadPlan(workId, rootDir);
  if (!plan) {
    throw new Error(`plan.json não encontrado para o Work ${workId}`);
  }
  return plan.tasks.map((task) => loadTaskContract(workId, task.id, rootDir));
}
