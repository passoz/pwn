import fs from 'node:fs';
import path from 'node:path';
import type { TaskContractV4 } from './contract-engine.js';
import { loadPlan } from './plan-renderer.js';

/**
 * Load the frozen V4 contract for a task inside a work directory.
 * The plan.json maps task id → contract id; the contract lives at `<contract_id>.json`.
 */
export function loadTaskContract(workId: string, taskId: string, rootDir: string = process.cwd()): TaskContractV4 {
  const plan = loadPlan(workId, rootDir);
  if (!plan) {
    throw new Error(`plan.json não encontrado para o Work ${workId} em .piwerness/work/${workId}/`);
  }

  const task = plan.tasks.find((t) => t.id === taskId);
  if (!task) {
    throw new Error(`Task ${taskId} não encontrada no plano do Work ${workId}`);
  }
  if (!task.contract_id) {
    throw new Error(`Task ${taskId} não vincula contract_id no plano do Work ${workId}`);
  }

  const contractPath = path.resolve(rootDir, '.piwerness/work', workId, `${task.contract_id}.json`);
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
 * Load every frozen contract referenced by the plan, in plan order.
 */
export function loadWorkContracts(workId: string, rootDir: string = process.cwd()): TaskContractV4[] {
  const plan = loadPlan(workId, rootDir);
  if (!plan) {
    throw new Error(`plan.json não encontrado para o Work ${workId}`);
  }
  return plan.tasks.map((task) => loadTaskContract(workId, task.id, rootDir));
}
