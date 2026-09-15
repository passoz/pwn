import fs from 'node:fs';
import path from 'node:path';
import { collectPlanStatus } from './project_status.js';
import { isWorkManifestState, updateManifest, type WorkManifestState } from './work-manifest.js';

/**
 * Mapeia o panorama (project_status) para o vocabulário canônico de estado do
 * manifest (work-manifest). Todo destino precisa estar em WORK_MANIFEST_STATES,
 * caso contrário o manifest conviveria com dois vocabulários divergentes.
 */
const PANORAMA_TO_MANIFEST: Record<string, WorkManifestState> = {
  'COMPLETE': 'completed',
  'TASKS COMPLETE': 'completed',
  'NOT STARTED': 'planned',
  'NO TASKS': 'planned',
  'BLOCKED': 'blocked',
  'IN PROGRESS': 'active',
  'INVALID PLAN': 'active',
  'STALE EVIDENCE': 'active',
  'INCONSISTENT STATE': 'active',
  'INCONSISTENT ORDER': 'active',
};

function panoramaState(workId: string, rootDir: string): string {
  try {
    return collectPlanStatus(workId, rootDir).panorama?.state ?? 'planned';
  } catch {
    return 'invalid';
  }
}

/**
 * Sincroniza o `state` do manifest v3 (.work/NNNN.json) com o estado real do Work
 * derivado do plano/evidências. Retorna o novo estado, ou "manifest-ausente".
 *
 * Escreve via `updateManifest`, portanto o estado é sempre validado contra o
 * vocabulário canônico (WORK_MANIFEST_STATES).
 */
export function syncWorkManifest(workId: string, rootDir: string = process.cwd()): string {
  const manifestPath = path.resolve(rootDir, '.work', `${workId}.json`);
  if (!fs.existsSync(manifestPath)) {
    return 'manifest-ausente';
  }

  const state = PANORAMA_TO_MANIFEST[panoramaState(workId, rootDir)] ?? 'invalid';
  if (!isWorkManifestState(state)) {
    throw new Error(`estado de manifest inválido derivado do panorama: ${state}`);
  }
  updateManifest(rootDir, workId, { state });
  return state;
}
