import fs from 'node:fs';
import path from 'node:path';
import { runPackScript } from './runner.js';

// Mapeia o estado do panorama (project_status.js) para o vocabulário de estado do manifest v3.
const PANORAMA_TO_MANIFEST: Record<string, string> = {
  'COMPLETE': 'complete',
  'TASKS COMPLETE': 'complete',
  'NOT STARTED': 'planned',
  'NO TASKS': 'planned',
  'BLOCKED': 'blocked',
  'IN PROGRESS': 'in_progress',
  'INVALID PLAN': 'in_progress',
  'STALE EVIDENCE': 'in_progress',
  'INCONSISTENT STATE': 'in_progress',
  'INCONSISTENT ORDER': 'in_progress',
};

function panoramaState(workId: string, rootDir: string): string {
  const result = runPackScript('project_status.js', [workId, '--json'], rootDir);
  if (result.status !== 0) return 'invalid';
  try {
    const report = JSON.parse(result.stdout);
    return report.panorama?.state ?? 'planned';
  } catch {
    return 'invalid';
  }
}

/**
 * Sincroniza o `state` do manifest v3 (.work/NNNN.json) com o estado real do Work
 * derivado do plano/evidências. Retorna o novo estado, ou "manifest-ausente".
 */
export function syncWorkManifest(workId: string, rootDir: string = process.cwd()): string {
  const manifestPath = path.resolve(rootDir, '.work', `${workId}.json`);
  if (!fs.existsSync(manifestPath)) {
    return 'manifest-ausente';
  }

  const state = PANORAMA_TO_MANIFEST[panoramaState(workId, rootDir)] ?? 'planned';
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.state = state;
  manifest.updated_at = new Date().toISOString();
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return state;
}
