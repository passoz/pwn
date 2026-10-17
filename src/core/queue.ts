import fs from 'node:fs';
import path from 'node:path';

export interface QueueItem {
  runId: string;
  workId: string;
  taskId: string;
  title: string;
  pausedAtStep: string;
  reason: string;
  riskLevel: string;
  createdAt: string;
  status: 'pending_review' | 'approved' | 'rejected';
  payload?: any;
}

export function getQueueDir(rootDir: string = process.cwd()): string {
  const qDir = path.resolve(rootDir, 'queue/review');
  if (!fs.existsSync(qDir)) {
    fs.mkdirSync(qDir, { recursive: true });
  }
  return qDir;
}

export function enqueueReview(
  item: Omit<QueueItem, 'createdAt' | 'status'>,
  rootDir: string = process.cwd(),
  status: QueueItem['status'] = 'pending_review',
): QueueItem {
  const qDir = getQueueDir(rootDir);
  const fullItem: QueueItem = {
    ...item,
    createdAt: new Date().toISOString(),
    status,
  };

  const filePath = path.join(qDir, `${item.runId}.json`);
  fs.writeFileSync(filePath, JSON.stringify(fullItem, null, 2), 'utf8');

  return fullItem;
}

export function listQueueItems(rootDir: string = process.cwd()): QueueItem[] {
  const qDir = getQueueDir(rootDir);
  const files = fs.readdirSync(qDir).filter(f => f.endsWith('.json'));

  const items: QueueItem[] = [];
  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(qDir, file), 'utf8');
      items.push(JSON.parse(content));
    } catch {
      // Ignore corrupt files
    }
  }

  return items;
}

/** Vínculo de uma aprovação L4: vale só para o contrato e o comando que foram revisados. */
export interface ReviewBinding {
  contract_sha256: string;
  command: string[];
}

/** Aprovação vigente na fila para a task, com o mesmo contrato e o mesmo comando. */
export function findApprovedReview(workId: string, taskId: string, binding: ReviewBinding, rootDir: string = process.cwd()): QueueItem | null {
  const wanted = JSON.stringify(binding.command);
  return (
    listQueueItems(rootDir).find(
      (item) =>
        item.status === 'approved' &&
        item.workId === workId &&
        item.taskId === taskId &&
        item.payload?.contract_sha256 === binding.contract_sha256 &&
        JSON.stringify(item.payload?.command) === wanted,
    ) ?? null
  );
}

export function updateQueueStatus(
  runId: string,
  newStatus: 'approved' | 'rejected',
  rootDir: string = process.cwd()
): QueueItem | null {
  const qDir = getQueueDir(rootDir);
  const filePath = path.join(qDir, `${runId}.json`);

  if (!fs.existsSync(filePath)) {
    return null;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const item: QueueItem = JSON.parse(content);

  item.status = newStatus;
  fs.writeFileSync(filePath, JSON.stringify(item, null, 2), 'utf8');

  return item;
}
