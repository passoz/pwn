import fs from 'node:fs';
import path from 'node:path';

export interface LearningEntry {
  id: string;
  timestamp: string;
  category: 'code_style' | 'architecture' | 'gotcha' | 'domain_rule';
  title: string;
  description: string;
  sourceTaskId?: string;
  tags: string[];
}

export function getLearningsFilePath(rootDir: string = process.cwd()): string {
  const dir = path.resolve(rootDir, '.piwerness');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return path.join(dir, 'learnings.json');
}

export function addLearning(learning: Omit<LearningEntry, 'id' | 'timestamp'>, rootDir: string = process.cwd()): LearningEntry {
  const file = getLearningsFilePath(rootDir);
  const existing = readLearnings(rootDir);

  const newEntry: LearningEntry = {
    id: `LRN-${Date.now()}`,
    timestamp: new Date().toISOString(),
    ...learning,
  };

  existing.push(newEntry);
  fs.writeFileSync(file, JSON.stringify(existing, null, 2), 'utf8');

  return newEntry;
}

export function readLearnings(rootDir: string = process.cwd()): LearningEntry[] {
  const file = getLearningsFilePath(rootDir);
  if (!fs.existsSync(file)) {
    return [];
  }

  try {
    const content = fs.readFileSync(file, 'utf8');
    return JSON.parse(content);
  } catch {
    return [];
  }
}
