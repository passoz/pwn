import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { withFileLock, writeFileAtomic } from './fs-lock.js';

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
  const dir = path.resolve(rootDir, '.pwn');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return path.join(dir, 'learnings.json');
}

export function addLearning(learning: Omit<LearningEntry, 'id' | 'timestamp'>, rootDir: string = process.cwd()): LearningEntry {
  const file = getLearningsFilePath(rootDir);

  // Read-modify-write compartilhado entre runs paralelas: sob lock, e com id único
  // (Date.now() sozinho colide entre processos no mesmo milissegundo).
  return withFileLock(file, () => {
    const existing = readLearnings(rootDir);
    const newEntry: LearningEntry = {
      id: `LRN-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      ...learning,
    };
    existing.push(newEntry);
    writeFileAtomic(file, JSON.stringify(existing, null, 2));
    return newEntry;
  });
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
