import fs from 'node:fs';
import path from 'node:path';

export interface MetricsEntry {
  timestamp: string;
  runId: string;
  workId: string;
  taskId: string;
  agentRole: 'cheap' | 'strong' | 'review' | 'plan';
  model: string;
  tokensInput: number;
  tokensOutput: number;
  costUSD: number;
  durationMs: number;
  status: 'success' | 'failed' | 'escalated';
  attempts: number;
}

export interface OptimizationSuggestion {
  taskId?: string;
  agentRole: string;
  currentModel: string;
  recommendedRole: string;
  reason: string;
  estimatedSavingsPercent: number;
}

export function getMetricsFilePath(rootDir: string = process.cwd()): string {
  const dir = path.resolve(rootDir, '.piwerness');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return path.join(dir, 'metrics.jsonl');
}

export function recordMetrics(entry: MetricsEntry, rootDir: string = process.cwd()): void {
  const filePath = getMetricsFilePath(rootDir);
  const line = JSON.stringify(entry) + '\n';
  fs.appendFileSync(filePath, line, 'utf8');
}

export function readMetrics(rootDir: string = process.cwd()): MetricsEntry[] {
  const filePath = getMetricsFilePath(rootDir);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l.trim().length > 0);

  const entries: MetricsEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      // Skip malformed lines
    }
  }

  return entries;
}

export function generateOptimizationSuggestions(rootDir: string = process.cwd()): OptimizationSuggestion[] {
  const entries = readMetrics(rootDir);

  if (entries.length === 0) {
    return [];
  }

  const suggestions: OptimizationSuggestion[] = [];

  // Analyze entries for tasks run with 'strong' that passed on attempt 1 without failures
  const strongSuccesses = entries.filter(e => e.agentRole === 'strong' && e.status === 'success' && e.attempts === 1);
  if (strongSuccesses.length > 0) {
    suggestions.push({
      agentRole: 'strong',
      currentModel: 'claude-3-7-sonnet',
      recommendedRole: 'cheap',
      reason: `${strongSuccesses.length} execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para papel 'cheap' com economia.`,
      estimatedSavingsPercent: 65,
    });
  }

  return suggestions;
}
