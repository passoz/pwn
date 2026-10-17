import { describe, expect, test } from 'bun:test';
import { aggregateExit, buildVerifyJobs } from '../src/commands/verify.js';

const cli = { execPath: '/bin/bun', cliPath: '/x/cli.ts', timeoutSeconds: 30 };
const ap = (work_id: string, task_id: string) => ({ work_id, task_id, kind: 'task' }) as never;

describe('buildVerifyJobs', () => {
  test('filtra Work, deduplica, ignora não vigentes e usa --global para G-n', () => {
    const jobs = buildVerifyJobs(
      [ap('0001', '1.1'), ap('0002', '1.1'), ap('0001', 'G-1'), ap('0001', '1.1'), ap('0001', '1.2')],
      '0001',
      cli,
      (t) => t !== '1.2',
    );
    expect(jobs.map((j) => j.id)).toEqual(['1.1', 'G-1']);
    expect(jobs[0].command).toEqual(['/bin/bun', '/x/cli.ts', 'verify', 'run', '--work', '0001', '--task', '1.1', '--timeout-seconds', '30']);
    expect(jobs[1].command).toContain('--global');
  });
});

describe('aggregateExit', () => {
  const r = (status: number, timedOut = false) => ({ status, timedOut });
  test('0 se todas passam', () => expect(aggregateExit([r(0), r(0)])).toBe(0));
  test('1 se alguma falha', () => expect(aggregateExit([r(0), r(1)])).toBe(1));
  test('timeout conta como falha', () => expect(aggregateExit([r(0, true)])).toBe(1));
  test('2 se alguma BLOCKED, mesmo com falhas', () => expect(aggregateExit([r(1), r(2), r(0)])).toBe(2));
});
