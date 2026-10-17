import { describe, expect, test } from 'bun:test';
import { runPool, type PoolJob } from '../src/core/process-pool.js';

const sh = (id: string, script: string): PoolJob => ({ id, command: ['sh', '-c', script] });

describe('runPool', () => {
  test('preserva a ordem de jobs com durações invertidas', async () => {
    const jobs = [sh('a', 'sleep 0.4; echo a'), sh('b', 'sleep 0.2; echo b'), sh('c', 'echo c')];
    const finished: string[] = [];
    const results = await runPool(jobs, { concurrency: 3, onResult: (r) => finished.push(r.id) });
    expect(results.map((r) => r.id)).toEqual(['a', 'b', 'c']);
    expect(results.map((r) => r.stdout.trim())).toEqual(['a', 'b', 'c']);
    expect(finished[0]).toBe('c');
  });

  test('concorrência nunca excede N', async () => {
    const jobs = Array.from({ length: 6 }, (_, i) => sh(`j${i}`, 'date +%s%N; sleep 0.3; date +%s%N'));
    const results = await runPool(jobs, { concurrency: 2 });
    const spans = results.map((r) => {
      const [s, e] = r.stdout.trim().split('\n').map((v) => BigInt(v));
      return { s, e };
    });
    for (const probe of spans) {
      const overlapping = spans.filter((o) => o.s <= probe.s && o.e > probe.s).length;
      expect(overlapping).toBeLessThanOrEqual(2);
    }
  });

  test('timeout mata o processo e marca timedOut', async () => {
    const [r] = await runPool([sh('slow', 'sleep 10')], { concurrency: 1, timeoutMs: 200 });
    expect(r.timedOut).toBe(true);
    expect(r.durationMs).toBeLessThan(5000);
  });

  test('exit != 0 não rejeita e captura stderr', async () => {
    const [r] = await runPool([sh('bad', 'echo oops >&2; exit 3')], { concurrency: 1 });
    expect(r.status).toBe(3);
    expect(r.stderr).toContain('oops');
    expect(r.timedOut).toBe(false);
  });
});
