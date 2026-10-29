import { test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');

test('vetores de referência estáveis', () => {
  const result = spawnSync('bun', ['scripts/parity/golden.ts', '--check'], { cwd: ROOT, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`GOLDEN-CHECK-FAILED: ${result.stderr || result.stdout}`);
});
