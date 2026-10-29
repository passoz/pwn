import { test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');

test('conjunto de conformidade estável', () => {
  const result = spawnSync('bun', ['scripts/parity/schema-corpus.ts', '--check'], { cwd: ROOT, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`SCHEMA-CORPUS-FAILED: ${result.stderr || result.stdout}`);
});
