import { describe, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');
const FIXTURE = ['bun', '-e', 'console.log("472 pass\\n0 fail\\nRan 472 tests across 42 files")'];

describe('linha de base (aceitação)', () => {
  test('captura a linha de base', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-baseline-acceptance-'));
    try {
      const out = path.join(directory, 'manifest.json');
      const result = spawnSync(
        'bun',
        ['scripts/parity/capture-baseline.ts', '--out', out, '--command', JSON.stringify(FIXTURE)],
        { cwd: ROOT, encoding: 'utf8' },
      );
      if (result.status !== 0) throw new Error(`CAPTURE-FAILED: ${result.stderr || result.stdout}`);
      const report = JSON.parse(fs.readFileSync(out, 'utf8')) as Record<string, number>;
      if (report.exit_code !== 0) throw new Error(`BASELINE-EXIT: ${report.exit_code}`);
      if (report.tests_pass !== 472) throw new Error(`BASELINE-COUNT: ${report.tests_pass}`);
      if (report.tests_fail !== 0) throw new Error(`BASELINE-FAIL: ${report.tests_fail}`);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  test('executor diferencial detecta divergência', () => {
    const result = spawnSync('bun', ['scripts/parity/diff.ts', '--self-test'], { cwd: ROOT, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(`DIFF-SELFTEST-FAILED: ${result.stderr || result.stdout}`);
  });
});
