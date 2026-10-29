import { test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');

test('monta node_modules e bloqueia a rede', () => {
  const proof = JSON.parse(fs.readFileSync(path.join(ROOT, 'testdata/parity/sandbox.json'), 'utf8')) as Record<string, unknown>;
  if (proof.node_modules_visible !== true) throw new Error('SANDBOX-PROOF-FAILED: node_modules não visível');
  if (proof.network !== false) throw new Error('SANDBOX-PROOF-FAILED: rede habilitada');
  if (proof.check_exit !== 0) throw new Error(`SANDBOX-PROOF-FAILED: check exit ${proof.check_exit}`);
});
