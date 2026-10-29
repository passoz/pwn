import { createHash, createHmac, createPrivateKey, sign } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../../src/core/acceptance.js';
import { renderTasksMarkdown, type Plan } from '../../src/core/plan-renderer.js';

const root = process.cwd();
const directory = path.join(root, 'testdata/parity/golden');
const key = JSON.parse(fs.readFileSync(path.join(directory, 'ed25519-key.json'), 'utf8')) as {
  private: string;
  public: string;
};
const privateKey = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', d: key.private, x: key.public },
  format: 'jwk',
});

const subject = {
  approval_id: 'APR-TEST-0002',
  work_id: '0002',
  task_id: '1.3',
  outcome: 'pass',
  checks: [{ id: 'AC-1', exit_code: 0 }],
};
const canonical = canonicalJson(subject);
const plan: Plan = {
  work_id: '0002',
  title: 'Vetor de referência',
  components: [{ name: 'parity', purpose: 'vetores de referência' }],
  global_gates: ['`bun test tests/parity` — a suíte de paridade passa com exit 0.'],
  tasks: [
    {
      id: '1.3',
      title: 'Gerar os vetores de referência',
      requirement_id: 'FR-003',
      depends_on: [],
      behavior: 'gera vetores determinísticos para comparação entre os binários',
      components: ['parity'],
      files: ['testdata/parity/golden/vectors.json'],
      implementation_files: ['scripts/parity/golden.ts'],
      test_files: ['tests/parity/golden.test.ts'],
      red: { command: 'bun test tests/parity/golden.test.ts', description: 'os vetores ainda não existem' },
      implementation_steps: ['Gerar os vetores', 'Conferir a segunda execução'],
      acceptance_criteria: [{ command: 'bun scripts/parity/golden.ts --check', description: 'os vetores são estáveis' }],
      visual: 'N/A',
      documentation: 'N/A',
      spec_reference: 'CAP-001',
      contract_id: 'CTR-003',
      complexity: 'standard',
      status: 'pending',
    },
  ],
};

const vectors = {
  canonical_json: canonical,
  sha256: createHash('sha256').update('pwn-golden').digest('hex'),
  hmac_sha256: createHmac('sha256', 'pwn-golden-key').update('pwn-golden').digest('hex'),
  ed25519_signature: sign(null, Buffer.from(canonical), privateKey).toString('base64'),
  plan_markdown: renderTasksMarkdown(plan),
};

const checkPath = path.join(directory, 'vectors.json');
const args = process.argv.slice(2);
if (args.includes('--write')) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(checkPath, `${JSON.stringify(vectors, null, 2)}\n`, 'utf8');
  console.log(`PASS: vetores gravados em ${path.relative(root, checkPath)}`);
  process.exit(0);
}
if (args.includes('--check')) {
  if (!fs.existsSync(checkPath)) {
    console.error('GOLDEN-CHECK-FAILED: vectors.json ausente; rode --write');
    process.exit(1);
  }
  const expected = JSON.parse(fs.readFileSync(checkPath, 'utf8')) as Record<string, unknown>;
  if (JSON.stringify(vectors) !== JSON.stringify(expected)) {
    console.error('GOLDEN-CHECK-FAILED: os vetores calculados divergem dos gravados');
    process.exit(1);
  }
  console.log('PASS: vetores de referência estáveis');
  process.exit(0);
}
console.error('uso: bun scripts/parity/golden.ts --write | --check');
process.exit(2);
