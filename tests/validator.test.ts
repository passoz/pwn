import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { validateWorkDocuments } from '../src/core/validator.js';

function workFixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-validate-'));
  mkdirSync(path.join(dir, '.piwerness', 'work', '0001'), { recursive: true });
  return dir;
}

const validPlan = {
  work_id: '0001',
  title: 'app',
  components: [{ name: 'core', purpose: 'nucleo' }],
  global_gates: ['suite verde'],
  tasks: [
    {
      id: '1.1',
      title: 'Nucleo',
      requirement_id: 'FR-001',
      spec_reference: 'CAP-001',
      contract_id: 'CTR-001',
      depends_on: [],
      components: ['core'],
      files: ['src/a.ts', 'tests/a.test.ts'],
      implementation_files: ['src/a.ts'],
      test_files: ['tests/a.test.ts'],
      red: { command: 'bun test', description: 'falha esperada' },
      implementation_steps: ['implementar'],
      acceptance_criteria: [{ command: 'bun test', description: 'passa' }],
    },
  ],
};

const validPrd = {
  id: 'PRD-0001',
  meta: { version: '1.0', created_at: '2026-09-10T00:00:00.000Z', author: 'operator' },
  title: 'PRD do app de teste',
  status: 'draft',
  problem: { statement: 'Problema que precisa ser resolvido pelo produto em teste' },
  solution: { statement: 'Solucao que resolve o problema descrito' },
  decisions: [{ id: 'DEC-001', statement: 'Decisao inicial', status: 'proposed' }],
  accepted_requirements: ['FR-001'],
};

test('validateWorkDocuments valida plan.json conforme schema', () => {
  const dir = workFixture();
  try {
    writeFileSync(path.join(dir, '.piwerness/work/0001/plan.json'), JSON.stringify(validPlan), 'utf8');
    const results = validateWorkDocuments('0001', dir);
    const plan = results.find((r) => r.file.endsWith('plan.json'));
    assert.ok(plan, 'plan.json deve ser validado');
    assert.equal(plan.valid, true, plan.errors.join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validateWorkDocuments reprova prd.json inválido apontando o campo', () => {
  const dir = workFixture();
  try {
    writeFileSync(path.join(dir, '.piwerness/work/0001/prd.json'), JSON.stringify({ id: 'PRD-0001' }), 'utf8');
    const results = validateWorkDocuments('0001', dir);
    const prd = results.find((r) => r.file.endsWith('prd.json'));
    assert.ok(prd);
    assert.equal(prd.valid, false);
    assert.ok(prd.errors.some((e) => /required property/.test(e)), `erro deve citar campo ausente: ${prd.errors.join('; ')}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validateWorkDocuments aceita prd.json conforme schema', () => {
  const dir = workFixture();
  try {
    writeFileSync(path.join(dir, '.piwerness/work/0001/prd.json'), JSON.stringify(validPrd), 'utf8');
    const results = validateWorkDocuments('0001', dir);
    const prd = results.find((r) => r.file.endsWith('prd.json'));
    assert.ok(prd);
    assert.equal(prd.valid, true, prd.errors.join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
