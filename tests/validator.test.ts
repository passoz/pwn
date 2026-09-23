import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { validateNormativeDocument, validateWorkDocuments } from '../src/core/validator.js';

function workFixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-validate-'));
  mkdirSync(path.join(dir, '.pwn', 'work', '0001'), { recursive: true });
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
    writeFileSync(path.join(dir, '.pwn/work/0001/plan.json'), JSON.stringify(validPlan), 'utf8');
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
    writeFileSync(path.join(dir, '.pwn/work/0001/prd.json'), JSON.stringify({ id: 'PRD-0001' }), 'utf8');
    const results = validateWorkDocuments('0001', dir);
    const prd = results.find((r) => r.file.endsWith('prd.json'));
    assert.ok(prd);
    assert.equal(prd.valid, false);
    assert.ok(prd.errors.some((e) => /required property/.test(e)), `erro deve citar campo ausente: ${prd.errors.join('; ')}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validateNormativeDocument reprova documento que declara schema desconhecido', () => {
  const dir = workFixture();
  try {
    writeFileSync(
      path.join(dir, '.pwn/work/0001/plan.json'),
      JSON.stringify({ ...validPlan, $schema: 'https://pwn.dev/schemas/inexistente.schema.json' }),
      'utf8',
    );
    const result = validateNormativeDocument('.pwn/work/0001/plan.json', dir);
    assert.equal(result.valid, false, 'documento com schema declarado e indisponível nunca pode passar');
    assert.ok(
      result.errors.some((e) => e.includes('inexistente.schema.json')),
      `erro deve nomear o schema indisponível: ${result.errors.join('; ')}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('validateWorkDocuments aceita prd.json conforme schema', () => {
  const dir = workFixture();
  try {
    writeFileSync(path.join(dir, '.pwn/work/0001/prd.json'), JSON.stringify(validPrd), 'utf8');
    const results = validateWorkDocuments('0001', dir);
    const prd = results.find((r) => r.file.endsWith('prd.json'));
    assert.ok(prd);
    assert.equal(prd.valid, true, prd.errors.join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejeita $schema que resolve para a cadeia de protótipos em vez de uma lei embutida', () => {
  // Regressão: `schemaFile in EMBEDDED_SCHEMAS` aceitava chaves herdadas de
  // Object.prototype, então `"constructor"`/`"toString"` passavam sem validação
  // alguma e `"__proto__"`/`"valueOf"` derrubavam o CLI com TypeError.
  const dir = workFixture();
  try {
    const target = path.join(dir, 'evidencia.json');
    for (const key of ['constructor', 'toString', '__proto__', 'valueOf', 'hasOwnProperty', 'name']) {
      writeFileSync(target, JSON.stringify({ $schema: key, conteudo: 'qualquer coisa' }), 'utf8');
      const result = validateNormativeDocument(target, dir);
      assert.equal(result.valid, false, `$schema=${key} não pode ser aceito como lei embutida`);
      assert.match(result.errors.join('\n'), /não verificável|unknown schema/i);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejeita $schema declarado sem nome de schema utilizável', () => {
  // Regressão: `"$schema": ""` (ou null/42/{}/[]) era tratado como "sem schema
  // declarado" e o documento passava sem validação nenhuma.
  const dir = workFixture();
  try {
    const target = path.join(dir, 'evidencia.json');
    for (const declared of ['', '/', 42, null, true, {}, []]) {
      writeFileSync(target, JSON.stringify({ $schema: declared, conteudo: 'qualquer coisa' }), 'utf8');
      const result = validateNormativeDocument(target, dir);
      assert.equal(result.valid, false, `$schema=${JSON.stringify(declared)} não pode escapar da validação`);
      assert.match(result.errors.join('\n'), /não verificável/i);
    }

    // Ausência de `$schema` continua sendo documento validado pelos gates, não erro.
    writeFileSync(target, JSON.stringify({ conteudo: 'sem schema' }), 'utf8');
    assert.equal(validateNormativeDocument(target, dir).valid, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
