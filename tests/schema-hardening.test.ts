import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';
import { Ajv } from 'ajv';

const SCHEMA_DIR = path.resolve(import.meta.dirname, '../schemas');

const ajv = new Ajv({ allErrors: true, strict: false, formats: { date: true, 'date-time': true } });

const planValidate = ajv.compile(
  JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, 'plan.schema.json'), 'utf8')),
);
const systemValidate = ajv.compile(
  JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, 'system.schema.json'), 'utf8')),
);

/** Plano minimo valido usado como base; cada teste sobrescreve apenas o campo sob analise. */
function basePlan(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    work_id: '0001',
    title: 'Plano de teste',
    components: [{ name: 'core', purpose: 'nucleo do harness' }],
    global_gates: [],
    tasks: [
      {
        id: '1.1',
        title: 'Tarefa de teste',
        requirement_id: 'FR-001',
        spec_reference: 'spec#FR-001',
        contract_id: 'CTR-001',
        complexity: 'standard',
        components: ['core'],
        files: ['src/core/a.ts'],
        implementation_files: ['src/core/a.ts'],
        test_files: ['tests/a.test.ts'],
        red: { command: 'bun test tests/a.test.ts', description: 'falha antes da implementacao' },
        implementation_steps: ['implementar a'],
        acceptance_criteria: [{ command: 'bun test tests/a.test.ts', description: 'passa' }],
      },
    ],
    ...overrides,
  };
}

function withTask(overrides: Record<string, unknown>): Record<string, unknown> {
  const plan = basePlan();
  (plan.tasks as Record<string, unknown>[])[0] = {
    ...(plan.tasks as Record<string, unknown>[])[0],
    ...overrides,
  };
  return plan;
}

describe('schemas compilam sem $ref quebrado', () => {
  test('plan.schema.json compila', () => {
    expect(planValidate).toBeDefined();
    expect(typeof planValidate).toBe('function');
  });

  test('system.schema.json compila', () => {
    expect(systemValidate).toBeDefined();
    expect(typeof systemValidate).toBe('function');
  });
});

describe('plan.schema.json: enum de complexity', () => {
  test('complexity "standard" passa', () => {
    expect(planValidate(withTask({ complexity: 'standard' }))).toBe(true);
  });

  test('complexity "banana" falha', () => {
    expect(planValidate(withTask({ complexity: 'banana' }))).toBe(false);
  });

  test('todos os valores do enum sao aceitos', () => {
    for (const value of ['low', 'standard', 'medium', 'high', 'critical', 'architectural']) {
      expect(planValidate(withTask({ complexity: value }))).toBe(true);
    }
  });
});

describe('plan.schema.json: tetos de aceitacao', () => {
  test('3 acceptance_criteria passa', () => {
    const ac = Array.from({ length: 3 }, (_, i) => ({ command: `cmd ${i}`, description: `desc ${i}` }));
    expect(planValidate(withTask({ acceptance_criteria: ac }))).toBe(true);
  });

  test('13 acceptance_criteria falha', () => {
    const ac = Array.from({ length: 13 }, (_, i) => ({ command: `cmd ${i}`, description: `desc ${i}` }));
    expect(planValidate(withTask({ acceptance_criteria: ac }))).toBe(false);
  });
});

describe('plan.schema.json: tetos declarados', () => {
  test('implementation_steps acima de 12 falha', () => {
    const steps = Array.from({ length: 13 }, (_, i) => `passo ${i}`);
    expect(planValidate(withTask({ implementation_steps: steps }))).toBe(false);
  });

  test('components acima de 3 falha', () => {
    expect(planValidate(withTask({ components: ['a', 'b', 'c', 'd'] }))).toBe(false);
  });

  test('test_files acima de 12 falha', () => {
    const files = Array.from({ length: 13 }, (_, i) => `tests/f${i}.test.ts`);
    expect(planValidate(withTask({ test_files: files }))).toBe(false);
  });

  test('implementation_files acima de 12 falha', () => {
    const files = Array.from({ length: 13 }, (_, i) => `src/f${i}.ts`);
    expect(planValidate(withTask({ implementation_files: files }))).toBe(false);
  });

  test('tasks acima de 40 falha', () => {
    const task = (basePlan().tasks as Record<string, unknown>[])[0];
    const tasks = Array.from({ length: 41 }, (_, i) => ({ ...task, id: `1.${i}` }));
    expect(planValidate(basePlan({ tasks }))).toBe(false);
  });

  test('plano real de 3 tarefas continua valido', () => {
    expect(planValidate(basePlan())).toBe(true);
  });
});

describe('system.schema.json: tetos declarados', () => {
  function baseSystem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      meta: {
        title: 'Sistema de teste',
        version: 1,
        last_reconciled: '2026-01-01',
        scope: 'escopo minimo para validacao do schema',
      },
      status: 'Baseline validada',
      actors: [{ id: 'ACT-001', name: 'ator', description: 'desc', evidence: 'src/a.ts' }],
      capabilities: [
        {
          id: 'CAP-001',
          title: 'capacidade',
          value: 'valor',
          actors: ['ACT-001'],
          behavior: 'comportamento',
          failures: 'falhas',
          rules: ['BR-001'],
          contracts: ['CON-001'],
          evidence: 'src/a.ts',
        },
      ],
      rules: [{ id: 'BR-001', statement: 'regra', coverage: ['CAP-001'], evidence: 'src/a.ts' }],
      contracts: [
        {
          id: 'CON-001',
          title: 'contrato',
          consumers: ['ACT-001'],
          inputs: 'in',
          outputs: 'out',
          errors: 'erros',
          compatibility: 'backward',
          evidence: 'src/a.ts',
        },
      ],
      entities: [{ id: 'ENT-001', name: 'entidade', description: 'desc', evidence: 'src/a.ts' }],
      coverage: {
        capabilities: [{ id: 'CAP-001', status: 'Confirmado', evidence: 'src/a.ts', observation: 'ok' }],
        gaps: [],
      },
      traceability: [{ capability: 'CAP-001', actors: ['ACT-001'], rules: ['BR-001'], contracts: ['CON-001'] }],
      ...overrides,
    };
  }

  test('system baseline minimo passa', () => {
    expect(systemValidate(baseSystem())).toBe(true);
  });

  test('capabilities acima de 40 falha', () => {
    const cap = (baseSystem().capabilities as Record<string, unknown>[])[0];
    const capabilities = Array.from({ length: 41 }, (_, i) => ({ ...cap, id: `CAP-${String(i).padStart(3, '0')}` }));
    expect(systemValidate(baseSystem({ capabilities }))).toBe(false);
  });

  test('rules acima de 120 falha', () => {
    const rule = (baseSystem().rules as Record<string, unknown>[])[0];
    const rules = Array.from({ length: 121 }, (_, i) => ({ ...rule, id: `BR-${String(i).padStart(3, '0')}` }));
    expect(systemValidate(baseSystem({ rules }))).toBe(false);
  });
});
