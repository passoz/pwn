import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  computeWorkCoverage,
  evaluateAllGates,
  evaluateGateSpecPlan,
  validateTaskAtomicity,
} from '../src/core/gates.js';

function fixture(): string {
  return mkdtempSync(path.join(tmpdir(), 'pwn-atomic-'));
}

function writeJson(workDir: string, name: string, data: unknown): void {
  writeFileSync(path.join(workDir, name), `${JSON.stringify(data, null, 2)}\n`);
}

const ATOMIC_PLAN = {
  work_id: '0001',
  title: 'Plano atômico',
  components: [{ name: 'core', purpose: 'Componente principal' }],
  global_gates: ['bun test'],
  tasks: [
    {
      id: '1.1',
      title: 'Implementar capacidade única',
      requirement_id: 'FR-001',
      behavior: 'entrega a capacidade declarada',
      components: ['core'],
      files: ['src/core/x.ts'],
      implementation_files: ['src/core/x.ts'],
      test_files: ['tests/x.test.ts'],
      red: { command: 'bun test', description: 'falha antes da implementação' },
      implementation_steps: ['RED', 'GREEN'],
      acceptance_criteria: [{ command: 'bun test', description: 'suíte verde' }],
      spec_reference: 'CAP-001',
      contract_id: 'CTR-001',
    },
  ],
};

describe('validateTaskAtomicity', () => {
  test('task atômica não gera findings', () => {
    const workDir = fixture();
    try {
      writeJson(workDir, 'plan.json', ATOMIC_PLAN);
      expect(validateTaskAtomicity(workDir)).toEqual([]);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('spec_reference múltipla e componentes acoplados geram findings advisory', () => {
    const workDir = fixture();
    try {
      writeJson(workDir, 'plan.json', {
        ...ATOMIC_PLAN,
        tasks: [
          {
            ...ATOMIC_PLAN.tasks[0],
            id: '2.1',
            spec_reference: 'CAP-001 + CAP-002',
            components: ['core', 'cli'],
          },
        ],
      });

      const findings = validateTaskAtomicity(workDir);
      const specFinding = findings.find((f) => f.id === 'FIND-ATOMIC-SPEC-2.1');
      const compFinding = findings.find((f) => f.id === 'FIND-ATOMIC-COMP-2.1');

      expect(specFinding).toBeDefined();
      expect(specFinding?.severity).toBe('medium');
      expect(specFinding?.type).toBe('coverage_gap');
      expect(specFinding?.resolution_owner).toBe('planner');
      expect(specFinding?.status).toBe('open');
      expect(specFinding?.required_resolution).toBe('Dividir a task para referenciar uma única capability');

      expect(compFinding).toBeDefined();
      expect(compFinding?.severity).toBe('low');
      expect(compFinding?.target_refs).toEqual(['core', 'cli']);
      expect(compFinding?.required_resolution).toBe('Dividir a task por componente ou justificar o acoplamento');

      // Atomicidade é advisory: nunca bloqueia o gate.
      expect(evaluateGateSpecPlan('0001', workDir).result).toBe('pass_with_notes');
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('plan.json ausente retorna lista vazia', () => {
    const workDir = fixture();
    try {
      expect(validateTaskAtomicity(workDir)).toEqual([]);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});

describe('computeWorkCoverage', () => {
  test('diretório vazio retorna zeros sem lançar', () => {
    const workDir = fixture();
    try {
      expect(computeWorkCoverage(workDir)).toEqual({
        requirements: 0,
        accepted_requirements: 0,
        capabilities: 0,
        capabilities_with_rules: 0,
        tasks: 0,
        tasks_with_contract: 0,
        tasks_with_acs: 0,
      });
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('conta artefatos e vínculos presentes', () => {
    const workDir = fixture();
    try {
      writeJson(workDir, 'requirements.json', {
        work_id: '0001',
        requirements: [{ id: 'FR-001' }, { id: 'FR-002' }],
      });
      writeJson(workDir, 'prd.json', { accepted_requirements: ['FR-001'] });
      writeJson(workDir, 'spec.json', {
        capabilities: [
          { id: 'CAP-001', rules: ['BR-001'] },
          { id: 'CAP-002', rules: [] },
        ],
      });
      writeJson(workDir, 'plan.json', ATOMIC_PLAN);

      expect(computeWorkCoverage(workDir)).toEqual({
        requirements: 2,
        accepted_requirements: 1,
        capabilities: 2,
        capabilities_with_rules: 1,
        tasks: 1,
        tasks_with_contract: 1,
        tasks_with_acs: 1,
      });
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});

describe('evaluateAllGates', () => {
  test('roda os 5 gates na ordem canônica', () => {
    const workDir = fixture();
    try {
      const outputs = evaluateAllGates('0001', workDir);
      expect(outputs).toHaveLength(5);
      expect(outputs.map((o) => o.gate)).toEqual([
        'GATE-DISC-REQ',
        'GATE-REQ-PRD',
        'GATE-PRD-SPEC',
        'GATE-SPEC-PLAN',
        'GATE-PLAN-CONTRACT',
      ]);
      // Não para no primeiro gate bloqueado: todos os artefatos estão ausentes aqui.
      expect(outputs.every((o) => o.result === 'blocked')).toBe(true);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});
