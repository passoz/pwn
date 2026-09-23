import { describe, expect, test } from 'bun:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { describeBaseline, mutationCases, runMutations } from '../src/core/self_check_mutate.js';

/** Escreve um Work mínimo porém válido (todos os gates passam antes das mutações). */
function writeValidWork(rootDir: string, workId = '0001'): string {
  const workDir = path.join(rootDir, '.pwn', 'work', workId);
  fs.mkdirSync(workDir, { recursive: true });
  const artifacts: Record<string, unknown> = {
    'discovery.json': {
      work_id: workId,
      problem: 'Problema de teste',
      actors: ['ACT-001'],
      objectives: ['Objetivo de teste'],
      constraints: ['Restrição de teste'],
    },
    'requirements.json': {
      work_id: workId,
      requirements: [
        {
          id: 'FR-001',
          title: 'Requisito de teste',
          user_story: 'Como operador, quero X para obter Y',
          acceptance_criteria: ['Critério observável'],
        },
      ],
    },
    'prd.json': {
      id: `PRD-${workId}`,
      title: `PRD de teste do Work ${workId}`,
      status: 'draft',
      accepted_requirements: ['FR-001'],
      requirements: [{ id: 'FR-001', statement: 'Manter a rastreabilidade entre artefatos.' }],
    },
    'spec.json': {
      work_id: workId,
      capabilities: [
        { id: 'CAP-001', description: 'Capacidade que atende FR-001', rules: ['RULE-001: preservar rastreabilidade'] },
      ],
    },
    'plan.json': {
      work_id: workId,
      tasks: [
        {
          id: 'T-001',
          description: 'Task de teste',
          spec_reference: 'CAP-001',
          contract_id: 'CTR-001',
          acceptance_criteria: ['Critério de aceite da task'],
        },
      ],
    },
    'traceability-matrix.json': {
      work_id: workId,
      matrix: [
        {
          origin: 'DISC-001',
          requirement_id: 'FR-001',
          decision_id: 'TD-001',
          spec_section: 'CAP-001',
          task_id: 'T-001',
          contract_id: 'CTR-001',
          evidence_id: 'EVD-001',
          status: 'planned',
        },
      ],
    },
  };
  for (const [name, value] of Object.entries(artifacts)) {
    fs.writeFileSync(path.join(workDir, name), `${JSON.stringify(value, null, 2)}\n`);
  }
  return workDir;
}

/** Hash estável do conteúdo de um diretório de Work (detecta qualquer escrita). */
function hashDir(dir: string): string {
  const hash = crypto.createHash('sha256');
  const walk = (current: string): void => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else {
        hash.update(path.relative(dir, full));
        hash.update(fs.readFileSync(full));
      }
    }
  };
  walk(dir);
  return hash.digest('hex');
}

function withFixture(run: (rootDir: string, workDir: string) => void): void {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-self-check-mut-'));
  try {
    run(rootDir, writeValidWork(rootDir));
  } finally {
    fs.rmSync(rootDir, { recursive: true, force: true });
  }
}

describe('mutationCases', () => {
  test('declara ao menos 5 mutações com id e gate únicos', () => {
    const cases = mutationCases();
    expect(cases.length).toBeGreaterThanOrEqual(5);
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
    expect(new Set(cases.map((c) => c.gate)).size).toBe(cases.length);
    for (const mutationCase of cases) {
      expect(mutationCase.description.length).toBeGreaterThan(0);
      expect(mutationCase.gate.startsWith('GATE-')).toBe(true);
      expect(typeof mutationCase.expect_blocked).toBe('boolean');
    }
  });

  test('inclui os casos canônicos exigidos pelo harness', () => {
    const ids = mutationCases().map((c) => c.id);
    for (const id of [
      'mut-missing-ac',
      'mut-missing-contract',
      'mut-broken-traceability',
      'mut-prd-missing-accepted',
      'mut-spec-no-rules',
    ]) {
      expect(ids).toContain(id);
    }
  });
});

describe('runMutations', () => {
  test('retorna um resultado por caso, sem lançar, sobre um Work temporário válido', () => {
    withFixture((rootDir) => {
      const results = runMutations({ workId: '0001', rootDir });
      const cases = mutationCases();

      expect(results.length).toBe(cases.length);
      for (const result of results) {
        const mutationCase = cases.find((c) => c.id === result.id);
        expect(mutationCase).toBeDefined();
        expect(result.gate).toBe(mutationCase!.gate);
        expect(typeof result.detected).toBe('boolean');
        expect(result.detail.length).toBeGreaterThan(0);
      }
      // A baseline veio do Work do projeto, não da baseline canônica embutida.
      expect(describeBaseline({ workId: '0001', rootDir })).not.toContain('baseline canônica');
    });
  });

  test('detecta as mutações declaradas como bloqueantes', () => {
    withFixture((rootDir) => {
      const results = runMutations({ workId: '0001', rootDir });
      const blocked = results.filter((r) => mutationCases().find((c) => c.id === r.id)!.expect_blocked);
      expect(blocked.length).toBeGreaterThanOrEqual(2);
      for (const result of blocked) {
        expect(result.detected).toBe(true);
        expect(result.detail).toContain('depois=\'blocked\'');
      }
    });
  });

  test('expõe gates decorativos: mutações advisory ficam registradas com veredito honesto', () => {
    withFixture((rootDir) => {
      const results = runMutations({ workId: '0001', rootDir });
      const advisory = results.filter((r) => !mutationCases().find((c) => c.id === r.id)!.expect_blocked);
      expect(advisory.length).toBeGreaterThanOrEqual(1);
      for (const result of advisory) {
        expect(result.detail).toContain('antes=');
        // O detalhe precisa explicar o veredito: gate não bloqueou, mutação não
        // aplicável, ou gate endureceu depois que a lista canônica foi medida.
        const explained =
          result.detail.includes('gate não bloqueia') ||
          result.detail.includes('não aplicável') ||
          result.detail.includes('gate endureceu');
        expect(explained).toBe(true);
        if (result.detail.includes('gate endureceu')) expect(result.detected).toBe(true);
        else expect(result.detected).toBe(false);
      }
      // Estado medido hoje: GATE-SPEC-PLAN não olha acceptance_criteria das tasks,
      // GATE-PLAN-CONTRACT só confere presença de contract_id e GATE-PRD-SPEC trata
      // capability sem rules como finding 'medium' (advisory) — ver docs/LIMITES.md.
      expect(results.find((r) => r.id === 'mut-spec-no-rules')!.detail).toContain('pass_with_notes');
    });
  });

  test('nunca modifica o Work original', () => {
    withFixture((rootDir, workDir) => {
      const before = hashDir(workDir);
      const results = runMutations({ workId: '0001', rootDir });
      expect(results.some((r) => r.detected)).toBe(true);
      expect(hashDir(workDir)).toBe(before);
    });
  });

  test('usa a baseline canônica quando o Work não existe, sem lançar', () => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-self-check-mut-'));
    try {
      expect(describeBaseline({ workId: '9999', rootDir })).toContain('não encontrado');
      const results = runMutations({ workId: '9999', rootDir });
      expect(results.length).toBe(mutationCases().length);
      expect(results.some((r) => r.detected)).toBe(true);
      expect(fs.readdirSync(rootDir).length).toBe(0);
    } finally {
      fs.rmSync(rootDir, { recursive: true, force: true });
    }
  });
});
