import { test, expect, describe } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(import.meta.dir, '../bin/pwn.js');

function run(cwd: string, args: string[]) {
  const result = spawnSync('bun', [CLI, ...args], { cwd, encoding: 'utf8' });
  return { status: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function makeWork(cwd: string, workId: string, files: Record<string, unknown>) {
  const dir = path.join(cwd, '.piwerness', 'work', workId);
  mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(path.join(dir, name), `${JSON.stringify(content, null, 2)}\n`, 'utf8');
  }
}

const COMPLETE = {
  'requirements.json': { requirements: [{ id: 'FR-001' }, { id: 'FR-002' }] },
  'prd.json': { accepted_requirements: ['FR-001', 'FR-002'] },
  'spec.json': { capabilities: [{ id: 'CAP-001', rules: ['BR-001'] }, { id: 'CAP-002', rules: ['BR-002'] }] },
  'plan.json': {
    work_id: '0001',
    title: 't',
    components: [{ name: 'c', purpose: 'p' }],
    global_gates: [],
    tasks: [
      { id: '1.1', contract_id: 'CTR-001', acceptance_criteria: [{ command: 'x', description: 'd' }] },
      { id: '1.2', contract_id: 'CTR-002', acceptance_criteria: [{ command: 'y', description: 'd' }] },
    ],
  },
};

describe('pwn work status --coverage', () => {
  test('reporta COMPLETO e exit 0 quando todos os vínculos existem', () => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'pwn-coverage-ok-'));
    try {
      makeWork(cwd, '0001', COMPLETE);
      const r = run(cwd, ['work', 'status', '--coverage', '--work', '0001']);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('COVERAGE RESULT');
      expect(r.stdout).toContain('COMPLETO');
      expect(r.stdout).toContain('requisitos aceitos');
      expect(r.stdout).toContain('2/2');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test('reporta lacunas e exit 1 quando faltam vínculos', () => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'pwn-coverage-gap-'));
    try {
      makeWork(cwd, '0001', {
        ...COMPLETE,
        // apenas 1 dos 2 requisitos aceito; 1 capability sem regras; 1 task sem AC
        'prd.json': { accepted_requirements: ['FR-001'] },
        'spec.json': { capabilities: [{ id: 'CAP-001', rules: ['BR-001'] }, { id: 'CAP-002' }] },
        'plan.json': {
          ...COMPLETE['plan.json'],
          tasks: [
            { id: '1.1', contract_id: 'CTR-001', acceptance_criteria: [{ command: 'x', description: 'd' }] },
            { id: '1.2' },
          ],
        },
      });
      const r = run(cwd, ['work', 'status', '--coverage', '--work', '0001']);
      expect(r.status).toBe(1);
      expect(r.stdout).toContain('lacuna');
      expect(r.stdout).toContain('1/2');
      expect(r.stdout).toContain('4 lacuna(s)');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test('não quebra o status normal (sem --coverage) quando o Work não existe', () => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'pwn-coverage-missing-'));
    try {
      const r = run(cwd, ['work', 'status', '--coverage', '--work', '9999']);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('não encontrado');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
});
