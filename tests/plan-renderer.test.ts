import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { renderTasksMarkdown, normalizeMarkers, planMatchesMarkdown, type Plan } from '../src/core/plan-renderer.js';

const validateScript = path.resolve(import.meta.dirname, '../packs/software-engineering/scripts/validate_tasks.js');

function samplePlan(): Plan {
  return {
    work_id: '0001',
    title: 'pwn-ledger',
    components: [
      { name: 'core-domain', purpose: 'Dominio e validacao dos lancamentos' },
      { name: 'cli', purpose: 'Interface de linha de comando' },
    ],
    global_gates: ['Suite completa verde com bun test'],
    tasks: [
      {
        id: '1.1',
        title: 'Dominio de lancamentos',
        requirement_id: 'FR-001',
        depends_on: [],
        behavior: 'Valida descricao, valor e tipo e calcula o saldo',
        components: ['core-domain'],
        files: ['src/ledger.ts', 'tests/ledger.test.ts'],
        implementation_files: ['src/ledger.ts'],
        test_files: ['tests/ledger.test.ts'],
        red: { command: 'bun test tests/ledger.test.ts', description: 'a assercao de saldo consolidado falha antes da implementacao' },
        implementation_steps: ['Implementar addEntry com validacao', 'Implementar computeBalance'],
        acceptance_criteria: [
          { command: 'bun test tests/ledger.test.ts', description: 'a suite focada do dominio passa' },
          { command: 'bun test', description: 'a suite completa permanece verde' },
        ],
        spec_reference: 'CAP-001',
        contract_id: 'CTR-001',
        complexity: 'medium',
      },
    ],
  };
}

test('renderTasksMarkdown gera markdown v3 valido para o pack', () => {
  const markdown = renderTasksMarkdown(samplePlan());

  assert.match(markdown, /^# Tasks: pwn-ledger/m);
  assert.match(markdown, /\*\*Contract version:\*\* 3/);
  assert.match(markdown, /\*\*Work ID:\*\* 0001/);
  assert.match(markdown, /## Execution contract/);
  assert.match(markdown, /## Global gates/);
  assert.match(markdown, /### \[ \] \[1\.1\] Dominio de lancamentos/);
  assert.match(markdown, /\*\*Requirement:\*\* FR-001/);

  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-render-'));
  try {
    mkdirSync(path.join(dir, '.todo'), { recursive: true });
    const target = path.join(dir, '.todo', '0001-tasks.md');
    writeFileSync(target, markdown, 'utf8');
    const result = spawnSync(process.execPath, [validateScript, target], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('normalizeMarkers ignora estado de checkbox', () => {
  const clean = renderTasksMarkdown(samplePlan());
  const marked = clean
    .replace('### [ ] [1.1]', '### [x] [1.1]')
    .replace('- [ ] Suite completa', '- [x] Suite completa');
  assert.equal(normalizeMarkers(clean), normalizeMarkers(marked));
});

test('planMatchesMarkdown ignora marcadores mas detecta drift estrutural', () => {
  const plan = samplePlan();
  const markdown = renderTasksMarkdown(plan);

  const marked = markdown.replace('### [ ] [1.1]', '### [x] [1.1]');
  assert.equal(planMatchesMarkdown(plan, marked), true, 'marcador de estado não deve contar como drift');

  const drifted = markdown.replace('**Behavior:** Valida descricao', '**Behavior:** Alterado manualmente');
  assert.equal(planMatchesMarkdown(plan, drifted), false, 'mudança estrutural deve ser detectada como drift');
});
