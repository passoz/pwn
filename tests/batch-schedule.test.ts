import { describe, expect, test } from 'bun:test';

import { planNextBatch, type Schedule, type SchedulableTask } from '../src/core/batch.js';

function task(id: string, overrides: Partial<SchedulableTask> = {}): SchedulableTask {
  return {
    id,
    title: `task ${id}`,
    dependsOn: [],
    components: [`comp-${id}`],
    writeAllow: [`src/${id}/**`],
    risk: 'L2',
    marker: ' ',
    stage: 'not started',
    crossWorkBlockers: [],
    approved: true,
    ...overrides,
  };
}

const ids = (tasks: SchedulableTask[]): string[] => tasks.map((entry) => entry.id);
const reasonOf = (schedule: Schedule, id: string): string | undefined =>
  schedule.deferred.find((entry) => entry.id === id)?.reason;

describe('planNextBatch', () => {
  test('tasks prontas e disjuntas formam um lote em ordem de plano, limitado por --jobs', () => {
    const schedule = planNextBatch([task('1.1'), task('1.2'), task('1.3')], 2, '0001');
    expect(ids(schedule.batch)).toEqual(['1.1', '1.2']);
    expect(reasonOf(schedule, '1.3')).toMatch(/limite de 2/);
  });

  test('dependência só libera depois de integrada; task integrada não volta ao lote mesmo com evidência STALE', () => {
    const schedule = planNextBatch([
      task('1.1', { stage: 'GREEN' }),
      task('1.2', { dependsOn: ['0001/1.1'] }),
      task('1.3', { dependsOn: ['1.2'] }),
      task('1.4', { dependsOn: ['9.9'] }),
    ], 4, '0001');
    expect(schedule.integrated).toEqual(['1.1']);
    expect(ids(schedule.batch)).toEqual(['1.2']);
    expect(reasonOf(schedule, '1.3')).toMatch(/depende de 1\.2, ainda não integrada/);
    expect(reasonOf(schedule, '1.4')).toMatch(/não existe no plano/);
  });

  test('escopo que pode sobrepor ou componente compartilhado adia a task citando a outra', () => {
    const schedule = planNextBatch([
      task('1.1', { writeAllow: ['src/**'] }),
      task('1.2', { writeAllow: ['src/a.ts'] }),
      task('1.3', { components: ['comp-1.1'], writeAllow: ['lib/**'] }),
      task('1.4', { writeAllow: ['docs/**'] }),
    ], 4, '0001');
    expect(ids(schedule.batch)).toEqual(['1.1', '1.4']);
    expect(reasonOf(schedule, '1.2')).toMatch(/escopo pode sobrepor 1\.1 \(src\/a\.ts × src\/\*\*\)/);
    expect(reasonOf(schedule, '1.3')).toMatch(/componente compartilhado com 1\.1/);
  });

  test('L4 e escopo sobre manifesto de dependências exigem lote próprio', () => {
    const late = planNextBatch([task('1.1'), task('1.2', { risk: 'L4' })], 4, '0001');
    expect(ids(late.batch)).toEqual(['1.1']);
    expect(reasonOf(late, '1.2')).toMatch(/execução isolada \(risco L4/);

    const first = planNextBatch([task('1.1', { writeAllow: ['package.json', 'src/1.1/**'] }), task('1.2')], 4, '0001');
    expect(ids(first.batch)).toEqual(['1.1']);
    expect(reasonOf(first, '1.2')).toMatch(/aguarda: 1\.1 exige execução isolada/);
  });

  test('sem aprovação, já iniciada, bloqueada ou com dependência entre Works não entra no lote', () => {
    const schedule = planNextBatch([
      task('1.1', { approved: false }),
      task('1.2', { stage: 'RED' }),
      task('1.3', { marker: '!' }),
      task('1.4', { crossWorkBlockers: ['0002/1.1'] }),
    ], 4, '0001');
    expect(schedule.batch).toEqual([]);
    expect(reasonOf(schedule, '1.1')).toMatch(/sem aprovação vigente/);
    expect(reasonOf(schedule, '1.2')).toMatch(/já iniciada .*RED/);
    expect(reasonOf(schedule, '1.3')).toMatch(/bloqueada no plano/);
    expect(reasonOf(schedule, '1.4')).toMatch(/entre Works .*0002\/1\.1/);
  });

  test('--tasks restringe os candidatos sem ignorar dependências', () => {
    const schedule = planNextBatch([task('1.1'), task('1.2', { dependsOn: ['1.1'] }), task('1.3')], 4, '0001', new Set(['1.2', '1.3']));
    expect(ids(schedule.batch)).toEqual(['1.3']);
    expect(reasonOf(schedule, '1.2')).toMatch(/depende de 1\.1/);
    expect(reasonOf(schedule, '1.1')).toBeUndefined();
  });
});
