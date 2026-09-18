import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  EXIT_INCOMPLETE,
  EXIT_OK,
  EXIT_SUSPENDED,
  EXIT_VIOLATION,
  main,
  readAttestation,
} from '../src/core/task_evidence.js';

/** Executa `main` em um diretório temporário vazio, capturando stderr e restaurando o cwd. */
function runInEmptyDir(argv: string[]): { code: number; stderr: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-audit-exit-'));
  const cwd = process.cwd();
  const originalError = console.error;
  const lines: string[] = [];
  console.error = (...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  };
  try {
    process.chdir(dir);
    return { code: main(argv), stderr: lines.join('\n') };
  } finally {
    console.error = originalError;
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('códigos de saída do audit de evidências', () => {
  test('exporta os códigos estáveis do contrato', () => {
    expect(EXIT_OK).toBe(0);
    expect(EXIT_VIOLATION).toBe(1);
    expect(EXIT_INCOMPLETE).toBe(2);
    expect(EXIT_SUSPENDED).toBe(3);
  });

  test('verify sem baseline devolve EXIT_INCOMPLETE em vez de violação', () => {
    const { code, stderr } = runInEmptyDir(['verify', '--work', '9999', '--task', '9.9']);
    expect(code).toBe(EXIT_INCOMPLETE);
    expect(stderr).toContain('INCOMPLETO: faltam 1 evidência(s):');
    expect(stderr).toContain('baseline not found for task 9.9');
  });

  test('green sem baseline devolve EXIT_INCOMPLETE', () => {
    const { code } = runInEmptyDir(['green', '--work', '9999', '--task', '9.9']);
    expect(code).toBe(EXIT_INCOMPLETE);
  });

  test('red reconhece --expect-literal no parser e segue para a falta de baseline', () => {
    // Se a flag não fosse reconhecida, o parser lançaria "unexpected arguments" e o exit seria 1.
    const { code } = runInEmptyDir([
      'red',
      '--work',
      '9999',
      '--task',
      '9.9',
      '--expect',
      'algum-texto',
      '--expect-literal',
      '--',
      'echo',
      'ok',
    ]);
    expect(code).toBe(EXIT_INCOMPLETE);
  });

  test('check reconhece --expect-literal no parser', () => {
    const { code } = runInEmptyDir([
      'check',
      '--work',
      '9999',
      '--task',
      '9.9',
      '--name',
      'AC-1',
      '--expect',
      'algum-texto',
      '--expect-literal',
      '--',
      'echo',
      'ok',
    ]);
    expect(code).toBe(EXIT_INCOMPLETE);
  });

  test('check sem --expect e com --expect-literal é erro de uso (violação)', () => {
    const { code } = runInEmptyDir([
      'check',
      '--work',
      '9999',
      '--task',
      '9.9',
      '--name',
      'AC-1',
      '--expect-literal',
      '--',
      'echo',
      'ok',
    ]);
    expect(code).toBe(EXIT_VIOLATION);
  });
});

describe('readAttestation', () => {
  function writeAttestation(fixtureName: string, payload: unknown): string {
    const dir = mkdtempSync(path.join(tmpdir(), 'pwn-attestation-'));
    const filePath = path.join(dir, `${fixtureName}.json`);
    writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    return filePath;
  }

  test('aceita atestação v1 legada como compatível', () => {
    const filePath = writeAttestation('v1', {
      version: 1,
      kind: 'task-acceptance-candidate',
      work_id: '0001',
      task_id: '1.1',
      result: 'pass',
    });
    expect(readAttestation(filePath)).toEqual({ version: 1, harness_version: null, compatible: true });
    rmSync(path.dirname(filePath), { recursive: true, force: true });
  });

  test('rejeita v2 sem harness_version', () => {
    const filePath = writeAttestation('v2-sem-versao', {
      version: 2,
      kind: 'task-acceptance-candidate',
      gate_version: '1',
      work_id: '0001',
      task_id: '1.1',
      result: 'pass',
    });
    expect(readAttestation(filePath)).toEqual({ version: 2, harness_version: null, compatible: false });
    rmSync(path.dirname(filePath), { recursive: true, force: true });
  });

  test('aceita v2 com harness_version', () => {
    const filePath = writeAttestation('v2', {
      version: 2,
      kind: 'task-acceptance-candidate',
      harness_version: '0.1.0',
      gate_version: '1',
      work_id: '0001',
      task_id: '1.1',
      result: 'pass',
    });
    expect(readAttestation(filePath)).toEqual({ version: 2, harness_version: '0.1.0', compatible: true });
    rmSync(path.dirname(filePath), { recursive: true, force: true });
  });

  test('devolve null para arquivo ausente e para JSON inválido', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'pwn-attestation-invalida-'));
    const invalid = path.join(dir, 'invalida.json');
    writeFileSync(invalid, '{ nao e json', 'utf8');
    expect(readAttestation(path.join(dir, 'ausente.json'))).toBeNull();
    expect(readAttestation(invalid)).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });
});
