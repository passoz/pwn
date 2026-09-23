import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';

const REPO = path.resolve(import.meta.dirname, '..');

function runPwn(args: string[]) {
  return spawnSync('bun', [path.join(REPO, 'src/cli.ts'), ...args], {
    cwd: REPO,
    encoding: 'utf8',
  });
}

test('pwn --help exibe ajuda principal com status 0', () => {
  const result = runPwn(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /PWN — Policy Work Norms CLI \(pwn\)/);
  assert.match(result.stdout, /COMANDOS DISPONÍVEIS:/);
});

test('pwn --version exibe a versão', () => {
  const result = runPwn(['--version']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /pwn v\d+\.\d+\.\d+/);
});

test('pwn self-check valida documentos normativos do framework com PASS', () => {
  const result = runPwn(['self-check']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /VÁLIDO/);
  assert.match(result.stdout, /4\/4 arquivos válidos/);
});

test('pwn task capsule sem task-id exige task-id e contrato congelado', () => {
  const result = runPwn(['task', 'capsule']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Uso: pwn task capsule/);
});
