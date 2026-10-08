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

test('flags globais do CLI não engolem o comando do operador depois de --', () => {
  // `bun --version` é o comando do OPERADOR: precisa chegar ao audit, não ser
  // interceptado pelo `--version` do próprio pwn. Sem baseline, o audit devolve
  // INCOMPLETO (exit 2); antes da correção, o CLI imprimia a versão do pwn (exit 0).
  const result = runPwn(['work', 'audit', 'check', '--work', '9999', '--task', '9.9', '--name', 'AC-1', '--', 'bun', '--version']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /INCOMPLETO|baseline not found/);
  assert.doesNotMatch(result.stdout, /pwn v\d/);
});
