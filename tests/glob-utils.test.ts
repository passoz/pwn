import assert from 'node:assert/strict';
import test from 'node:test';
import { minimatch } from '../src/core/glob-utils.js';
import { checkFileAgainstScope } from '../src/core/contract-guard.js';

test('minimatch: src/** casa com src/ e subdiretórios', () => {
  assert.equal(minimatch('src/cli.ts', 'src/**'), true);
  assert.equal(minimatch('src/core/sandbox.ts', 'src/**'), true);
  assert.equal(minimatch('src/a/b/c/d.ts', 'src/**'), true);
});

test('minimatch: src/** NÃO casa com src-foo/bar.ts', () => {
  assert.equal(minimatch('src-foo/bar.ts', 'src/**'), false);
  assert.equal(minimatch('notsrc/cli.ts', 'src/**'), false);
});

test('minimatch: src/*.ts casa apenas com arquivos .ts diretos em src/', () => {
  assert.equal(minimatch('src/cli.ts', 'src/*.ts'), true);
  assert.equal(minimatch('src/sandbox.ts', 'src/*.ts'), true);
  assert.equal(minimatch('src/core/sandbox.ts', 'src/*.ts'), false);
  assert.equal(minimatch('src/cli.js', 'src/*.ts'), false);
});

test('minimatch: *.ts casa com .ts no nível raiz', () => {
  assert.equal(minimatch('cli.ts', '*.ts'), true);
  assert.equal(minimatch('src/cli.js', '*.ts'), false);
});

test('minimatch: .git/** bloqueia tudo dentro de .git', () => {
  assert.equal(minimatch('.git/config', '.git/**'), true);
  assert.equal(minimatch('.git/objects/pack/file', '.git/**'), true);
  assert.equal(minimatch('src/.gitignore', '.git/**'), false);
});

test('minimatch: package.json casa com nome literal', () => {
  assert.equal(minimatch('package.json', 'package.json'), true);
  assert.equal(minimatch('src/package.json', 'package.json'), false);
});

test('minimatch: tests/** casa com testes em qualquer profundidade', () => {
  assert.equal(minimatch('tests/cli.test.ts', 'tests/**'), true);
  assert.equal(minimatch('tests/core/sandbox.test.ts', 'tests/**'), true);
  assert.equal(minimatch('src/tests/foo.ts', 'tests/**'), false);
});

test('minimatch: alternação {a,b} casa cada alternativa', () => {
  assert.equal(minimatch('src/a.ts', 'src/{a,b}.ts'), true);
  assert.equal(minimatch('src/b.ts', 'src/{a,b}.ts'), true);
  assert.equal(minimatch('src/c.ts', 'src/{a,b}.ts'), false);
  assert.equal(minimatch('src/a.tsx', 'src/{a,b}.ts'), false);
});

test('minimatch: write_deny com alternação bloqueia de fato (regressão de segurança)', () => {
  // Um `{a,b}` quebrado deixava o deny silenciosamente inerte e a escrita passava.
  const denied = checkFileAgainstScope('secrets/a', ['**'], ['secrets/{a,b}']);
  assert.equal(denied.allowed, false);
  assert.equal(denied.violationType, 'write_deny');

  const other = checkFileAgainstScope('secrets/c', ['**'], ['secrets/{a,b}']);
  assert.equal(other.allowed, true);
});

test('minimatch: alternativas aceitam curingas e aninhamento', () => {
  assert.equal(minimatch('a.ts', '*.{ts,js}'), true);
  assert.equal(minimatch('a.js', '*.{ts,js}'), true);
  assert.equal(minimatch('a.rb', '*.{ts,js}'), false);
  assert.equal(minimatch('a.key', '*.{pem,key}'), true);
  assert.equal(minimatch('b', '{a,{b,c}}'), true);
  assert.equal(minimatch('c', '{a,{b,c}}'), true);
  assert.equal(minimatch('a}', '{a,{b,c}}'), false);
});

test('minimatch: write_deny com curinga dentro da alternação bloqueia de fato', () => {
  // Antes, as alternativas eram tratadas como literais: `{*.key,*.pem}` não casava nada.
  const denied = checkFileAgainstScope('secrets/a.key', ['**'], ['**/*.{key,pem}']);
  assert.equal(denied.allowed, false);
  assert.equal(denied.violationType, 'write_deny');

  const other = checkFileAgainstScope('secrets/a.txt', ['**'], ['**/*.{key,pem}']);
  assert.equal(other.allowed, true);
});

test('minimatch: padrão malformado lança em vez de virar proteção inexistente', () => {
  // Um `write_deny` que não casa nada é pior do que um erro: falha alto.
  assert.throws(() => minimatch('a.pem', '*.{pem'), /glob inválido/);
  assert.throws(() => minimatch('a', '{a,}'), /alternativa vazia/);
  assert.throws(() => minimatch('a', '{}'), /alternativa vazia/);
});

test('minimatch: classe de caracteres é opaca para chaves e vírgulas', () => {
  // `{`, `}` e `,` dentro de `[...]` são literais e não podem fechar o grupo.
  assert.equal(minimatch('a,b', '{a[,]b}'), true);
  assert.equal(minimatch('b', '{a[}],b}'), true);
  assert.equal(minimatch('a}', '{a[}],b}'), true);
  assert.equal(minimatch('a{', '{a[{],b}'), true);
  assert.equal(minimatch('b', '{a[{],b}'), true);
});

test('minimatch: aninhamento absurdo é recusado em vez de custar segundos', () => {
  const deep = '{a,'.repeat(200) + 'b' + '}'.repeat(200);
  const start = Date.now();
  assert.throws(() => minimatch('b', deep), /aninhamento de grupos/);
  assert.ok(Date.now() - start < 1000, 'recusa precisa ser imediata, não O(L²)');
});
