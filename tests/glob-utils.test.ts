import assert from 'node:assert/strict';
import test from 'node:test';
import { minimatch } from '../src/core/glob-utils.js';

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
