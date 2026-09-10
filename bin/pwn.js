#!/usr/bin/env node

if (!process.versions.bun) {
  console.error('pwn requer o runtime Bun (https://bun.sh).');
  console.error(`Runtime detectado: ${process.versions.node ? `node ${process.versions.node}` : 'desconhecido'} — não suportado.`);
  console.error('Execute com: bun bin/pwn.js <comando>');
  process.exit(1);
}

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = resolve(__dirname, '../src/cli.ts');

import(cliPath).catch((err) => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
