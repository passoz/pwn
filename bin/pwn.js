#!/usr/bin/env node

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = resolve(__dirname, '../src/cli.ts');

import(cliPath).catch((err) => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
