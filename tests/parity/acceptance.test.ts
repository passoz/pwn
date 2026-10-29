import { describe, test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');

function checkDocument(relative: string): void {
  const document = JSON.parse(fs.readFileSync(path.join(ROOT, relative), 'utf8')) as Record<string, unknown>;
  const value = document.restrictions;
  if (!Array.isArray(value)) throw new Error(`DEC-030: lista restrictions ausente em ${relative}`);
  const entries = value as Array<Record<string, unknown>>;
  const dec030 = entries.find((entry) => entry.decision_id === 'DEC-030');
  const dec005 = entries.find((entry) => entry.decision_id === 'DEC-005');
  if (!dec030) throw new Error(`DEC-030 ausente em ${relative}`);
  if (dec005) throw new Error(`DEC-030 deve substituir DEC-005 em ${relative}`);
  if (typeof dec030.statement !== 'string' || !/\bGo\b/.test(dec030.statement)) {
    throw new Error(`DEC-030 sem a implementação em Go em ${relative}`);
  }
  if (typeof dec030.reference !== 'string' || !/DEC-005/.test(dec030.reference)) {
    throw new Error(`DEC-030 sem a referência a DEC-005 em ${relative}`);
  }
}

describe('DEC-030 (aceitação)', () => {
  test('spec.json substitui DEC-005', () => {
    checkDocument('spec.json');
  });

  test('.specs/system.json substitui DEC-005', () => {
    checkDocument('.specs/system.json');
  });
});
