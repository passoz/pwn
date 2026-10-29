import { Ajv } from 'ajv';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const directory = path.join(root, 'testdata/parity/schema');
const corpusPath = path.join(directory, 'corpus.json');

const schema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  required: ['name', 'items', 'mode', 'when', 'ref'],
  properties: {
    name: { type: 'string', minLength: 2, maxLength: 5, pattern: '^[a-z]+$' },
    items: {
      type: 'array',
      minItems: 1,
      maxItems: 2,
      items: { type: 'integer', minimum: 1, maximum: 3, enum: [1, 2, 3] },
    },
    mode: { type: 'string', enum: ['a', 'b'] },
    extra: {
      type: 'object',
      minProperties: 1,
      additionalProperties: false,
      properties: { flag: { type: 'boolean' } },
    },
    when: { type: 'string', format: 'date-time' },
    ref: { $ref: '#/definitions/positive' },
    choice: { oneOf: [{ type: 'string' }, { type: 'number' }] },
  },
  definitions: { positive: { type: 'number', exclusiveMinimum: 0 } },
};

const keywords = [
  'type',
  'properties',
  'required',
  'items',
  'additionalProperties',
  'enum',
  'pattern',
  'minLength',
  'maxLength',
  'minItems',
  'maxItems',
  'minimum',
  'maximum',
  'minProperties',
  'oneOf',
  '$ref',
  'format',
];

const base = {
  name: 'abc',
  items: [1],
  mode: 'a',
  when: '2026-10-28T00:00:00Z',
  ref: 1,
  choice: 'x',
  extra: { flag: true },
};

const cases = [
  { id: 'valid', keyword: 'type', document: base },
  { id: 'invalid-type', keyword: 'type', document: { ...base, name: 1 } },
  { id: 'missing-required', keyword: 'required', document: { items: [1], mode: 'a', when: base.when, ref: 1 } },
  { id: 'invalid-items', keyword: 'items', document: { ...base, items: 'x' } },
  { id: 'extra-property', keyword: 'additionalProperties', document: { ...base, extra: { other: 1 } } },
  { id: 'invalid-enum', keyword: 'enum', document: { ...base, mode: 'c' } },
  { id: 'invalid-pattern', keyword: 'pattern', document: { ...base, name: 'ABC' } },
  { id: 'short-name', keyword: 'minLength', document: { ...base, name: 'a' } },
  { id: 'long-name', keyword: 'maxLength', document: { ...base, name: 'abcdef' } },
  { id: 'empty-items', keyword: 'minItems', document: { ...base, items: [] } },
  { id: 'too-many-items', keyword: 'maxItems', document: { ...base, items: [1, 2, 3] } },
  { id: 'below-minimum', keyword: 'minimum', document: { ...base, items: [0] } },
  { id: 'above-maximum', keyword: 'maximum', document: { ...base, items: [4] } },
  { id: 'empty-extra', keyword: 'minProperties', document: { ...base, extra: {} } },
  { id: 'invalid-one-of', keyword: 'oneOf', document: { ...base, choice: true } },
  { id: 'invalid-ref', keyword: '$ref', document: { ...base, ref: 0 } },
  { id: 'format-not-asserted', keyword: 'format', document: { ...base, when: 'not-a-date' } },
];

const ajv = new Ajv({ allErrors: true, strict: false, formats: { date: true, 'date-time': true } });
const validate = ajv.compile(schema);
const corpus = {
  schema,
  keywords,
  cases: cases.map((entry) => ({ ...entry, valid: Boolean(validate(entry.document)) })),
};

const args = process.argv.slice(2);
if (args.includes('--write')) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, 'utf8');
  console.log(`PASS: conjunto gravado em ${path.relative(root, corpusPath)}`);
  process.exit(0);
}
if (args.includes('--check')) {
  if (!fs.existsSync(corpusPath)) {
    console.error('SCHEMA-CORPUS-FAILED: corpus.json ausente; rode --write');
    process.exit(1);
  }
  const expected = JSON.parse(fs.readFileSync(corpusPath, 'utf8')) as Record<string, unknown>;
  if (JSON.stringify(corpus) !== JSON.stringify(expected)) {
    console.error('SCHEMA-CORPUS-FAILED: o conjunto calculado diverge do gravado');
    process.exit(1);
  }
  console.log('PASS: conjunto de conformidade estável');
  process.exit(0);
}
console.error('uso: bun scripts/parity/schema-corpus.ts --write | --check');
process.exit(2);
