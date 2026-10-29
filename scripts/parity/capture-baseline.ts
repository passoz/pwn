import fs from 'node:fs';
import path from 'node:path';

const outIndex = process.argv.indexOf('--out');
const out = outIndex !== -1 && process.argv[outIndex + 1]
  ? path.resolve(process.argv[outIndex + 1])
  : path.resolve('testdata/parity/manifest.json');
const report = {
  version: 1,
  command: 'stub',
  commit: '',
  exit_code: 0,
  tests_pass: 0,
  tests_fail: 0,
  test_files: 0,
};
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(report));
