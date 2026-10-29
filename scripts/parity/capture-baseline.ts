import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const outIndex = process.argv.indexOf('--out');
const out = outIndex !== -1 && process.argv[outIndex + 1]
  ? path.resolve(process.argv[outIndex + 1])
  : path.join(root, 'testdata/parity/manifest.json');
const commandIndex = process.argv.indexOf('--command');
const command = commandIndex !== -1
  ? JSON.parse(process.argv[commandIndex + 1]) as string[]
  : ['bun', 'run', 'check'];

const check = spawnSync(command[0], command.slice(1), { cwd: root, encoding: 'utf8', timeout: 300_000 });
const output = `${check.stdout ?? ''}\n${check.stderr ?? ''}`;
const testsPass = Number(output.match(/(\d+)\s+pass/)?.[1] ?? 0);
const testsFail = Number(output.match(/(\d+)\s+fail/)?.[1] ?? 0);
const testFiles = Number(output.match(/Ran \d+ tests across (\d+) files/)?.[1] ?? 0);
const commit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout?.trim() ?? '';

const report = {
  version: 1,
  command: command.join(' '),
  commit,
  exit_code: check.status ?? 1,
  tests_pass: testsPass,
  tests_fail: testsFail,
  test_files: testFiles,
};

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(report));
process.exit(check.status ?? 1);
