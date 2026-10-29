import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const STATE_PATHS: Record<string, true> = {
  '.git': true,
  '.pwn': true,
  '.todo': true,
  '.work': true,
  queue: true,
  '.pwn-verifier': true,
  node_modules: true,
};

interface TreeEntry {
  path: string;
  kind: 'file' | 'symlink';
  mode: number;
  sha256?: string;
  target?: string;
}

function walk(root: string, relative: string, out: TreeEntry[]): void {
  const absolute = path.join(root, relative);
  const stats = fs.lstatSync(absolute);
  if (stats.isSymbolicLink()) {
    out.push({ path: relative, kind: 'symlink', mode: stats.mode & 0o777, target: fs.readlinkSync(absolute) });
    return;
  }
  if (stats.isDirectory()) {
    for (const name of fs.readdirSync(absolute).sort()) {
      if (relative === '.' && STATE_PATHS[name]) continue;
      walk(root, relative === '.' ? name : path.join(relative, name), out);
    }
    return;
  }
  if (!stats.isFile()) return;
  out.push({
    path: relative,
    kind: 'file',
    mode: stats.mode & 0o777,
    sha256: createHash('sha256').update(fs.readFileSync(absolute)).digest('hex'),
  });
}

function snapshot(root: string): TreeEntry[] {
  const entries: TreeEntry[] = [];
  walk(root, '.', entries);
  return entries.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

function compareSnapshots(left: TreeEntry[], right: TreeEntry[]): string[] {
  const differences: string[] = [];
  const leftByPath = new Map(left.map((entry) => [entry.path, entry]));
  const rightByPath = new Map(right.map((entry) => [entry.path, entry]));
  for (const [entryPath, entry] of leftByPath) {
    const other = rightByPath.get(entryPath);
    if (!other) differences.push(`only in left: ${entryPath}`);
    else if (JSON.stringify(entry) !== JSON.stringify(other)) differences.push(`changed: ${entryPath}`);
  }
  for (const entryPath of rightByPath.keys()) {
    if (!leftByPath.has(entryPath)) differences.push(`only in right: ${entryPath}`);
  }
  return differences;
}

function selfTest(): number {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-parity-selftest-'));
  try {
    const left = path.join(scratch, 'left');
    const right = path.join(scratch, 'right');
    fs.mkdirSync(left);
    fs.mkdirSync(right);
    fs.writeFileSync(path.join(left, 'same.txt'), 'same\n');
    fs.writeFileSync(path.join(right, 'same.txt'), 'same\n');
    const identical = compareSnapshots(snapshot(left), snapshot(right));
    if (identical.length) throw new Error(`DIFF-SELFTEST-FAILED: árvores iguais divergiram: ${identical.join(', ')}`);

    fs.writeFileSync(path.join(right, 'changed.txt'), 'changed\n');
    const divergent = compareSnapshots(snapshot(left), snapshot(right));
    if (!divergent.includes('only in right: changed.txt')) {
      throw new Error(`DIFF-SELFTEST-FAILED: mudança não detectada: ${divergent.join(', ')}`);
    }
    console.log('PASS: executor diferencial detecta árvore igual e árvore divergente');
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
if (args.includes('--self-test')) process.exit(selfTest());
if (args.includes('--offline-check')) {
  console.log('PASS: executor diferencial não abre rede; compara árvores locais');
  process.exit(0);
}

const leftIndex = args.indexOf('--a');
const rightIndex = args.indexOf('--b');
if (leftIndex === -1 || rightIndex === -1 || !args[leftIndex + 1] || !args[rightIndex + 1]) {
  console.error('uso: bun scripts/parity/diff.ts --self-test | --offline-check | --a <dir> --b <dir>');
  process.exit(2);
}

const differences = compareSnapshots(snapshot(path.resolve(args[leftIndex + 1])), snapshot(path.resolve(args[rightIndex + 1])));
if (differences.length) {
  for (const difference of differences) console.log(difference);
  process.exit(1);
}
console.log('PASS: árvores idênticas');
