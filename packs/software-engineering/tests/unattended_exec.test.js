import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

const SCRIPT = path.resolve(import.meta.dirname, "../scripts/unattended_exec.js");

function run(args, options = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    timeout: options.timeout ?? 5_000,
  });
}

test("unattended_exec preserves command output and exit code", () => {
  const result = run([
    "--timeout-seconds", "5", "--",
    process.execPath, "-e", "console.log('out'); console.error('err'); process.exit(7)",
  ]);

  assert.equal(result.status, 7);
  assert.match(result.stdout, /out/);
  assert.match(result.stderr, /err/);
});

test("unattended_exec closes child stdin", () => {
  const result = run([
    "--timeout-seconds", "5", "--",
    process.execPath, "-e", "process.stdin.resume(); process.stdin.on('end', () => console.log('stdin-closed'))",
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stdin-closed/);
});

test("unattended_exec applies non-interactive environment", () => {
  const result = run([
    "--timeout-seconds", "5", "--",
    process.execPath, "-e",
    "console.log([process.env.GIT_TERMINAL_PROMPT, process.env.GIT_PAGER, process.env.PAGER].join(','))",
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^0,cat,cat\s*$/);
});

test("unattended_exec terminates a timed-out command", () => {
  const started = Date.now();
  const result = run([
    "--timeout-seconds", "1", "--",
    process.execPath, "-e", "setInterval(() => {}, 1000)",
  ], { timeout: 4_000 });

  assert.equal(result.status, 124, result.stderr);
  assert.match(result.stderr, /TIMEOUT after 1s/);
  assert.ok(Date.now() - started < 3_500, "wrapper did not terminate promptly");
});

test("unattended_exec rejects invalid usage", () => {
  const result = run([]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: unattended_exec\.js/);
});
