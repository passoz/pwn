import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readlinkSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const REPO = path.resolve(import.meta.dirname, "..");

function run(script, home, extraEnv = {}) {
  return spawnSync(path.join(REPO, script), [], {
    cwd: REPO,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: home,
      PI_AGENT_DIR: path.join(home, "pi"),
      AGENT_SKILLS_DIR: path.join(home, "shared", "skills"),
      ...extraEnv,
    },
  });
}

function fixture() {
  return mkdtempSync(path.join(tmpdir(), "ai-skills-install-"));
}

test("installs skills only in the shared directory and Pi adapters separately", () => {
  const home = fixture();
  const result = run("install.sh", home);
  assert.equal(result.status, 0, result.stderr || result.stdout || "install.sh failed");

  const shared = path.join(home, "shared", "skills", "engineering-workflow");
  const piSkill = path.join(home, "pi", "skills", "engineering-workflow");
  const piAdapter = path.join(home, "pi", "prompts", "make-todo.md");
  const makeAllAdapter = path.join(home, "pi", "prompts", "make-all.md");
  assert.equal(lstatSync(shared).isSymbolicLink(), true);
  assert.equal(path.resolve(path.dirname(shared), readlinkSync(shared)), path.join(REPO, "skills", "engineering-workflow"));
  assert.equal(existsSync(piSkill), false);
  assert.equal(lstatSync(piAdapter).isSymbolicLink(), true);
  assert.equal(lstatSync(makeAllAdapter).isSymbolicLink(), true);
});

test("preserves an existing shared skill from another source", () => {
  const home = fixture();
  const existing = path.join(home, "shared", "skills", "engineering-workflow");
  mkdirSync(existing, { recursive: true });
  writeFileSync(path.join(existing, "SKILL.md"), "existing\n", "utf8");

  const result = run("install.sh", home);
  assert.equal(result.status, 0, result.stderr || result.stdout || "install.sh failed");
  assert.equal(lstatSync(existing).isDirectory(), true);
  assert.equal(existsSync(path.join(existing, "SKILL.md")), true);
  assert.match(result.stdout, /existing shared skill preserved/);
});

test("migrates a legacy Pi-local link owned by this repository", () => {
  const home = fixture();
  const legacyDirectory = path.join(home, "pi", "skills");
  mkdirSync(legacyDirectory, { recursive: true });
  const legacy = path.join(legacyDirectory, "engineering-workflow");
  symlinkSync(path.join(REPO, "skills", "engineering-workflow"), legacy);

  const result = run("install.sh", home);
  assert.equal(result.status, 0, result.stderr || result.stdout || "install.sh failed");
  assert.equal(existsSync(legacy), false);
  assert.equal(lstatSync(path.join(home, "shared", "skills", "engineering-workflow")).isSymbolicLink(), true);
});

test("uninstall removes only links owned by this repository", () => {
  const home = fixture();
  let result = run("install.sh", home);
  assert.equal(result.status, 0, result.stderr || result.stdout || "install.sh failed");

  const foreign = path.join(home, "shared", "skills", "foreign-skill");
  mkdirSync(foreign, { recursive: true });
  writeFileSync(path.join(foreign, "SKILL.md"), "foreign\n", "utf8");

  result = run("uninstall.sh", home);
  assert.equal(result.status, 0, result.stderr || result.stdout || "uninstall.sh failed");
  assert.equal(existsSync(path.join(home, "shared", "skills", "engineering-workflow")), false);
  assert.equal(existsSync(path.join(home, "pi", "prompts", "make-todo.md")), false);
  assert.equal(existsSync(path.join(home, "pi", "prompts", "make-all.md")), false);
  assert.equal(existsSync(foreign), true);
});
