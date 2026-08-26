import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const REPO = path.resolve(import.meta.dirname, "..");

function read(relativePath) {
  return readFileSync(path.join(REPO, relativePath), "utf8");
}

test("engineering workflow exposes make-all and its authoritative reference exists", () => {
  const skill = read("skills/engineering-workflow/SKILL.md");
  const workflow = read("skills/engineering-workflow/references/run-all.md");

  assert.match(skill, /`\/make-all` \| `references\/run-all\.md`/);
  assert.match(workflow, /execute-task\.md/);
  assert.match(workflow, /audit-acceptance\.md/);
  assert.match(workflow, /\/make-task/);
  assert.match(workflow, /\/make-ac/);
  assert.match(workflow, /PLANO/);
});

test("make-all is explicitly non-interactive and bounded", () => {
  const workflow = read("skills/engineering-workflow/references/run-all.md");

  assert.match(workflow, /não faça perguntas/);
  assert.match(workflow, /timeout finito/);
  assert.match(workflow, /Até três ciclos por task/);
  assert.match(workflow, /tasks independentes/);
  assert.match(workflow, /encerre somente processos iniciados por este supervisor/);
  assert.match(workflow, /sem pergunta/);
});

test("make-all autonomy preserves dangerous-action boundaries", () => {
  const workflow = read("skills/engineering-workflow/references/run-all.md");

  for (const forbiddenBoundary of ["instalação", "deploy", "publish", "alteração remota", "ação destrutiva", "secrets"]) {
    assert.match(workflow, new RegExp(forbiddenBoundary));
  }
  assert.match(workflow, /não autoriza/);
});

test("Pi adapter delegates make-all to engineering-workflow", () => {
  const adapter = read("adapters/pi/prompts/make-all.md");

  assert.match(adapter, /Load the installed skill `engineering-workflow`/);
  assert.match(adapter, /Pass `\$@` through unchanged/);
  assert.match(adapter, /unattended make-all workflow/);
});
