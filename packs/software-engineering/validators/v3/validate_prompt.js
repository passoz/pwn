#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_SECTIONS = [
  "## Delta da system spec",
  "## Problema e resultado",
  "## Contexto confirmado",
  "## Atores e valor",
  "## Escopo",
  "## Cenários de usuário",
  "## Contrato observável",
  "## Requisitos",
  "## Casos de borda",
  "## Critérios de sucesso",
  "## Premissas",
  "## Componentes afetados",
  "## Rastreabilidade",
];

const REQUIRED_SUBSECTIONS = [
  "### Inclui",
  "### Não inclui",
  "### Funcionais",
  "### Qualidade e restrições",
];

const UNRESOLVED = /<[^>\n]+>|\b(?:TODO|TBD|NEEDS CLARIFICATION)\b/g;
const CHECKBOX = /^\s*- \[[ xX!]\]/m;
const USER_STORY = /^### (US-\d{3}) — .+ \(P[1-3]\)$/gm;
const ACCEPTANCE_SCENARIO = /^\d+\. \*\*Given\*\* .+ \*\*When\*\* .+ \*\*Then\*\* .+\(([^)]+)\)\s*$/gm;
const REQUIREMENT = /^- \*\*((?:FR|QR)-\d{3}):\*\*\s+(.+)$/gm;
const EDGE_CASE = /^- \*\*(EC-\d{3}):\*\*\s+(.+)$/gm;
const SUCCESS_CRITERION = /^- \*\*(SC-\d{3}):\*\*\s+(.+)$/gm;
const ASSUMPTION = /^- \*\*(A-\d{3}):\*\*\s+(.+)$/gm;
const TRACE_ROW = /^\| `((?:FR|QR)-\d{3})` \| ([^|]+) \| ([^|]+) \|\s*$/gm;
const REFERENCE = /\b(?:FR|QR|US|EC|SC|A)-\d{3}\b/g;
const SYSTEM_REFERENCE = /\b(?:ACT|CAP|BR|CON|ENT|SQR|INT|GAP)-\d{3}\b/g;
const VAGUE = /\b(?:rápid[oa]s?|segur[oa]s?|intuitiv[oa]s?|robust[oa]s?|adequad[oa]s?|corretamente|eficiente(?:mente)?)\b/gi;
const STATUS = "**Status:** Pronto para planejamento";

function occurrences(text, value) {
  let count = 0;
  let offset = 0;
  while ((offset = text.indexOf(value, offset)) !== -1) {
    count += 1;
    offset += value.length;
  }
  return count;
}

function lineFor(text, index) {
  return text.slice(0, index).split("\n").length;
}

function matches(text, expression) {
  return [...text.matchAll(expression)];
}

function duplicateIds(entries, errors) {
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry)) errors.push(`duplicate ID: ${entry}`);
    seen.add(entry);
  }
}

function checkSequence(ids, prefix, errors) {
  ids.forEach((id, index) => {
    const expected = `${prefix}-${String(index + 1).padStart(3, "0")}`;
    if (id !== expected) errors.push(`${prefix} IDs must be sequential: expected ${expected}, found ${id}`);
  });
}

function sectionText(text, heading) {
  const start = text.indexOf(heading);
  if (start === -1) return "";
  const contentStart = start + heading.length;
  const next = text.indexOf("\n## ", contentStart);
  return text.slice(contentStart, next === -1 ? text.length : next);
}

function validateReferences(text, knownIds, errors) {
  for (const match of text.matchAll(REFERENCE)) {
    if (!knownIds.has(match[0])) errors.push(`line ${lineFor(text, match.index)}: reference to unknown ID: ${match[0]}`);
  }
}

export function validatePrompt(filePath, systemSpecPath) {
  if (!existsSync(filePath)) return { errors: [`file not found: ${filePath}`], counts: null };

  const text = readFileSync(filePath, "utf8");
  const errors = [];
  let systemText = "";
  if (!systemSpecPath) errors.push("system spec path is required");
  else if (!existsSync(systemSpecPath)) errors.push(`system spec not found: ${systemSpecPath}`);
  else systemText = readFileSync(systemSpecPath, "utf8");

  if (!/^# PROMPT: \S.+$/m.test(text)) errors.push("missing concrete title: # PROMPT: ...");
  if (!text.includes(STATUS)) errors.push(`missing status: ${STATUS}`);
  const workMatch = text.match(/^\*\*Work ID:\*\* (\d{4})$/m);
  if (!workMatch) errors.push("missing or invalid Work ID: **Work ID:** NNNN");
  const canonicalPrompt = path.basename(filePath).match(/^(\d{4})-change\.md$/);
  if (!canonicalPrompt || path.basename(path.dirname(filePath)) !== ".prompts") {
    errors.push(`prompt must use canonical path .prompts/NNNN-change.md: ${filePath}`);
  } else if (workMatch && canonicalPrompt[1] !== workMatch[1]) {
    errors.push(`prompt filename Work ID ${canonicalPrompt[1]} does not match declaration ${workMatch[1]}`);
  }
  if (!/^\*\*Origem:\*\* `\.sources\/\d{4}-.+\.md`$/m.test(text)) errors.push("missing canonical numbered source snapshot reference");
  if (!/^\*\*System spec:\*\* `[^`]+`$/m.test(text)) errors.push("missing system spec reference");
  if (!/^\*\*Baseline:\*\* \S.+$/m.test(text)) errors.push("missing concrete system baseline version and status");

  let lastSectionIndex = -1;
  for (const heading of REQUIRED_SECTIONS) {
    const count = occurrences(text, heading);
    if (count === 0) {
      errors.push(`missing section: ${heading}`);
      continue;
    }
    if (count > 1) errors.push(`duplicate section: ${heading}`);
    const index = text.indexOf(heading);
    if (index < lastSectionIndex) errors.push(`section out of order: ${heading}`);
    lastSectionIndex = index;
    if (!sectionText(text, heading).trim()) errors.push(`empty section: ${heading}`);
  }

  for (const heading of REQUIRED_SUBSECTIONS) {
    const count = occurrences(text, heading);
    if (count === 0) errors.push(`missing subsection: ${heading}`);
    if (count > 1) errors.push(`duplicate subsection: ${heading}`);
  }

  for (const marker of text.matchAll(UNRESOLVED)) {
    errors.push(`line ${lineFor(text, marker.index)}: unresolved marker: ${marker[0]}`);
  }
  if (CHECKBOX.test(text)) errors.push("checkboxes are not allowed in a specification");

  const storyMatches = matches(text, USER_STORY);
  const stories = storyMatches.map((match) => match[1]);
  const acceptanceScenarios = matches(text, ACCEPTANCE_SCENARIO);
  const requirements = matches(text, REQUIREMENT);
  const edgeCases = matches(text, EDGE_CASE);
  const successCriteria = matches(text, SUCCESS_CRITERION);
  const assumptions = matches(text, ASSUMPTION);
  const traceRows = matches(text, TRACE_ROW);

  if (!stories.length) errors.push("at least one canonical user scenario is required: ### US-001 — Title (P1)");
  if (!acceptanceScenarios.length) errors.push("at least one Given/When/Then acceptance scenario with requirement references is required");
  for (let index = 0; index < storyMatches.length; index += 1) {
    const current = storyMatches[index];
    const next = storyMatches[index + 1];
    const sectionEnd = text.indexOf("\n## ", current.index);
    const end = next?.index ?? (sectionEnd === -1 ? text.length : sectionEnd);
    const block = text.slice(current.index, end);
    for (const field of ["Ator", "Valor independente", "Verificação independente"]) {
      if (!new RegExp(`\\*\\*${field}:\\*\\*\\s+\\S`).test(block)) errors.push(`${current[1]} missing concrete field: ${field}`);
    }
    if (!matches(block, ACCEPTANCE_SCENARIO).length) errors.push(`${current[1]} needs at least one canonical Given/When/Then acceptance scenario`);
  }
  if (!requirements.some((match) => match[1].startsWith("FR-"))) errors.push("at least one functional requirement FR-001 is required");
  if (!successCriteria.length) errors.push("at least one success criterion SC-001 is required");
  if (!edgeCases.length) errors.push("at least one edge case EC-001 is required");

  const groups = [
    [stories, "US"],
    [requirements.filter((match) => match[1].startsWith("FR-")).map((match) => match[1]), "FR"],
    [requirements.filter((match) => match[1].startsWith("QR-")).map((match) => match[1]), "QR"],
    [edgeCases.map((match) => match[1]), "EC"],
    [successCriteria.map((match) => match[1]), "SC"],
    [assumptions.map((match) => match[1]), "A"],
  ];
  for (const [ids, prefix] of groups) {
    duplicateIds(ids, errors);
    if (ids.length) checkSequence(ids, prefix, errors);
  }

  const requirementIds = requirements.map((match) => match[1]);
  const allIds = new Set([
    ...stories,
    ...requirementIds,
    ...edgeCases.map((match) => match[1]),
    ...successCriteria.map((match) => match[1]),
    ...assumptions.map((match) => match[1]),
  ]);
  validateReferences(text, allIds, errors);

  if (systemText) {
    const knownSystemIds = new Set([...systemText.matchAll(SYSTEM_REFERENCE)].map((match) => match[0]));
    for (const reference of text.matchAll(SYSTEM_REFERENCE)) {
      if (!knownSystemIds.has(reference[0])) errors.push(`line ${lineFor(text, reference.index)}: system reference not found in baseline: ${reference[0]}`);
    }
  }

  const delta = sectionText(text, "## Delta da system spec");
  for (const field of [
    "Capacidades afetadas",
    "Regras preservadas",
    "Regras alteradas",
    "Contratos afetados",
    "Qualidades, entidades e integrações relacionadas",
    "Gaps tocados",
    "Reconciliação esperada após implementação",
  ]) {
    if (!new RegExp(`^- \\*\\*${field}:\\*\\* \\S`, "m").test(delta)) errors.push(`Delta da system spec missing concrete field: ${field}`);
  }
  if (!/(?:CAP-\d{3}|nenhuma)/i.test(delta)) errors.push("delta must identify affected CAP-* capabilities or explicitly state none");
  if (!/(?:CON-\d{3}|nenhum)/i.test(delta)) errors.push("delta must identify affected CON-* contracts or explicitly state none");

  const acceptanceReferences = new Set();
  for (const scenario of acceptanceScenarios) {
    for (const reference of scenario[1].matchAll(/(?:FR|QR)-\d{3}/g)) acceptanceReferences.add(reference[0]);
  }
  if (!acceptanceReferences.size) errors.push("acceptance scenarios must reference FR-* or QR-* IDs");

  for (const entry of [...edgeCases, ...successCriteria]) {
    if (!/(?:FR|QR)-\d{3}/.test(entry[2])) errors.push(`${entry[1]} must reference at least one FR-* or QR-* ID`);
  }

  const traceByRequirement = new Map();
  for (const row of traceRows) {
    if (traceByRequirement.has(row[1])) errors.push(`duplicate traceability row: ${row[1]}`);
    traceByRequirement.set(row[1], row);
    const coverageIds = [...row[2].matchAll(/(?:US|EC|SC)-\d{3}/g)].map((match) => match[0]);
    if (!coverageIds.length) errors.push(`traceability coverage needs US-*, EC-* or SC-* IDs: ${row[1]}`);
    const evidence = row[3].trim();
    if (evidence.split(/\s+/).length < 4 || /^testes? pass(?:a|am)$/i.test(evidence.replace(/[.!]$/, ""))) {
      errors.push(`traceability evidence is not specific enough: ${row[1]}`);
    }
  }
  for (const id of requirementIds) {
    if (!traceByRequirement.has(id)) errors.push(`requirement missing from traceability table: ${id}`);
  }
  for (const id of traceByRequirement.keys()) {
    if (!requirementIds.includes(id)) errors.push(`traceability row references unknown requirement: ${id}`);
  }

  for (const match of requirements) {
    const words = match[2].trim().split(/\s+/);
    if (words.length < 7) errors.push(`${match[1]} is too short to be reliably testable`);
    for (const vague of match[2].matchAll(VAGUE)) {
      errors.push(`${match[1]} uses vague term without an objective condition: ${vague[0]}`);
    }
  }

  const problem = sectionText(text, "## Problema e resultado");
  if (!/\*\*Problema:\*\*\s+\S/.test(problem)) errors.push("Problema e resultado must contain a concrete **Problema:** field");
  if (!/\*\*Resultado esperado:\*\*\s+\S/.test(problem)) errors.push("Problema e resultado must contain a concrete **Resultado esperado:** field");

  const scope = sectionText(text, "## Escopo");
  for (const heading of ["### Inclui", "### Não inclui"]) {
    const start = scope.indexOf(heading);
    if (start === -1) continue;
    const after = scope.slice(start + heading.length);
    const next = after.indexOf("\n### ");
    const content = after.slice(0, next === -1 ? after.length : next);
    if (!/^\s*- \S/m.test(content)) errors.push(`${heading} must contain at least one concrete list item`);
  }

  const contract = sectionText(text, "## Contrato observável");
  for (const field of ["Entradas", "Saídas e efeitos", "Erros"]) {
    if (!new RegExp(`^- \\*\\*${field}:\\*\\* \\S`, "m").test(contract)) errors.push(`Contrato observável missing concrete field: ${field}`);
  }

  const counts = {
    requirements: requirementIds.length,
    scenarios: stories.length,
    successCriteria: successCriteria.length,
  };
  return { errors, counts };
}

export function main(argv = process.argv.slice(2)) {
  const [filePath, systemSpecPath, ...extra] = argv;
  if (!filePath || !systemSpecPath || extra.length) {
    console.error("Usage: validate_prompt.js <prompt.md> <system-spec.md>");
    return 2;
  }

  const result = validatePrompt(filePath, systemSpecPath);
  if (result.errors.length) {
    console.error(`PROMPT VALIDATION: FAIL (${result.errors.length} error${result.errors.length === 1 ? "" : "s"})`);
    for (const error of result.errors) console.error(`- ${error}`);
    return 1;
  }

  console.log("PROMPT VALIDATION: PASS");
  console.log(`Requirements: ${result.counts.requirements}`);
  console.log(`Scenarios: ${result.counts.scenarios}`);
  console.log(`Success criteria: ${result.counts.successCriteria}`);
  return 0;
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile)) process.exitCode = main();
