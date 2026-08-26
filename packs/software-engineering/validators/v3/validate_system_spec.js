#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_SECTIONS = [
  "## Propósito e resultados sistêmicos",
  "## Fronteira do sistema",
  "## Atores e sistemas externos",
  "## Capacidades sistêmicas",
  "## Regras e invariantes globais",
  "## Contratos observáveis",
  "## Modelo conceitual do domínio",
  "## Dados e ciclo de vida",
  "## Segurança, privacidade e autorização",
  "## Qualidades sistêmicas",
  "## Integrações externas",
  "## Restrições e decisões vigentes",
  "## Registro de cobertura e drift",
  "## Rastreabilidade sistêmica",
  "## Política de evolução",
];

const REQUIRED_SUBSECTIONS = ["### Dentro da fronteira", "### Fora da fronteira"];
const UNRESOLVED = /<[^>\n]+>|\b(?:TODO|TBD|NEEDS CLARIFICATION)\b/g;
const CHECKBOX = /^\s*- \[[ xX!]\]/m;
const ID = /\b(?:ACT|CAP|BR|CON|ENT|SQR|INT|GAP)-\d{3}\b/g;
const ACTOR = /^- \*\*(ACT-\d{3}) — .+?:\*\*\s+(.+)$/gm;
const CAPABILITY = /^### (CAP-\d{3}) — .+$/gm;
const RULE = /^- \*\*(BR-\d{3}):\*\*\s+(.+)$/gm;
const CONTRACT = /^### (CON-\d{3}) — .+$/gm;
const ENTITY = /^- \*\*(ENT-\d{3}) — .+?:\*\*\s+(.+)$/gm;
const QUALITY = /^- \*\*(SQR-\d{3}):\*\*\s+(.+)$/gm;
const INTEGRATION = /^- \*\*(INT-\d{3}) — .+?:\*\*\s+(.+)$/gm;
const GAP_ROW = /^\| `(GAP-\d{3})` \| (?:Lacuna|Conflito|Drift) \| ([^|]+) \| ([^|]+) \|\s*$/gm;
const TRACE_ROW = /^\| `(CAP-\d{3})` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|\s*$/gm;
const EVIDENCE_PATH = /`([^`\n]+)`/g;
const STATUS = /^\*\*Status:\*\* (Baseline parcial|Baseline validada)$/m;
const VERSION = /^\*\*Versão:\*\* ([1-9]\d*)$/m;
const RECONCILIATION_DATE = /^\*\*Última reconciliação:\*\* (\d{4}-\d{2}-\d{2})$/m;

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

function sectionText(text, heading) {
  const start = text.indexOf(heading);
  if (start === -1) return "";
  const contentStart = start + heading.length;
  const next = text.indexOf("\n## ", contentStart);
  return text.slice(contentStart, next === -1 ? text.length : next);
}

function duplicateIds(ids, errors) {
  const seen = new Set();
  for (const id of ids) {
    if (seen.has(id)) errors.push(`duplicate ID: ${id}`);
    seen.add(id);
  }
}

function checkSequence(ids, prefix, errors) {
  ids.forEach((id, index) => {
    const expected = `${prefix}-${String(index + 1).padStart(3, "0")}`;
    if (id !== expected) errors.push(`${prefix} IDs must be sequential: expected ${expected}, found ${id}`);
  });
}

function idsFrom(text, prefixes) {
  const pattern = new RegExp(`\\b(?:${prefixes.join("|")})-\\d{3}\\b`, "g");
  return [...text.matchAll(pattern)].map((match) => match[0]);
}

function capabilityBlock(text, capabilityMatches, index) {
  const current = capabilityMatches[index];
  const next = capabilityMatches[index + 1];
  const sectionEnd = text.indexOf("\n## ", current.index);
  const end = next?.index ?? (sectionEnd === -1 ? text.length : sectionEnd);
  return text.slice(current.index, end);
}

function contractBlock(text, contractMatches, index) {
  const current = contractMatches[index];
  const next = contractMatches[index + 1];
  const sectionEnd = text.indexOf("\n## ", current.index);
  const end = next?.index ?? (sectionEnd === -1 ? text.length : sectionEnd);
  return text.slice(current.index, end);
}

function dateIsValid(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

export function validateSystemSpec(filePath) {
  if (!existsSync(filePath)) return { errors: [`file not found: ${filePath}`], counts: null, status: null };

  const text = readFileSync(filePath, "utf8");
  const errors = [];

  if (!/^# SYSTEM SPEC: \S.+$/m.test(text)) errors.push("missing concrete title: # SYSTEM SPEC: ...");
  const statusMatch = text.match(STATUS);
  if (!statusMatch) errors.push("missing or invalid status: Baseline parcial | Baseline validada");
  if (!VERSION.test(text)) errors.push("missing positive integer version: **Versão:** N");
  const dateMatch = text.match(RECONCILIATION_DATE);
  if (!dateMatch || !dateIsValid(dateMatch[1])) errors.push("missing or invalid reconciliation date: **Última reconciliação:** YYYY-MM-DD");
  if (!/^\*\*Escopo da baseline:\*\* \S.+$/m.test(text)) errors.push("missing concrete baseline scope");

  let previousIndex = -1;
  for (const heading of REQUIRED_SECTIONS) {
    const count = occurrences(text, heading);
    if (count === 0) {
      errors.push(`missing section: ${heading}`);
      continue;
    }
    if (count > 1) errors.push(`duplicate section: ${heading}`);
    const index = text.indexOf(heading);
    if (index < previousIndex) errors.push(`section out of order: ${heading}`);
    previousIndex = index;
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
  if (CHECKBOX.test(text)) errors.push("checkboxes are not allowed in a system specification");

  const actors = matches(text, ACTOR);
  const capabilities = matches(text, CAPABILITY);
  const rules = matches(text, RULE);
  const contracts = matches(text, CONTRACT);
  const entities = matches(text, ENTITY);
  const qualities = matches(text, QUALITY);
  const integrations = matches(text, INTEGRATION);
  const gaps = matches(text, GAP_ROW);
  const traceRows = matches(text, TRACE_ROW);

  if (!actors.length) errors.push("at least one canonical actor ACT-001 is required");
  if (!capabilities.length) errors.push("at least one canonical capability CAP-001 is required");
  if (!rules.length) errors.push("at least one canonical rule BR-001 is required");
  if (!contracts.length) errors.push("at least one canonical contract CON-001 is required");

  const groups = [
    [actors.map((match) => match[1]), "ACT"],
    [capabilities.map((match) => match[1]), "CAP"],
    [rules.map((match) => match[1]), "BR"],
    [contracts.map((match) => match[1]), "CON"],
    [entities.map((match) => match[1]), "ENT"],
    [qualities.map((match) => match[1]), "SQR"],
    [integrations.map((match) => match[1]), "INT"],
    [gaps.map((match) => match[1]), "GAP"],
  ];
  for (const [ids, prefix] of groups) {
    duplicateIds(ids, errors);
    if (ids.length) checkSequence(ids, prefix, errors);
  }

  const knownIds = new Set(groups.flatMap(([ids]) => ids));
  for (const reference of text.matchAll(ID)) {
    if (!knownIds.has(reference[0])) errors.push(`line ${lineFor(text, reference.index)}: reference to unknown ID: ${reference[0]}`);
  }

  for (let index = 0; index < capabilities.length; index += 1) {
    const block = capabilityBlock(text, capabilities, index);
    for (const field of ["Valor", "Atores", "Comportamento", "Falhas e limites", "Regras relacionadas", "Contratos relacionados", "Evidência"]) {
      if (!new RegExp(`\\*\\*${field}:\\*\\*\\s+\\S`).test(block)) errors.push(`${capabilities[index][1]} missing concrete field: ${field}`);
    }
    if (!idsFrom(block, ["ACT"]).length) errors.push(`${capabilities[index][1]} must reference at least one ACT-* ID`);
    if (!idsFrom(block, ["BR"]).length) errors.push(`${capabilities[index][1]} must reference at least one BR-* ID`);
    if (!idsFrom(block, ["CON"]).length) errors.push(`${capabilities[index][1]} must reference at least one CON-* ID`);
  }

  for (let index = 0; index < contracts.length; index += 1) {
    const block = contractBlock(text, contracts, index);
    for (const field of ["Consumidores", "Entradas", "Saídas e efeitos", "Erros", "Compatibilidade", "Evidência"]) {
      if (!new RegExp(`\\*\\*${field}:\\*\\*\\s+\\S`).test(block)) errors.push(`${contracts[index][1]} missing concrete field: ${field}`);
    }
  }

  for (const entry of actors) {
    if (!/\*\*Evidência:\*\*\s+\S/.test(entry[2])) errors.push(`${entry[1]} missing evidence`);
  }
  for (const entry of rules) {
    if (!/\*\*Cobertura:\*\*\s+.*CAP-\d{3}/.test(entry[2])) errors.push(`${entry[1]} must reference CAP-* coverage`);
    if (!/\*\*Evidência:\*\*\s+\S/.test(entry[2])) errors.push(`${entry[1]} missing evidence`);
  }
  for (const entry of [...entities, ...qualities, ...integrations]) {
    if (!/\*\*Evidência:\*\*\s+\S/.test(entry[2])) errors.push(`${entry[1]} missing evidence`);
  }

  const traceByCapability = new Map();
  for (const row of traceRows) {
    if (traceByCapability.has(row[1])) errors.push(`duplicate system traceability row: ${row[1]}`);
    traceByCapability.set(row[1], row);
    if (!idsFrom(row[2], ["ACT"]).length) errors.push(`${row[1]} traceability missing ACT-*`);
    if (!idsFrom(row[3], ["BR"]).length) errors.push(`${row[1]} traceability missing BR-*`);
    if (!idsFrom(row[4], ["CON"]).length) errors.push(`${row[1]} traceability missing CON-*`);
  }
  for (const capability of capabilities.map((match) => match[1])) {
    if (!traceByCapability.has(capability)) errors.push(`capability missing from system traceability: ${capability}`);
  }
  for (const capability of traceByCapability.keys()) {
    if (!capabilities.some((match) => match[1] === capability)) errors.push(`traceability row references unknown capability: ${capability}`);
  }

  if (statusMatch?.[1] === "Baseline validada" && gaps.length) {
    errors.push("Baseline validada cannot contain GAP-* entries");
  }

  const coverageSection = sectionText(text, "## Registro de cobertura e drift");
  for (const capability of capabilities.map((match) => match[1])) {
    const pattern = new RegExp(`^\\| \\x60${capability}\\x60 \\| (?:Confirmado|Parcial) \\|`, "m");
    if (!pattern.test(coverageSection)) errors.push(`capability missing from coverage register: ${capability}`);
  }

  const evidenceSections = [
    sectionText(text, "## Atores e sistemas externos"),
    sectionText(text, "## Capacidades sistêmicas"),
    sectionText(text, "## Regras e invariantes globais"),
    sectionText(text, "## Contratos observáveis"),
  ].join("\n");
  for (const evidenceLine of evidenceSections.split("\n").filter((line) => line.includes("**Evidência:**"))) {
    const evidence = evidenceLine.slice(evidenceLine.indexOf("**Evidência:**") + "**Evidência:**".length);
    if (![...evidence.matchAll(EVIDENCE_PATH)].length && !/decisão explícita do usuário/i.test(evidence)) {
      errors.push(`evidence must cite a path or explicit user decision: ${evidenceLine.trim()}`);
    }
  }

  const purpose = sectionText(text, "## Propósito e resultados sistêmicos");
  if (!/\*\*Problema sistêmico:\*\*\s+\S/.test(purpose)) errors.push("purpose must contain a concrete **Problema sistêmico:** field");
  if (!/\*\*Resultado sistêmico:\*\*\s+\S/.test(purpose)) errors.push("purpose must contain a concrete **Resultado sistêmico:** field");

  const boundary = sectionText(text, "## Fronteira do sistema");
  for (const heading of REQUIRED_SUBSECTIONS) {
    const start = boundary.indexOf(heading);
    if (start === -1) continue;
    const after = boundary.slice(start + heading.length);
    const next = after.indexOf("\n### ");
    const content = after.slice(0, next === -1 ? after.length : next);
    if (!/^\s*- \S/m.test(content)) errors.push(`${heading} must contain at least one concrete list item`);
  }

  const counts = {
    capabilities: capabilities.length,
    rules: rules.length,
    contracts: contracts.length,
    gaps: gaps.length,
  };
  return { errors, counts, status: statusMatch?.[1] ?? null };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1) {
    console.error("Usage: validate_system_spec.js <system-spec.md>");
    return 2;
  }

  const result = validateSystemSpec(argv[0]);
  if (result.errors.length) {
    console.error(`SYSTEM SPEC VALIDATION: FAIL (${result.errors.length} error${result.errors.length === 1 ? "" : "s"})`);
    for (const error of result.errors) console.error(`- ${error}`);
    return 1;
  }

  console.log("SYSTEM SPEC VALIDATION: PASS");
  console.log(`Status: ${result.status}`);
  console.log(`Capabilities: ${result.counts.capabilities}`);
  console.log(`Rules: ${result.counts.rules}`);
  console.log(`Contracts: ${result.counts.contracts}`);
  console.log(`Gaps: ${result.counts.gaps}`);
  return 0;
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile)) process.exitCode = main();
