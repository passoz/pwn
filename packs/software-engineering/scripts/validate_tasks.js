#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const LEGACY_TASK_CONTRACT_VERSION = 1;
export const PREVIOUS_TASK_CONTRACT_VERSION = 2;
export const CURRENT_TASK_CONTRACT_VERSION = 3;

const TASK_HEADING = /^### \[([ x!])\] \[(\d+)\.(\d+)\] (\S.*)$/;
const WORK_ID_DECLARATION = /^\*\*Work ID:\*\* (\d{4})$/;
const ANY_TASK_HEADING = /^### /;
const CONTRACT_VERSION = /^\*\*Contract version:\*\* ([1-9]\d*)$/;
const MIGRATED_FROM_CONTRACT = /^\*\*Migrated from task contract:\*\* ([1-9]\d*)$/;
const PLACEHOLDER = /<[^>\n]+>|\b(?:TODO|TBD)\b/gi;
const INLINE_CODE = /`([^`\n]+)`/g;
const AC = /^- \[[ x!]\] `([^`]+)`\s+—\s+\S.*$/;
const RED = /^- `([^`]+)`\s+—\s+\S.*$/;
// Phrases in the RED description that indicate an incidental environment/toolchain failure
// rather than a test assertion, violating BR-001. Applied as errors in v3, warnings in older contracts.
const INCIDENTAL_RED_PATTERNS = [
  /\bausente\b/i,
  /\bnot found\b/i,
  /\bcannot find\b/i,
  /\bno such file\b/i,
  /\bmissing module\b/i,
  /\bno module\b/i,
  /\bno required module\b/i,
  /\bfile not found\b/i,
  /\bmodule not found\b/i,
  /\bsyntax\b/i,
  /\bundefined\b/i,
  /\bunresolved\b/i,
  /\breferenceerror\b/i,
  /\bparse error\b/i,
  /\btype mismatch\b/i,
];
const DOC_EVIDENCE = /^- \*\*Evidence:\*\* `([^`]+)`\s+—\s+\S.*$/;
const DEPENDENCY_INSTALLATION = /^- `([^`]+)`\s+—\s+declared in `([^`]+)`\.\s*$/i;
const PACKAGE_INSTALLATION = /\b(?:npm|pnpm|yarn)\s+(?:install|add)\b|\b(?:pip|pip3)\s+install\b|\bgo\s+get\b|\bcargo\s+add\b|\bapt(?:-get)?\s+install\b|\bbrew\s+install\b/;
const REQUIREMENT_ID = /^(?:FR|QR|EC|SC|SOURCE)-\d{3}$/;
const LOCAL_DEPENDENCY_ID = /^\d+\.\d+$/;
const QUALIFIED_DEPENDENCY_ID = /^(\d{4})\/(\d+\.\d+)$/;
const IMPLEMENTATION_STEP = /^\d+\.\s+\S/;
const LEGACY_ALLOWANCE_KEYS = new Set(["implementation-files", "red-commands", "ac-commands", "implementation-steps"]);
const UNSAFE_COMMANDS = [
  ["sudo", /(^|[;&|]\s*|\s)sudo(?:\s|$)/],
  ["eval", /(^|[;&|]\s*|\s)eval(?:\s|$)/],
  ["download piped to shell", /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b/],
  ["destructive git reset", /\bgit\s+reset\s+--hard\b/],
  ["destructive git clean", /\bgit\s+clean\b/],
  ["destructive removal", /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f|-rf|-fr)\b/i],
  ["migration rollback/reset", /\b(?:migrate\b.*\bdown|db:(?:drop|reset|rollback)|migration\s+(?:down|reset))\b/],
  ["package installation", PACKAGE_INSTALLATION],
  ["deploy/publish", /\b(?:npm|pnpm|yarn|cargo)\s+publish\b|\bmake\s+(?:deploy|publish)\b|\b(?:kubectl|helm|fly|vercel|netlify|gcloud)\b[^\n;&|]*\bdeploy\b/],
  ["environment disclosure", /\b(?:cat\s+\.env\b|printenv\b|env\s*$)/],
];

function section(lines, heading) {
  const start = lines.indexOf(heading);
  if (start === -1) return null;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].startsWith("## ")) {
      end = index;
      break;
    }
  }
  return [start, end];
}

function contractComponents(lines) {
  const bounds = section(lines, "## Execution contract");
  if (!bounds) return new Set();
  const [start, end] = bounds;
  const components = new Set();
  for (const line of lines.slice(start + 1, end)) {
    if (!line.startsWith("|")) continue;
    const cells = line.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim().replace(/^`|`$/g, ""));
    if (!cells.length || cells[0].toLowerCase() === "component" || /^[-:]+$/.test(cells[0])) continue;
    components.add(cells[0]);
  }
  return components;
}

function parseTasks(lines, issue) {
  const found = [];
  lines.forEach((line, index) => {
    if (!ANY_TASK_HEADING.test(line)) return;
    const match = line.match(TASK_HEADING);
    if (!match) {
      issue("error", `line ${index + 1}: malformed task heading: ${line}`);
      return;
    }
    found.push([index, match]);
  });

  return found.map(([start, match], index) => ({
    status: match[1],
    taskId: `${Number(match[2])}.${Number(match[3])}`,
    order: [Number(match[2]), Number(match[3])],
    title: match[4],
    start,
    end: index + 1 < found.length ? found[index + 1][0] : lines.length,
  }));
}

function fieldValue(block, name) {
  const prefixes = [`**${name}:**`, `- **${name}:**`];
  for (const line of block) {
    for (const prefix of prefixes) {
      if (line.startsWith(prefix)) return line.slice(prefix.length).trim();
    }
  }
  return null;
}

function pathValues(value) {
  return new Set(value.split(",").map((part) => part.trim().replace(/^`|`$/g, "")).filter((part) => part && part !== "N/A"));
}

function inlineCommands(line) {
  return [...line.matchAll(INLINE_CODE)].map((match) => match[1]);
}

function commandsIn(lines) {
  const commands = [];
  let inContract = false;
  const commandPrefixes = ["- `", "- [ ] `", "- [x] `", "- [!] `", "- **Playwright:** `", "- **Evidence:** `"];

  lines.forEach((line, zeroBasedIndex) => {
    const lineNumber = zeroBasedIndex + 1;
    if (line === "## Execution contract") {
      inContract = true;
      return;
    }
    if (inContract && line.startsWith("## ")) inContract = false;

    if (inContract && line.startsWith("|")) {
      const cells = line.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim().replace(/^`|`$/g, ""));
      if (cells.length && cells[0].toLowerCase() !== "component" && !/^[-:]+$/.test(cells[0])) {
        for (const cell of cells.slice(2)) if (cell !== "N/A") commands.push([lineNumber, cell]);
      }
      return;
    }

    if (commandPrefixes.some((prefix) => line.startsWith(prefix))) {
      for (const command of inlineCommands(line)) commands.push([lineNumber, command]);
    }
  });
  return commands;
}

function compareOrder(left, right) {
  if (left[0] !== right[0]) return left[0] - right[0];
  return left[1] - right[1];
}

function fieldSection(block, name) {
  const start = block.indexOf(`**${name}:**`);
  if (start === -1) return [];
  let end = block.length;
  for (let index = start + 1; index < block.length; index += 1) {
    if (block[index].startsWith("**")) {
      end = index;
      break;
    }
  }
  return block.slice(start + 1, end);
}

function packageNames(command) {
  const tokens = command.trim().split(/\s+/);
  const manager = tokens[0]?.toLowerCase();
  let packages = [];
  if (["npm", "pnpm", "yarn", "pip", "pip3", "cargo"].includes(manager)) packages = tokens.slice(2);
  else if (manager === "go" && tokens[1]?.toLowerCase() === "get") packages = tokens.slice(2);
  else if (["apt", "apt-get", "brew"].includes(manager)) packages = tokens.slice(2);
  if (packages.some((token) => token === "-g" || token === "--global")) return [];
  return packages
    .filter((token) => token && !token.startsWith("-"))
    .map((token) => {
      if (manager === "go") return token.split("@")[0];
      if (token.startsWith("@")) {
        const separator = token.indexOf("@", 1);
        return separator === -1 ? token : token.slice(0, separator);
      }
      return token.split(/[@=<>~!]/)[0];
    })
    .filter(Boolean);
}

function specDependencies(specText) {
  const dependencies = new Set();
  const declaration = /^\s*(?:-\s*)?\*\*(?:Dependencies|Dependency|Dependências|Dependência):\*\*\s+(.+)$/gim;
  for (const match of specText.matchAll(declaration)) {
    for (const value of match[1].matchAll(/`([^`]+)`/g)) dependencies.add(value[1].toLowerCase());
  }
  return dependencies;
}

function dependencyInstallations(lines, issue, planPath) {
  const allowedLines = new Set();
  const repositoryRoot = planPath ? path.resolve(path.dirname(planPath), "..") : null;
  for (const task of parseTasks(lines, () => {})) {
    if (task.status === "!") continue;
    const block = lines.slice(task.start + 1, task.end);
    const start = block.indexOf("**Dependency installations:**");
    if (start === -1) continue;
    const entries = fieldSection(block, "Dependency installations");
    if (!entries.length) issue("error", `task ${task.taskId}: Dependency installations needs at least one command and governing spec path`);
    for (let index = 0; index < entries.length; index += 1) {
      if (!entries[index].trim()) continue;
      const lineNumber = task.start + 2 + start + 1 + index;
      const match = entries[index].match(DEPENDENCY_INSTALLATION);
      const packages = match ? packageNames(match[1]) : [];
      if (!match || !PACKAGE_INSTALLATION.test(match[1].toLowerCase()) || !packages.length) {
        issue("error", `line ${lineNumber}: invalid dependency installation declaration`);
        continue;
      }
      if (!repositoryRoot) {
        issue("error", `line ${lineNumber}: dependency installation validation requires a plan file path`);
        continue;
      }
      const specPath = path.resolve(repositoryRoot, match[2]);
      if (specPath !== repositoryRoot && !specPath.startsWith(`${repositoryRoot}${path.sep}`)) {
        issue("error", `line ${lineNumber}: governing spec path escapes repository root: ${match[2]}`);
        continue;
      }
      if (!existsSync(specPath)) {
        issue("error", `line ${lineNumber}: governing spec not found: ${match[2]}`);
        continue;
      }
      const declaredDependencies = specDependencies(readFileSync(specPath, "utf8"));
      const missing = packages.filter((name) => !declaredDependencies.has(name.toLowerCase()));
      if (!packages.length || missing.length) {
        for (const name of missing.length ? missing : [match[1]]) {
          issue("error", `line ${lineNumber}: dependency ${name} is not declared in governing spec ${match[2]}`);
        }
        continue;
      }
      allowedLines.add(lineNumber);
    }
  }
  return allowedLines;
}

function parseLegacyAllowances(block, taskId, contractVersion, migratedFrom, issue) {
  const value = fieldValue(block, "Legacy allowances");
  const allowances = new Map();
  if (value === null) return allowances;
  if (contractVersion !== CURRENT_TASK_CONTRACT_VERSION || ![LEGACY_TASK_CONTRACT_VERSION, PREVIOUS_TASK_CONTRACT_VERSION].includes(migratedFrom)) {
    issue("error", `task ${taskId}: Legacy allowances require a v${CURRENT_TASK_CONTRACT_VERSION} plan marked as migrated from v1 or v2`);
    return allowances;
  }

  const entries = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (!entries.length) issue("error", `task ${taskId}: Legacy allowances cannot be empty`);
  for (const entry of entries) {
    const match = entry.match(/^([a-z-]+)=(\d+)$/);
    if (!match || !LEGACY_ALLOWANCE_KEYS.has(match[1])) {
      issue("error", `task ${taskId}: invalid legacy allowance: ${entry}`);
      continue;
    }
    if (allowances.has(match[1])) {
      issue("error", `task ${taskId}: duplicate legacy allowance: ${match[1]}`);
      continue;
    }
    allowances.set(match[1], Number(match[2]));
  }
  return allowances;
}

function detectMigrationSource(lines, contractVersion, issue) {
  const declarations = lines
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => line.startsWith("**Migrated from task contract:**"));
  if (!declarations.length) return null;
  if (declarations.length > 1) issue("error", "duplicate task contract migration source declaration");

  const match = declarations[0].line.match(MIGRATED_FROM_CONTRACT);
  if (!match) {
    issue("error", `line ${declarations[0].index + 1}: invalid task contract migration source declaration`);
    return null;
  }
  const migratedFrom = Number(match[1]);
  if (contractVersion !== CURRENT_TASK_CONTRACT_VERSION || ![LEGACY_TASK_CONTRACT_VERSION, PREVIOUS_TASK_CONTRACT_VERSION].includes(migratedFrom)) {
    issue("error", `unsupported task contract migration source: v${migratedFrom} -> v${contractVersion}`);
  }
  return migratedFrom;
}

function detectContractVersion(lines, issue) {
  const declarations = lines
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => line.startsWith("**Contract version:**"));

  if (!declarations.length) {
    issue("warning", `task contract version is missing; assuming legacy version ${LEGACY_TASK_CONTRACT_VERSION}`);
    return { version: LEGACY_TASK_CONTRACT_VERSION, source: "inferred" };
  }
  if (declarations.length > 1) issue("error", "duplicate task contract version declaration");

  const match = declarations[0].line.match(CONTRACT_VERSION);
  if (!match) {
    issue("error", `line ${declarations[0].index + 1}: invalid task contract version declaration`);
    return { version: CURRENT_TASK_CONTRACT_VERSION, source: "invalid" };
  }

  const version = Number(match[1]);
  if (![LEGACY_TASK_CONTRACT_VERSION, PREVIOUS_TASK_CONTRACT_VERSION, CURRENT_TASK_CONTRACT_VERSION].includes(version)) {
    issue("error", `unsupported task contract version: ${version}; supported versions are ${LEGACY_TASK_CONTRACT_VERSION}, ${PREVIOUS_TASK_CONTRACT_VERSION}, and ${CURRENT_TASK_CONTRACT_VERSION}`);
  } else if (version < CURRENT_TASK_CONTRACT_VERSION) {
    issue("warning", `task contract version ${version} is legacy; migrate to version ${CURRENT_TASK_CONTRACT_VERSION}`);
  }
  return { version, source: "declared" };
}

export function analyzeTasks(text, options = {}) {
  const lines = text.split(/\r?\n/);
  const errors = [];
  const warnings = [];
  const exceptions = [];
  const issue = (severity, message) => (severity === "warning" ? warnings : errors).push(message);
  const contract = detectContractVersion(lines, issue);
  const migratedFrom = detectMigrationSource(lines, contract.version, issue);
  const compatibility = contract.version < CURRENT_TASK_CONTRACT_VERSION;
  const compatibilityIssue = (message) => issue(compatibility ? "warning" : "error", message);

  const workDeclarations = lines.map((line, index) => ({ line, index })).filter(({ line }) => line.startsWith("**Work ID:**"));
  const workMatch = workDeclarations[0]?.line.match(WORK_ID_DECLARATION);
  const declaredWorkId = workMatch?.[1] ?? null;
  if (contract.version === CURRENT_TASK_CONTRACT_VERSION) {
    if (workDeclarations.length !== 1) issue("error", workDeclarations.length ? "duplicate Work ID declaration" : "missing declaration: **Work ID:** NNNN");
    if (!workMatch && workDeclarations.length) issue("error", `line ${workDeclarations[0].index + 1}: invalid Work ID declaration; expected four digits`);
  }

  if (!lines.includes("## Execution contract")) issue("error", "missing section: ## Execution contract");
  if (!lines.includes("## Global gates")) issue("error", "missing section: ## Global gates");

  for (const match of text.matchAll(PLACEHOLDER)) {
    const line = text.slice(0, match.index).split("\n").length;
    issue("error", `line ${line}: unresolved marker: ${match[0]}`);
  }

  const components = contractComponents(lines);
  if (!components.size) issue("error", "execution contract has no components");

  const tasks = parseTasks(lines, issue);
  if (!tasks.length) issue("error", "no canonical task headings found");

  const seen = new Set();
  const primaryRequirements = new Map();
  let previous = null;
  const required = [
    "Requirement",
    "Depends on",
    "Behavior",
    "Components",
    "Files",
    "Implementation files",
    "Test files",
    "RED",
    "Implementation",
    "ACs",
    "Visual",
    "Documentation",
  ];
  const legacyAdvisoryFields = new Set(["Requirement", "Depends on"]);

  for (const task of tasks) {
    if (seen.has(task.taskId)) issue("error", `task ${task.taskId}: duplicate ID`);
    seen.add(task.taskId);
    if (previous && compareOrder(task.order, previous) <= 0) issue("error", `task ${task.taskId}: IDs are not strictly increasing`);
    previous = task.order;

    if (task.status === "!") {
      if (!task.title.toLowerCase().includes("bloquead") || !task.title.includes(":")) {
        issue("error", `task ${task.taskId}: blocked task must include a concrete reason`);
      }
      continue;
    }

    const block = lines.slice(task.start + 1, task.end);
    const allowances = parseLegacyAllowances(block, task.taskId, contract.version, migratedFrom, issue);
    const consumedAllowances = new Set();
    const atomicityIssue = (key, actual, valid, message) => {
      if (valid) return;
      if (compatibility) {
        issue("warning", message);
        return;
      }
      if (allowances.get(key) === actual) {
        consumedAllowances.add(key);
        exceptions.push(`task ${task.taskId}: preserved legacy allowance ${key}=${actual}`);
        return;
      }
      issue("error", message);
    };
    const values = Object.fromEntries(required.map((name) => [name, fieldValue(block, name)]));
    for (const [name, value] of Object.entries(values)) {
      if (value !== null) continue;
      const message = `task ${task.taskId}: missing field **${name}:**`;
      if (compatibility && legacyAdvisoryFields.has(name)) issue("warning", message);
      else issue("error", message);
    }

    if (values.Requirement) {
      const requirement = values.Requirement.replace(/^`|`$/g, "");
      if (!REQUIREMENT_ID.test(requirement)) {
        compatibilityIssue(`task ${task.taskId}: Requirement must contain exactly one FR-*, QR-*, EC-*, SC-* or SOURCE-* ID`);
      } else if (primaryRequirements.has(requirement)) {
        compatibilityIssue(`task ${task.taskId}: primary Requirement ${requirement} already belongs to task ${primaryRequirements.get(requirement)}; split the source requirement or use a distinct edge/success ID`);
      } else {
        primaryRequirements.set(requirement, task.taskId);
      }
    }

    if (values["Depends on"]) {
      const dependencyValue = values["Depends on"].replaceAll("`", "");
      const dependencies = dependencyValue === "none" ? [] : dependencyValue.split(",").map((value) => value.trim()).filter(Boolean);
      if (dependencyValue !== "none" && !dependencies.length) issue("error", `task ${task.taskId}: Depends on must be none, previous local task IDs, or qualified NNNN/task IDs`);
      for (const dependency of dependencies) {
        if (LOCAL_DEPENDENCY_ID.test(dependency)) {
          if (!seen.has(dependency)) issue("error", `task ${task.taskId}: local dependency must reference an earlier task: ${dependency}`);
          if (dependency === task.taskId) issue("error", `task ${task.taskId}: task cannot depend on itself`);
          continue;
        }
        const qualified = dependency.match(QUALIFIED_DEPENDENCY_ID);
        if (!qualified) {
          issue("error", `task ${task.taskId}: invalid dependency ID: ${dependency}`);
          continue;
        }
        if (declaredWorkId && qualified[1] === declaredWorkId) {
          if (!seen.has(qualified[2])) issue("error", `task ${task.taskId}: same-work dependency must reference an earlier task: ${dependency}`);
          if (qualified[2] === task.taskId) issue("error", `task ${task.taskId}: task cannot depend on itself`);
        }
      }
    }

    if (values.Components) {
      for (const name of values.Components.split(",").map((part) => part.trim().replace(/^`|`$/g, ""))) {
        if (!components.has(name)) issue("error", `task ${task.taskId}: unknown component: ${name}`);
      }
    }

    const files = pathValues(values.Files || "");
    const implementationFiles = pathValues(values["Implementation files"] || "");
    const testFiles = pathValues(values["Test files"] || "");
    const overlap = [...implementationFiles].filter((value) => testFiles.has(value)).sort();
    atomicityIssue(
      "implementation-files",
      implementationFiles.size,
      implementationFiles.size <= 3,
      `task ${task.taskId}: atomicity limit exceeded: ${implementationFiles.size} implementation files (max 3)`,
    );
    if (overlap.length) issue("error", `task ${task.taskId}: implementation/test files overlap: ${overlap.join(", ")}`);
    for (const declaredPath of [...new Set([...implementationFiles, ...testFiles])].sort()) {
      if (!files.has(declaredPath)) issue("error", `task ${task.taskId}: declared file missing from Files: ${declaredPath}`);
    }

    const redStart = block.indexOf("**RED:**");
    const acStart = block.indexOf("**ACs:**");
    const visualStart = block.findIndex((line) => line.startsWith("**Visual:**"));
    const documentationStart = block.findIndex((line) => line.startsWith("**Documentation:**"));
    if (redStart !== -1) {
      const redLines = fieldSection(block, "RED").filter((line) => RED.test(line));
      if (!redLines.length) issue("error", `task ${task.taskId}: RED needs a concrete command and expected failure`);
      atomicityIssue(
        "red-commands",
        redLines.length,
        redLines.length <= 1,
        `task ${task.taskId}: atomicity limit exceeded: RED must contain exactly one focused command`,
      );
      for (const redLine of redLines) {
        const description = redLine.replace(/^- `[^`]+`\s*—\s*/, "");
        if (INCIDENTAL_RED_PATTERNS.some((p) => p.test(description))) {
          compatibilityIssue(`task ${task.taskId}: RED description must not describe an incidental environment or toolchain failure as the primary mechanism; describe the assertion that fires instead`);
        }
      }
    }
    if (acStart !== -1) {
      const acLines = fieldSection(block, "ACs").filter((line) => AC.test(line));
      if (!acLines.length) issue("error", `task ${task.taskId}: ACs need at least one concrete command and expected result`);
      atomicityIssue(
        "ac-commands",
        acLines.length,
        acLines.length <= 3,
        `task ${task.taskId}: atomicity limit exceeded: ${acLines.length} ACs (max 3)`,
      );
    }

    const implementationSteps = fieldSection(block, "Implementation").filter((line) => IMPLEMENTATION_STEP.test(line));
    atomicityIssue(
      "implementation-steps",
      implementationSteps.length,
      implementationSteps.length >= 1 && implementationSteps.length <= 2,
      implementationSteps.length
        ? `task ${task.taskId}: atomicity limit exceeded: ${implementationSteps.length} implementation steps (max 2)`
        : `task ${task.taskId}: Implementation needs at least one numbered step`,
    );

    const visual = values.Visual;
    if (visual !== null && visual !== "N/A" && visual !== "REQUIRED") issue("error", `task ${task.taskId}: Visual must be N/A or REQUIRED`);
    if (visual === "REQUIRED" && visualStart !== -1) {
      const visualEnd = documentationStart !== -1 ? documentationStart : block.length;
      const visualBlock = block.slice(visualStart + 1, visualEnd);
      for (const name of ["Route", "Selector", "Playwright", "Expected"]) {
        if (!fieldValue(visualBlock, name)) issue("error", `task ${task.taskId}: visual validation missing ${name}`);
      }
    }

    const documentation = values.Documentation;
    if (documentation !== null && documentation !== "N/A" && documentation !== "REQUIRED") {
      issue("error", `task ${task.taskId}: Documentation must be N/A or REQUIRED`);
    }
    if (documentation === "REQUIRED" && documentationStart !== -1) {
      const documentationBlock = block.slice(documentationStart + 1);
      for (const name of ["Audience", "Files", "Sections", "Sources", "Evidence"]) {
        if (!fieldValue(documentationBlock, name)) issue("error", `task ${task.taskId}: documentation missing ${name}`);
      }
      if (!documentationBlock.some((line) => DOC_EVIDENCE.test(line))) {
        issue("error", `task ${task.taskId}: documentation Evidence needs a concrete command and expected result`);
      }
    }

    for (const [key, expected] of allowances) {
      if (!consumedAllowances.has(key)) {
        issue("error", `task ${task.taskId}: stale legacy allowance ${key}=${expected}; remove or update the task through an explicit replan`);
      }
    }
  }

  const allowedDependencyInstallations = dependencyInstallations(lines, issue, options.planPath);
  for (const [line, command] of commandsIn(lines)) {
    const lowered = command.toLowerCase();
    for (const [label, pattern] of UNSAFE_COMMANDS) {
      if (label === "package installation" && allowedDependencyInstallations.has(line)) continue;
      if (pattern.test(lowered)) issue("error", `line ${line}: unsafe command (${label}): ${command}`);
    }
  }

  if (options.strict && warnings.length) {
    errors.push(...warnings.map((warning) => `compatibility warning treated as error: ${warning}`));
    warnings.length = 0;
  }

  return {
    errors,
    warnings,
    exceptions,
    contractVersion: contract.version,
    contractVersionSource: contract.source,
    migratedFromContractVersion: migratedFrom,
    workId: declaredWorkId,
    tasks: tasks.map((task) => ({
      id: task.taskId,
      status: task.status,
      dependsOn: (fieldValue(lines.slice(task.start + 1, task.end), "Depends on") ?? "none").replaceAll("`", ""),
    })),
  };
}

export function validateTasksDetailed(filePath, options = {}) {
  if (!existsSync(filePath)) {
    return {
      errors: [`file not found: ${filePath}`],
      warnings: [],
      exceptions: [],
      contractVersion: null,
      contractVersionSource: "absent",
      migratedFromContractVersion: null,
      workId: null,
      tasks: [],
    };
  }
  return analyzeTasks(readFileSync(filePath, "utf8"), { ...options, planPath: filePath });
}

export function validateTasks(filePath, options = {}) {
  return validateTasksDetailed(filePath, options).errors;
}

function taskBlocks(lines) {
  const found = [];
  lines.forEach((line, index) => {
    const match = line.match(TASK_HEADING);
    if (match) found.push({ index, match });
  });
  return found.map((entry, index) => ({
    start: entry.index,
    end: found[index + 1]?.index ?? lines.length,
    status: entry.match[1],
    id: `${Number(entry.match[2])}.${Number(entry.match[3])}`,
  }));
}

function firstBodyLine(block) {
  let index = 1;
  while (index < block.length && block[index] === "") index += 1;
  return index;
}

function legacyAtomicityAllowances(block) {
  const allowances = [];
  const implementationFiles = pathValues(fieldValue(block, "Implementation files") || "").size;
  const redCommands = fieldSection(block, "RED").filter((line) => RED.test(line)).length;
  const acCommands = fieldSection(block, "ACs").filter((line) => AC.test(line)).length;
  const implementationSteps = fieldSection(block, "Implementation").filter((line) => IMPLEMENTATION_STEP.test(line)).length;
  if (implementationFiles > 3) allowances.push(`implementation-files=${implementationFiles}`);
  if (redCommands > 1) allowances.push(`red-commands=${redCommands}`);
  if (acCommands > 3) allowances.push(`ac-commands=${acCommands}`);
  if (implementationSteps < 1 || implementationSteps > 2) allowances.push(`implementation-steps=${implementationSteps}`);
  return allowances;
}

function migrateTaskBlock(block, taskIndex, previousTaskId, changes) {
  if (block[0].startsWith("### [!]")) return block;

  const id = block[0].match(TASK_HEADING)?.slice(2, 4).join(".") ?? String(taskIndex + 1);
  if (fieldValue(block, "Requirement") === null) {
    const insertion = firstBodyLine(block);
    block.splice(insertion, 0, `**Requirement:** SOURCE-${String(taskIndex + 1).padStart(3, "0")}`);
    changes.push(`task ${id}: added a SOURCE-* requirement`);
  }

  if (fieldValue(block, "Depends on") === null) {
    const requirementIndex = block.findIndex((line) => line.startsWith("**Requirement:**"));
    block.splice(requirementIndex + 1, 0, `**Depends on:** ${previousTaskId ?? "none"}`);
    changes.push(`task ${id}: made the legacy serial dependency explicit`);
  }

  const allowances = legacyAtomicityAllowances(block);
  if (allowances.length) {
    const dependsOnIndex = block.findIndex((line) => line.startsWith("**Depends on:**"));
    block.splice(dependsOnIndex + 1, 0, `**Legacy allowances:** ${allowances.join(", ")}`);
    changes.push(`task ${id}: recorded exact legacy atomicity allowances (${allowances.join(", ")})`);
  }

  return block;
}

export function migrateTasksContent(text, options = {}) {
  const before = analyzeTasks(text);
  if (before.errors.length) {
    return { content: text, changes: [], errors: before.errors, warnings: before.warnings, fromVersion: before.contractVersion, toVersion: CURRENT_TASK_CONTRACT_VERSION };
  }
  if (before.contractVersion === CURRENT_TASK_CONTRACT_VERSION) {
    return { content: text, changes: [], errors: [], warnings: before.warnings, fromVersion: before.contractVersion, toVersion: CURRENT_TASK_CONTRACT_VERSION };
  }

  let lines = text.split(/\r?\n/);
  const changes = [];
  const workId = options.workId ?? null;
  if (!workId || !/^\d{4}$/.test(workId)) {
    return {
      content: text,
      changes,
      errors: ["migration to task contract v3 requires a four-digit Work ID"],
      warnings: before.warnings,
      fromVersion: before.contractVersion,
      toVersion: CURRENT_TASK_CONTRACT_VERSION,
    };
  }
  const versionIndex = lines.findIndex((line) => line.startsWith("**Contract version:**"));
  if (versionIndex === -1) {
    const titleIndex = lines.findIndex((line) => line.startsWith("# Tasks:"));
    if (titleIndex === -1) {
      return { content: text, changes, errors: ["migration requires a canonical # Tasks: title"], warnings: before.warnings, fromVersion: before.contractVersion, toVersion: CURRENT_TASK_CONTRACT_VERSION };
    }
    lines.splice(
      titleIndex + 1,
      0,
      `**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}`,
      `**Migrated from task contract:** ${before.contractVersion}`,
    );
  } else {
    lines[versionIndex] = `**Contract version:** ${CURRENT_TASK_CONTRACT_VERSION}`;
    lines.splice(versionIndex + 1, 0, `**Migrated from task contract:** ${before.contractVersion}`);
  }
  changes.push(`set task contract version to ${CURRENT_TASK_CONTRACT_VERSION} with migration provenance from v${before.contractVersion}`);
  const existingWorkIndex = lines.findIndex((line) => line.startsWith("**Work ID:**"));
  if (existingWorkIndex === -1) {
    const contractIndex = lines.findIndex((line) => line.startsWith("**Contract version:**"));
    const migrationIndex = lines.findIndex((line) => line.startsWith("**Migrated from task contract:**"));
    lines.splice(Math.max(contractIndex, migrationIndex) + 1, 0, `**Work ID:** ${workId}`);
    changes.push(`assigned Work ID ${workId}`);
  } else if (lines[existingWorkIndex] !== `**Work ID:** ${workId}`) {
    return {
      content: text,
      changes,
      errors: [`migration Work ID conflicts with existing declaration: ${lines[existingWorkIndex]}`],
      warnings: before.warnings,
      fromVersion: before.contractVersion,
      toVersion: CURRENT_TASK_CONTRACT_VERSION,
    };
  }

  const blocks = taskBlocks(lines);
  for (let index = blocks.length - 1; index >= 0; index -= 1) {
    const task = blocks[index];
    const block = lines.slice(task.start, task.end);
    const migrated = migrateTaskBlock(block, index, blocks[index - 1]?.id ?? null, changes);
    lines.splice(task.start, task.end - task.start, ...migrated);
  }

  const content = `${lines.join("\n").replace(/\n+$/, "")}\n`;
  const after = analyzeTasks(content, { strict: true });
  return {
    content,
    changes,
    errors: after.errors,
    warnings: after.warnings,
    fromVersion: before.contractVersion,
    toVersion: CURRENT_TASK_CONTRACT_VERSION,
  };
}

function validatePlanIdentity(filePath, result) {
  if (result.contractVersion !== CURRENT_TASK_CONTRACT_VERSION) return [];
  const match = path.basename(filePath).match(/^(\d{4})-tasks\.md$/);
  if (!match || path.basename(path.dirname(filePath)) !== ".todo") {
    return [`current task contract requires canonical path .todo/NNNN-tasks.md: ${filePath}`];
  }
  if (match[1] !== result.workId) return [`plan filename Work ID ${match[1]} does not match declaration ${result.workId ?? "missing"}`];
  return [];
}

function usage() {
  console.error("usage: validate_tasks.js [--strict] PATH | --migrate --work NNNN [--write] PATH");
}

function printIssues(label, issues) {
  if (!issues.length) return;
  console.log(`${label} (${issues.length}):`);
  for (const issue of issues) console.log(`- ${issue}`);
}

export function main(argv = process.argv.slice(2)) {
  const strict = argv.includes("--strict");
  const migrate = argv.includes("--migrate");
  const write = argv.includes("--write");
  const workIndex = argv.indexOf("--work");
  const workId = workIndex === -1 ? null : argv[workIndex + 1];
  const withoutWork = workIndex === -1 ? [...argv] : argv.filter((_, index) => index !== workIndex && index !== workIndex + 1);
  const unknownOptions = withoutWork.filter((argument) => argument.startsWith("--") && !["--strict", "--migrate", "--write"].includes(argument));
  const args = withoutWork.filter((argument) => !argument.startsWith("--"));
  if (args.length !== 1 || unknownOptions.length || (write && !migrate) || (strict && migrate) || (migrate && !/^\d{4}$/.test(workId ?? ""))) {
    usage();
    return 2;
  }
  const filePath = args[0];

  if (migrate) {
    if (!existsSync(filePath)) {
      console.log(`MIGRATION FAIL: ${filePath}`);
      console.log(`- file not found: ${filePath}`);
      return 1;
    }
    const original = readFileSync(filePath, "utf8");
    const initial = analyzeTasks(original);
    if (initial.contractVersion === CURRENT_TASK_CONTRACT_VERSION) {
      if (initial.errors.length) {
        console.log(`MIGRATION BLOCKED: ${filePath}`);
        printIssues("Blocking issues", initial.errors);
        return 1;
      }
      console.log(`MIGRATION N/A: ${filePath} already uses task contract v${CURRENT_TASK_CONTRACT_VERSION}`);
      return 0;
    }
    const result = migrateTasksContent(original, { workId });
    if (result.errors.length) {
      console.log(`MIGRATION BLOCKED: ${filePath}`);
      printIssues("Blocking issues", result.errors);
      if (result.warnings.length) printIssues("Compatibility warnings", result.warnings);
      return 1;
    }
    console.log(`${write ? "MIGRATED" : "MIGRATION PREVIEW"}: ${filePath} (v${result.fromVersion} -> v${result.toVersion})`);
    printIssues("Changes", result.changes);
    if (write) {
      writeFileSync(filePath, result.content, "utf8");
      console.log(`PASS: ${filePath} is structurally valid under task contract v${CURRENT_TASK_CONTRACT_VERSION}`);
    } else {
      console.log("No file was changed. Migrated content follows:");
      console.log("--- BEGIN MIGRATED FILE ---");
      process.stdout.write(result.content);
      if (!result.content.endsWith("\n")) process.stdout.write("\n");
      console.log("--- END MIGRATED FILE ---");
      console.log("Apply by re-running the loaded validator with --migrate --write for the same file.");
    }
    return 0;
  }

  const result = validateTasksDetailed(filePath, { strict });
  result.errors.push(...validatePlanIdentity(filePath, result));
  if (result.errors.length) {
    console.log(`FAIL: ${filePath}`);
    printIssues("Blocking issues", result.errors);
    return 1;
  }
  const mode = result.contractVersion < CURRENT_TASK_CONTRACT_VERSION ? "legacy compatibility" : "current";
  console.log(`PASS: ${filePath} is executable under task contract v${result.contractVersion} (${mode})`);
  if (result.exceptions.length) printIssues("Preserved legacy exceptions", result.exceptions);
  if (result.warnings.length) {
    printIssues("Compatibility warnings", result.warnings);
    console.log("Migration is optional: preview with --migrate, then apply with --migrate --write.");
  }
  return 0;
}

const isDirect = process.argv[1]
  && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (isDirect) process.exitCode = main();
