
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { isDirectEntry } from './entry-guard.js';

import { validateTasksDetailed, type TaskAnalysis } from "./validate_tasks.js";
import { listWorks, loadManifest, resolvePlanTarget } from "./work-manifest.js";

const TASK_HEADING = /^### \[([ x!])\] \[(\d+\.\d+)\] (\S.*)$/;

interface FileDigest {
  exists: boolean;
  sha256: string | null;
}

interface EvidenceState {
  stage: string;
  stale: boolean;
}

interface StatusTask {
  id: string;
  marker: string;
  title: string;
  requirement: string;
  dependsOn: string;
  evidence: EvidenceState;
}

type ParsedTask = Omit<StatusTask, "evidence">;

interface GlobalGates {
  state: string;
  detail: string;
}

interface PanoramaCounts {
  total: number;
  completed: number;
  pending: number;
  blocked: number;
  stale: number;
  unverifiedChecked: number;
  verifiedOpen: number;
}

interface Panorama {
  state: string;
  stoppedAt: string;
  counts: PanoramaCounts;
  progress: number;
  compatibilityWarnings: number;
}

interface ArtifactState {
  path: string;
  state: string;
  detail: string;
}

interface ArtifactsStatus {
  systemSpec: ArtifactState;
  prompt: ArtifactState;
  tasks: ArtifactState;
}

interface ProjectStatus {
  artifacts: ArtifactsStatus;
  panorama: Panorama;
  globalGates: GlobalGates;
  tasks: StatusTask[];
  validationErrors: string[];
  validationWarnings: string[];
  validationExceptions: string[];
  contractVersion: number | null;
  contractVersionSource: string;
  migratedFromContractVersion: number | null;
  workId: string | null;
}

interface PlanStatus extends ProjectStatus {
  crossWorkBlockers?: Record<string, string[]>;
}

interface WorkIndexEntry {
  work_id: string;
  state: string;
  plan?: string;
  plan_exists?: boolean;
  error?: string;
  origin?: unknown;
  panorama: Panorama | null;
  globalGates?: GlobalGates;
  contractVersion?: number | null;
}

interface WorkIndexReport {
  works: WorkIndexEntry[];
}

function digest(filePath: string): FileDigest {
  if (!existsSync(filePath) || !statSync(filePath).isFile()) return { exists: false, sha256: null };
  return { exists: true, sha256: createHash("sha256").update(readFileSync(filePath)).digest("hex") };
}

function snapshotChanged(snapshot: unknown): boolean {
  if (!snapshot || typeof snapshot !== "object") return false;
  return Object.entries(snapshot).some(([filePath, expected]) => JSON.stringify(digest(filePath)) !== JSON.stringify(expected));
}

function fieldValue(lines: string[], start: number, end: number, name: string): string {
  const prefix = `**${name}:**`;
  for (const line of lines.slice(start + 1, end)) {
    if (line.startsWith(prefix)) return line.slice(prefix.length).trim().replaceAll("`", "");
  }
  return "—";
}

function parseTasks(text: string): ParsedTask[] {
  const lines = text.split(/\r?\n/);
  const found: Array<{ index: number; match: RegExpMatchArray }> = [];
  lines.forEach((line, index) => {
    const match = line.match(TASK_HEADING);
    if (match) found.push({ index, match });
  });
  return found.map((entry, index) => {
    const end = found[index + 1]?.index ?? lines.length;
    return {
      id: entry.match[2],
      marker: entry.match[1],
      title: entry.match[3],
      requirement: fieldValue(lines, entry.index, end, "Requirement"),
      dependsOn: fieldValue(lines, entry.index, end, "Depends on"),
    };
  });
}

function evidenceFor(taskId: string, todoDirectory: string, workId: string | null): EvidenceState {
  const evidenceRoot = workId ? path.join(todoDirectory, "evidence", workId) : path.join(todoDirectory, "evidence");
  const stateFile = path.join(evidenceRoot, "state", `${taskId}.json`);
  if (!existsSync(stateFile)) return { stage: "not started", stale: false };

  try {
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    if (!state.red_tests) return { stage: "BASELINE", stale: snapshotChanged(state.baseline_implementation) || snapshotChanged(state.baseline_tests) };
    if (!state.green_implementation) return { stage: "RED", stale: snapshotChanged(state.red_tests) };
    const stale = snapshotChanged(state.green_implementation) || snapshotChanged(state.green_tests);
    const verifyLog = path.join(evidenceRoot, `${taskId}-verify.log`);
    if (existsSync(verifyLog) && /VERDICT: PASS\s*$/m.test(readFileSync(verifyLog, "utf8"))) {
      return { stage: "VERIFIED", stale };
    }
    return { stage: "GREEN", stale };
  } catch (error) {
    return { stage: `invalid evidence: ${(error as Error).message}`, stale: true };
  }
}

function walkMarkdown(directory: string): string[] {
  if (!existsSync(directory)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkMarkdown(entryPath));
    else if (entry.isFile() && entry.name.endsWith(".md")) files.push(entryPath);
  }
  return files;
}

function latestPrompt(): string | null {
  const files = walkMarkdown(".prompts");
  if (!files.length) return null;
  return files.sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs || left.localeCompare(right))[0];
}

function firstMatch(text: string, expression: RegExp): string | null {
  return text.match(expression)?.[1] ?? null;
}

function artifactStatus(tasksPath: string, validation: TaskAnalysis): ArtifactsStatus {
  let systemSpec: ArtifactState = { path: ".specs/system.md", state: "absent", detail: "run /make-spec" };
  if (existsSync(systemSpec.path)) {
    const text = readFileSync(systemSpec.path, "utf8");
    const status = firstMatch(text, /^\*\*Status:\*\* (.+)$/m) ?? "status unknown";
    const version = firstMatch(text, /^\*\*Versão:\*\* (.+)$/m) ?? "version unknown";
    systemSpec = { path: systemSpec.path, state: "present", detail: `${status}; version ${version}` };
  }

  const promptPath = latestPrompt();
  const prompt: ArtifactState = promptPath
    ? { path: promptPath, state: "present", detail: firstMatch(readFileSync(promptPath, "utf8"), /^\*\*Status:\*\* (.+)$/m) ?? "status unknown" }
    : { path: ".prompts/", state: "absent", detail: "run /make-prompt" };

  let tasks: ArtifactState = { path: tasksPath, state: "absent", detail: "run /make-todo" };
  if (existsSync(tasksPath)) {
    const version = validation.contractVersion == null ? "unknown" : `v${validation.contractVersion}`;
    if (validation.errors.length) {
      tasks = { path: tasksPath, state: "invalid", detail: `${validation.errors.length} blocking error(s); contract ${version}` };
    } else if (validation.warnings.length || validation.exceptions.length) {
      const details = [];
      if (validation.warnings.length) details.push(`${validation.warnings.length} compatibility warning(s)`);
      if (validation.exceptions.length) details.push(`${validation.exceptions.length} preserved legacy exception(s)`);
      tasks = { path: tasksPath, state: "compatible", detail: `${details.join("; ")}; contract ${version}` };
    } else {
      tasks = { path: tasksPath, state: "valid", detail: `structural validation PASS; contract ${version}` };
    }
  }

  return { systemSpec, prompt, tasks };
}

function globalGates(text: string): GlobalGates {
  const start = text.indexOf("## Global gates");
  if (start === -1) return { state: "MISSING", detail: "missing" };
  const after = text.slice(start + "## Global gates".length);
  const boundaries = [after.indexOf("\n## "), after.indexOf("\n### ")].filter((index) => index !== -1);
  const end = boundaries.length ? Math.min(...boundaries) : after.length;
  const section = after.slice(0, end);
  if (/^\s*N\/A\s*$/m.test(section)) return { state: "N/A", detail: "N/A" };
  const items = [...section.matchAll(/^- \[([ xX!])\]/gm)].map((match) => match[1]);
  if (!items.length) return { state: "UNTRACKED", detail: "declared; no tracked checkbox state" };
  const checked = items.filter((marker) => marker.toLowerCase() === "x").length;
  const blocked = items.filter((marker) => marker === "!").length;
  const detail = `${checked}/${items.length} checked${blocked ? `; ${blocked} blocked` : ""}`;
  if (blocked) return { state: "BLOCKED", detail };
  if (checked === items.length) return { state: "PASS", detail };
  return { state: "PENDING", detail };
}

function panorama(tasks: StatusTask[], validationErrors: string[], validationWarnings: string[], gates: GlobalGates): Panorama {
  const completed = tasks.filter((task) => task.marker === "x").length;
  const pending = tasks.filter((task) => task.marker === " ").length;
  const blocked = tasks.filter((task) => task.marker === "!").length;
  const stale = tasks.filter((task) => task.evidence.stale).length;
  const unverifiedChecked = tasks.filter((task) => task.marker === "x" && task.evidence.stage !== "VERIFIED").length;
  const verifiedOpen = tasks.filter((task) => task.marker !== "x" && task.evidence.stage === "VERIFIED").length;
  const partial = tasks.find((task) => task.marker !== "x" && !["not started", "VERIFIED"].includes(task.evidence.stage));
  const firstBlocked = tasks.find((task) => task.marker === "!");
  const firstPending = tasks.find((task) => task.marker === " ")!;
  const firstOpenIndex = tasks.findIndex((task) => task.marker !== "x");
  const outOfOrder = firstOpenIndex !== -1 ? tasks.slice(firstOpenIndex + 1).find((task) => task.marker === "x") : null;

  let state = "NOT STARTED";
  let stoppedAt = "No task has started";
  if (validationErrors.length) {
    state = "INVALID PLAN";
    stoppedAt = `Structural validation failed with ${validationErrors.length} error(s)`;
  } else if (stale) {
    state = "STALE EVIDENCE";
    const task = tasks.find((entry) => entry.evidence.stale)!;
    stoppedAt = `Evidence no longer matches files at ${task.id}`;
  } else if (firstBlocked) {
    state = "BLOCKED";
    stoppedAt = `Blocked at ${firstBlocked.id}: ${firstBlocked.title}`;
  } else if (unverifiedChecked || verifiedOpen) {
    state = "INCONSISTENT STATE";
    const task = (tasks.find((entry) => entry.marker === "x" && entry.evidence.stage !== "VERIFIED")
      ?? tasks.find((entry) => entry.marker !== "x" && entry.evidence.stage === "VERIFIED"))!;
    stoppedAt = task.marker === "x"
      ? `Task ${task.id} is checked but evidence stage is ${task.evidence.stage}`
      : `Task ${task.id} has VERIFIED evidence but marker is not checked`;
  } else if (partial) {
    state = "IN PROGRESS";
    stoppedAt = `Stopped during ${partial.id} at ${partial.evidence.stage}`;
  } else if (pending && completed) {
    state = outOfOrder ? "INCONSISTENT ORDER" : "IN PROGRESS";
    stoppedAt = outOfOrder
      ? `Task ${outOfOrder.id} is checked after open task ${tasks[firstOpenIndex].id}`
      : `Next task: ${firstPending.id} — ${firstPending.title}`;
  } else if (pending) {
    stoppedAt = `Next task: ${firstPending.id} — ${firstPending.title}`;
  } else if (tasks.length) {
    if (["PASS", "N/A"].includes(gates.state)) {
      state = "COMPLETE";
      stoppedAt = "All tasks are checked and global gates are complete";
    } else {
      state = "TASKS COMPLETE";
      stoppedAt = `All tasks are checked; global gates are ${gates.state}: ${gates.detail}`;
    }
  } else {
    state = "NO TASKS";
    stoppedAt = "No canonical tasks found";
  }

  return {
    state,
    stoppedAt,
    counts: { total: tasks.length, completed, pending, blocked, stale, unverifiedChecked, verifiedOpen },
    progress: tasks.length ? Math.floor((completed / tasks.length) * 100) : 0,
    compatibilityWarnings: validationWarnings.length,
  };
}

export function collectProjectStatus(tasksPath = ".todo/tasks.md"): ProjectStatus {
  const exists = existsSync(tasksPath);
  const text = exists ? readFileSync(tasksPath, "utf8") : "";
  const validation: TaskAnalysis = exists
    ? validateTasksDetailed(tasksPath)
    : { errors: [], warnings: [], exceptions: [], contractVersion: null, contractVersionSource: "absent", migratedFromContractVersion: null, workId: null, tasks: [] };
  const todoDirectory = path.dirname(tasksPath);
  const workId = validation.workId ?? null;
  const tasks: StatusTask[] = parseTasks(text).map((task) => ({ ...task, evidence: evidenceFor(task.id, todoDirectory, workId) }));
  const gates = globalGates(text);
  return {
    artifacts: artifactStatus(tasksPath, validation),
    panorama: panorama(tasks, validation.errors, validation.warnings, gates),
    globalGates: gates,
    tasks,
    validationErrors: validation.errors,
    validationWarnings: validation.warnings,
    validationExceptions: validation.exceptions,
    contractVersion: validation.contractVersion,
    contractVersionSource: validation.contractVersionSource,
    migratedFromContractVersion: validation.migratedFromContractVersion,
    workId,
  };
}

export function collectWorkIndex(root = process.cwd()): WorkIndexReport {
  const works = listWorks(root).map((work) => {
    if (!work.plan_exists) return { ...work, panorama: null };
    const report = collectProjectStatus(path.join(root, work.plan!));
    return {
      ...work,
      panorama: report.panorama,
      globalGates: report.globalGates,
      contractVersion: report.contractVersion,
    };
  });
  return { works };
}

function crossWorkDependencyState(root: string, workId: string, dependsOn: string): string[] {
  if (!dependsOn || dependsOn === "none") return [];
  const blockers: string[] = [];
  for (const raw of dependsOn.split(",").map((entry) => entry.trim()).filter(Boolean)) {
    const match = raw.match(/^(\d{4})\/(\d+\.\d+)$/);
    if (!match || match[1] === workId) continue;
    try {
      const manifest = loadManifest(root, match[1]);
      const report = collectProjectStatus(path.join(root, manifest.artifacts.plan));
      const dependency = report.tasks.find((task) => task.id === match[2]);
      if (!dependency || dependency.marker !== "x" || dependency.evidence.stage !== "VERIFIED" || dependency.evidence.stale) {
        blockers.push(raw);
      }
    } catch {
      blockers.push(raw);
    }
  }
  return blockers;
}

export function collectPlanStatus(target: string, root = process.cwd()): PlanStatus {
  const resolved = resolvePlanTarget(root, target);
  const report: PlanStatus = { ...collectProjectStatus(resolved.absolute), crossWorkBlockers: {} };
  if (resolved.workId) {
    const workId = resolved.workId;
    report.crossWorkBlockers = Object.fromEntries(report.tasks.map((task) => [
      task.id,
      crossWorkDependencyState(root, workId, task.dependsOn),
    ]).filter(([, blockers]) => blockers.length));
  } else {
    report.crossWorkBlockers = {};
  }
  return report;
}

export function renderWorkIndex(report: WorkIndexReport): string {
  const lines = [
    "# Work index",
    "",
    "| Work | State | Plan | Progress | Panorama |",
    "|------|-------|------|----------|----------|",
  ];
  for (const work of report.works) {
    const progress = work.panorama ? `${work.panorama.counts.completed}/${work.panorama.counts.total}` : "—";
    const panorama = work.panorama?.state ?? work.error ?? "no plan";
    lines.push(`| \`${work.work_id}\` | ${work.state} | \`${work.plan ?? "—"}\` | ${progress} | ${escapeCell(panorama)} |`);
  }
  if (!report.works.length) lines.push("| — | — | — | — | No work artifacts found |");
  return `${lines.join("\n")}\n`;
}

function escapeCell(value: unknown): string {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

function markerStatus(marker: string): string {
  if (marker === "x") return "[x] checked";
  if (marker === "!") return "[!] blocked";
  return "[ ] pending";
}

export function renderMarkdown(report: PlanStatus): string {
  const lines = [
    "# Project status",
    "",
    "## Pipeline artifacts",
    "",
    "| Artifact | Path | State | Detail |",
    "|----------|------|-------|--------|",
    `| System spec | \`${escapeCell(report.artifacts.systemSpec.path)}\` | ${report.artifacts.systemSpec.state} | ${escapeCell(report.artifacts.systemSpec.detail)} |`,
    `| Change prompt | \`${escapeCell(report.artifacts.prompt.path)}\` | ${report.artifacts.prompt.state} | ${escapeCell(report.artifacts.prompt.detail)} |`,
    `| Task plan | \`${escapeCell(report.artifacts.tasks.path)}\` | ${report.artifacts.tasks.state} | ${escapeCell(report.artifacts.tasks.detail)} |`,
    "",
    "## Panorama",
    "",
    `- **Project state:** ${report.panorama.state}`,
    `- **Progress:** ${report.panorama.counts.completed}/${report.panorama.counts.total} checked (${report.panorama.progress}%)`,
    `- **Tasks:** ${report.panorama.counts.pending} pending | ${report.panorama.counts.completed} checked | ${report.panorama.counts.blocked} blocked`,
    `- **Consistency:** ${report.panorama.counts.unverifiedChecked} checked without VERIFIED evidence | ${report.panorama.counts.verifiedOpen} VERIFIED but open`,
    `- **Task contract:** ${report.contractVersion == null ? "unknown" : `v${report.contractVersion}`}${report.migratedFromContractVersion == null ? "" : ` migrated from v${report.migratedFromContractVersion}`} | ${report.panorama.compatibilityWarnings} compatibility warning(s) | ${report.validationExceptions.length} preserved legacy exception(s)`,
    `- **Where it stopped:** ${escapeCell(report.panorama.stoppedAt)}`,
    `- **Global gates:** ${report.globalGates.state} — ${escapeCell(report.globalGates.detail)}`,
    "",
    "## Tasks",
    "",
    "| ID | Status | Requirement | Depends on | Evidence | Task |",
    "|----|--------|-------------|------------|----------|------|",
  ];

  if (!report.tasks.length) lines.push("| — | — | — | — | — | No tasks found |\n");
  for (const task of report.tasks) {
    const evidence = `${task.evidence.stage}${task.evidence.stale ? " (STALE)" : ""}`;
    lines.push(`| \`${task.id}\` | ${markerStatus(task.marker)} | \`${escapeCell(task.requirement)}\` | ${escapeCell(task.dependsOn)} | ${escapeCell(evidence)} | ${escapeCell(task.title)} |`);
  }

  if (report.crossWorkBlockers && Object.keys(report.crossWorkBlockers).length) {
    lines.push("", "## Cross-work blockers", "");
    for (const [taskId, blockers] of Object.entries(report.crossWorkBlockers)) {
      lines.push(`- \`${taskId}\`: ${blockers.map((blocker) => `\`${blocker}\``).join(", ")}`);
    }
  }

  if (report.validationErrors.length) {
    lines.push("", "## Structural issues", "");
    for (const error of report.validationErrors) lines.push(`- ${error}`);
  }
  if (report.validationWarnings.length) {
    lines.push("", "## Compatibility warnings", "");
    for (const warning of report.validationWarnings) lines.push(`- ${warning}`);
    lines.push("", "Migration is optional: use the loaded engineering-workflow validator with `--migrate` for preview and `--migrate --write` to apply.");
  }
  if (report.validationExceptions.length) {
    lines.push("", "## Preserved legacy exceptions", "");
    for (const exception of report.validationExceptions) lines.push(`- ${exception}`);
  }
  return `${lines.join("\n")}\n`;
}

export function main(argv = process.argv.slice(2)): number {
  const json = argv.includes("--json");
  const args = argv.filter((argument) => argument !== "--json");
  if (args.length > 1) {
    console.error("usage: project_status.js [NNNN | CANONICAL_PLAN_PATH | legacy] [--json]");
    return 2;
  }
  if (!args.length) {
    const report = collectWorkIndex(process.cwd());
    console.log(json ? JSON.stringify(report, null, 2) : renderWorkIndex(report));
    return 0;
  }
  const report = collectPlanStatus(args[0], process.cwd());
  console.log(json ? JSON.stringify(report, null, 2) : renderMarkdown(report));
  return 0;
}

if (isDirectEntry(import.meta.url)) process.exitCode = main();
