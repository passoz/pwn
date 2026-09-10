
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const WORK_MANIFEST_VERSION = 1;
export const WORK_ID = /^\d{4}$/;
export const NUMBERED_PLAN = /^(\d{4})-tasks\.md$/;

const ARTIFACT_PATTERNS: Array<[string, RegExp]> = [
  [".work", /^(\d{4})\.json$/],
  [".sources", /^(\d{4})-.+\.md$/],
  [".prompts", /^(\d{4})-change\.md$/],
  [".todo", NUMBERED_PLAN],
];

export interface WorkManifestOrigin {
  type: string;
  reference: string | null;
}

export interface WorkManifestArtifacts {
  manifest: string;
  source: string;
  prompt: string;
  plan: string;
  evidence: string;
  diagnostics: string;
  screenshots: string;
  attestations: string;
}

export interface WorkManifest {
  version: number;
  work_id: string;
  state: string;
  origin: WorkManifestOrigin;
  artifacts: WorkManifestArtifacts;
  created_at: string;
  updated_at: string;
}

export interface ReserveWorkOptions {
  workId?: string | null;
  originType?: string;
  originReference?: string | null;
  sourcePath?: string | null;
}

export interface WorkSummary {
  work_id: string;
  state: string;
  origin?: WorkManifestOrigin;
  plan?: string;
  plan_exists?: boolean;
  error?: string;
}

export interface MigrationMove {
  from: string;
  to: string;
}

export interface PlanTarget {
  root: string;
  target: string | undefined;
  workId: string | undefined;
  legacy: boolean;
  relative: string;
  absolute: string;
}

function assertRepositoryPath(root: string, candidate: string): string {
  const absoluteRoot = path.resolve(root);
  const absolute = path.resolve(root, candidate);
  if (absolute !== absoluteRoot && !absolute.startsWith(`${absoluteRoot}${path.sep}`)) {
    throw new Error(`path escapes repository root: ${candidate}`);
  }
  return absolute;
}

function listIds(root: string): string[] {
  const ids = new Set<string>();
  for (const [directory, expression] of ARTIFACT_PATTERNS) {
    const absoluteDirectory = path.join(root, directory);
    if (!existsSync(absoluteDirectory)) continue;
    for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const match = entry.name.match(expression);
      if (match) ids.add(match[1]);
    }
  }
  return [...ids].sort();
}

function nextId(root: string): string {
  const ids = listIds(root);
  const highest = ids.length ? Number(ids.at(-1)) : 0;
  if (highest >= 9999) throw new Error("work ID space exhausted at 9999");
  return String(highest + 1).padStart(4, "0");
}

export function manifestPath(workId: string): string {
  if (!WORK_ID.test(workId)) throw new Error(`invalid Work ID: ${workId}; expected four digits`);
  return path.join(".work", `${workId}.json`);
}

export function canonicalArtifacts(workId: string, sourceKind = "request"): WorkManifestArtifacts {
  if (!WORK_ID.test(workId)) throw new Error(`invalid Work ID: ${workId}; expected four digits`);
  const safeKind = String(sourceKind).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "") || "request";
  return {
    manifest: manifestPath(workId),
    source: path.join(".sources", `${workId}-${safeKind}.md`),
    prompt: path.join(".prompts", `${workId}-change.md`),
    plan: path.join(".todo", `${workId}-tasks.md`),
    evidence: path.join(".todo", "evidence", workId),
    diagnostics: path.join(".todo", "diagnostics", workId),
    screenshots: path.join(".todo", "screenshots", workId),
    attestations: path.join(".todo", "attestations", workId),
  };
}

function orderedManifest(manifest: WorkManifest): WorkManifest {
  return {
    version: manifest.version,
    work_id: manifest.work_id,
    state: manifest.state,
    origin: manifest.origin,
    artifacts: manifest.artifacts,
    created_at: manifest.created_at,
    updated_at: manifest.updated_at,
  };
}

export function loadManifest(root: string, workId: string): WorkManifest {
  const relative = manifestPath(workId);
  const absolute = assertRepositoryPath(root, relative);
  if (!existsSync(absolute)) throw new Error(`work manifest not found: ${relative}`);
  const manifest = JSON.parse(readFileSync(absolute, "utf8")) as WorkManifest;
  if (manifest.version !== WORK_MANIFEST_VERSION) throw new Error(`unsupported work manifest version: ${manifest.version}`);
  if (manifest.work_id !== workId) throw new Error(`manifest Work ID mismatch: expected ${workId}, found ${manifest.work_id}`);
  return manifest;
}

export function reserveWork(root: string = process.cwd(), options: ReserveWorkOptions = {}): WorkManifest {
  const repositoryRoot = path.resolve(root);
  const requested = options.workId;
  if (requested && !WORK_ID.test(requested)) throw new Error(`invalid Work ID: ${requested}; expected four digits`);

  for (;;) {
    const workId = requested ?? nextId(repositoryRoot);
    const artifacts = canonicalArtifacts(workId, options.originType ?? "request");
    const absoluteManifest = assertRepositoryPath(repositoryRoot, artifacts.manifest);
    mkdirSync(path.dirname(absoluteManifest), { recursive: true });

    let descriptor: number;
    try {
      descriptor = openSync(absoluteManifest, "wx", 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (!requested && code === "EEXIST") continue;
      if (code === "EEXIST") throw new Error(`Work ID already reserved: ${workId}`);
      throw error;
    }

    const now = new Date().toISOString();
    const manifest = orderedManifest({
      version: WORK_MANIFEST_VERSION,
      work_id: workId,
      state: "source_pending",
      origin: {
        type: options.originType ?? "local",
        reference: options.originReference ?? null,
      },
      artifacts,
      created_at: now,
      updated_at: now,
    });
    try {
      writeFileSync(descriptor, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    } finally {
      closeSync(descriptor);
    }

    if (options.sourcePath) {
      const sourceAbsolute = assertRepositoryPath(repositoryRoot, options.sourcePath);
      if (!existsSync(sourceAbsolute) || !statSync(sourceAbsolute).isFile()) {
        throw new Error(`source file not found: ${options.sourcePath}`);
      }
      const snapshotAbsolute = assertRepositoryPath(repositoryRoot, artifacts.source);
      mkdirSync(path.dirname(snapshotAbsolute), { recursive: true });
      if (existsSync(snapshotAbsolute)) throw new Error(`source snapshot already exists: ${artifacts.source}`);
      copyFileSync(sourceAbsolute, snapshotAbsolute, 0);
      updateManifest(repositoryRoot, workId, { state: "prompt_pending" });
    }
    return loadManifest(repositoryRoot, workId);
  }
}

export function updateManifest(root: string, workId: string, changes: Partial<WorkManifest>): WorkManifest {
  const repositoryRoot = path.resolve(root);
  const manifest = loadManifest(repositoryRoot, workId);
  const allowedStates = new Set([
    "source_pending",
    "prompt_pending",
    "plan_pending",
    "planned",
    "active",
    "blocked",
    "completed",
    "abandoned",
  ]);
  if (changes.state && !allowedStates.has(changes.state)) throw new Error(`invalid work state: ${changes.state}`);
  const updated = orderedManifest({ ...manifest, ...changes, updated_at: new Date().toISOString() });
  const absolute = assertRepositoryPath(repositoryRoot, manifestPath(workId));
  writeFileSync(absolute, `${JSON.stringify(updated, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return updated;
}

export function resolvePlanTarget(root: string = process.cwd(), target?: string): PlanTarget {
  const repositoryRoot = path.resolve(root);
  if (!target) throw new Error("explicit plan target required; use NNNN, a canonical plan path, or legacy");
  let relative: string;
  let workId: string | undefined;
  let legacy = false;

  if (target === "legacy") {
    relative = path.join(".todo", "tasks.md");
    legacy = true;
  } else if (WORK_ID.test(target)) {
    workId = target;
    relative = path.join(".todo", `${target}-tasks.md`);
  } else if (/^\d+$/.test(target)) {
    throw new Error(`invalid Work ID: ${target}; preserve four digits`);
  } else {
    const absoluteTarget = assertRepositoryPath(repositoryRoot, target);
    relative = path.relative(repositoryRoot, absoluteTarget);
    const match = path.basename(relative).match(NUMBERED_PLAN);
    if (match && path.dirname(relative) === ".todo") workId = match[1];
    else if (relative === path.join(".todo", "tasks.md")) legacy = true;
    else throw new Error(`not a canonical plan target: ${target}`);
  }

  const absolute = assertRepositoryPath(repositoryRoot, relative);
  if (!existsSync(absolute)) throw new Error(`plan not found: ${relative}`);
  if (!legacy) {
    if (!workId) throw new Error(`canonical plan target requires a Work ID: ${target}`);
    const manifest = loadManifest(repositoryRoot, workId);
    if (manifest.artifacts.plan !== relative) {
      throw new Error(`manifest plan mismatch for Work ID ${workId}: ${manifest.artifacts.plan}`);
    }
  }
  return { root: repositoryRoot, target, workId, legacy, relative, absolute };
}

export function listWorks(root: string = process.cwd()): WorkSummary[] {
  const repositoryRoot = path.resolve(root);
  const works: WorkSummary[] = listIds(repositoryRoot).map((workId) => {
    const manifestFile = path.join(repositoryRoot, manifestPath(workId));
    if (!existsSync(manifestFile)) {
      return { work_id: workId, state: "invalid", error: `missing ${manifestPath(workId)}` };
    }
    try {
      const manifest = loadManifest(repositoryRoot, workId);
      return {
        work_id: workId,
        state: manifest.state,
        origin: manifest.origin,
        plan: manifest.artifacts.plan,
        plan_exists: existsSync(path.join(repositoryRoot, manifest.artifacts.plan)),
      };
    } catch (error) {
      return { work_id: workId, state: "invalid", error: (error as Error).message };
    }
  });
  if (existsSync(path.join(repositoryRoot, ".todo", "tasks.md"))) {
    works.push({ work_id: "legacy", state: "legacy", plan: ".todo/tasks.md", plan_exists: true });
  }
  return works;
}

function migrationMoves(root: string, workId: string): MigrationMove[] {
  const moves: MigrationMove[] = [];
  if (existsSync(path.join(root, ".todo/tasks.md"))) {
    moves.push({ from: ".todo/tasks.md", to: `.todo/${workId}-tasks.md` });
  }
  for (const directory of ["evidence", "diagnostics", "screenshots"]) {
    const base = path.join(root, ".todo", directory);
    if (!existsSync(base)) continue;
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (entry.name === workId || /^\d{4}$/.test(entry.name)) continue;
      moves.push({
        from: path.join(".todo", directory, entry.name),
        to: path.join(".todo", directory, workId, entry.name),
      });
    }
  }
  for (const move of moves) {
    if (existsSync(path.join(root, move.to))) throw new Error(`legacy migration destination already exists: ${move.to}`);
  }
  return moves;
}

export function previewLegacyMigration(root: string = process.cwd()): { work_id: string; moves: MigrationMove[] } {
  const repositoryRoot = path.resolve(root);
  if (!existsSync(path.join(repositoryRoot, ".todo", "tasks.md"))) throw new Error("legacy plan not found: .todo/tasks.md");
  const workId = nextId(repositoryRoot);
  return { work_id: workId, moves: migrationMoves(repositoryRoot, workId) };
}

export function applyLegacyMigration(root: string = process.cwd()): { work_id: string; moves: MigrationMove[]; manifest: string } {
  const repositoryRoot = path.resolve(root);
  const preview = previewLegacyMigration(repositoryRoot);
  const manifest = reserveWork(repositoryRoot, {
    workId: preview.work_id,
    originType: "legacy-migration",
    originReference: ".todo/tasks.md",
  });
  for (const move of preview.moves) {
    const destination = path.join(repositoryRoot, move.to);
    mkdirSync(path.dirname(destination), { recursive: true });
    renameSync(path.join(repositoryRoot, move.from), destination);
  }
  updateManifest(repositoryRoot, preview.work_id, { state: "planned" });
  return { ...preview, manifest: manifestPath(preview.work_id) };
}

function takeOption(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1) return null;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`missing value for ${name}`);
  args.splice(index, 2);
  return value;
}

function usage(): void {
  console.error("usage: work_artifacts.js reserve [--work NNNN] [--origin-type TYPE] [--origin-reference REF] [--source PATH]");
  console.error("       work_artifacts.js resolve TARGET");
  console.error("       work_artifacts.js list [--json]");
  console.error("       work_artifacts.js migrate-legacy [--write]");
}

export function main(argv: string[] = process.argv.slice(2)): number {
  try {
    const [action, ...tokens] = argv;
    if (action === "reserve") {
      const workId = takeOption(tokens, "--work");
      const originType = takeOption(tokens, "--origin-type") ?? "local";
      const originReference = takeOption(tokens, "--origin-reference");
      const sourcePath = takeOption(tokens, "--source");
      if (tokens.length) throw new Error(`unexpected arguments: ${tokens.join(" ")}`);
      const result = reserveWork(process.cwd(), { workId, originType, originReference, sourcePath });
      console.log(JSON.stringify(result, null, 2));
      return 0;
    }
    if (action === "resolve") {
      if (tokens.length !== 1) throw new Error("resolve requires exactly one target");
      console.log(JSON.stringify(resolvePlanTarget(process.cwd(), tokens[0]), null, 2));
      return 0;
    }
    if (action === "list") {
      const json = tokens.includes("--json");
      const unknown = tokens.filter((token) => token !== "--json");
      if (unknown.length) throw new Error(`unexpected arguments: ${unknown.join(" ")}`);
      const works = listWorks(process.cwd());
      if (json) console.log(JSON.stringify({ works }, null, 2));
      else for (const work of works) console.log(`${work.work_id}\t${work.state}\t${work.plan ?? work.error}`);
      return 0;
    }
    if (action === "migrate-legacy") {
      const write = tokens.includes("--write");
      const unknown = tokens.filter((token) => token !== "--write");
      if (unknown.length) throw new Error(`unexpected arguments: ${unknown.join(" ")}`);
      const result = write ? applyLegacyMigration(process.cwd()) : previewLegacyMigration(process.cwd());
      console.log(`${write ? "LEGACY MIGRATION APPLIED" : "LEGACY MIGRATION PREVIEW"}: Work ID ${result.work_id}`);
      for (const move of result.moves) console.log(`- ${move.from} -> ${move.to}`);
      if (!write) console.log("No file was changed. Re-run with --write to apply this exact class of migration.");
      return 0;
    }
    usage();
    return 2;
  } catch (error) {
    console.error(`FAIL: ${(error as Error).message}`);
    return 1;
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(currentFile)) process.exitCode = main();
