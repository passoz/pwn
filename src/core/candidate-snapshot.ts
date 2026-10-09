import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  symlinkSync,
} from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

/**
 * Captura determinística da entrega candidata.
 *
 * O recibo de aceitação precisa identificar EXATAMENTE o que foi avaliado. Um
 * digest por commit ou pelos arquivos listados na task deixa de fora módulos
 * indiretos, configuração de runtime, lockfile e assets — qualquer um deles pode
 * mudar o comportamento observado sem alterar os arquivos declarados.
 */

/** Estado do próprio harness: não é entrada executável e não entra no digest. */
export const HARNESS_STATE_PATHS = [".git", ".pwn", ".todo", ".work", "queue", ".pwn-verifier"];

/** Dependências: materializadas à parte e resumidas em `dependencyDigest`. */
export const DEPENDENCY_PATHS = ["node_modules"];

export interface SnapshotEntry {
  path: string;
  kind: "file" | "symlink";
  mode: number;
  sha256?: string;
  target?: string;
}

export interface CandidateSnapshot {
  version: 1;
  files: SnapshotEntry[];
  digest: string;
}

export interface DependencyDigest {
  files: Array<{ path: string; sha256: string | null }>;
  digest: string;
}

const DEPENDENCY_MANIFESTS = ["package.json", "bun.lock", "bun.lockb", "bunfig.toml", "tsconfig.json"];

function excludedRoot(target: string): boolean {
  return [...HARNESS_STATE_PATHS, ...DEPENDENCY_PATHS].includes(target);
}

function walk(rootDir: string, relative: string, out: SnapshotEntry[], budget: { count: number }): void {
  if (budget.count > 200_000) throw new Error("snapshot excedeu o limite de entradas (200000)");
  const absolute = path.join(rootDir, relative);
  const stats = lstatSync(absolute);
  if (stats.isSymbolicLink()) {
    out.push({ path: relative, kind: "symlink", mode: stats.mode & 0o777, target: readlinkSync(absolute) });
    return;
  }
  if (stats.isDirectory()) {
    for (const entry of readdirSync(absolute, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      if (entry.isDirectory() && excludedRoot(entry.name) && path.dirname(relative) === ".") continue;
      walk(rootDir, relative === "." ? entry.name : path.join(relative, entry.name), out, budget);
    }
    return;
  }
  if (!stats.isFile()) return; // sockets/fifos/dispositivos não são entrada de build
  budget.count += 1;
  out.push({
    path: relative,
    kind: "file",
    mode: stats.mode & 0o777,
    sha256: createHash("sha256").update(readFileSync(absolute)).digest("hex"),
  });
}

function snapshotDigest(files: SnapshotEntry[]): string {
  const canonical = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

/** Estado completo da árvore executável: caminho, tipo, modo e conteúdo. */
export function captureSnapshot(rootDir: string): CandidateSnapshot {
  const files: SnapshotEntry[] = [];
  walk(rootDir, ".", files, { count: 0 });
  return { version: 1, files, digest: snapshotDigest(files) };
}

/**
 * Digest das dependências: o conteúdo de `node_modules` é materializado pelo
 * gerenciador e vinculado por lockfile. Sem isso, trocar uma dependência entre a
 * avaliação e o uso passaria despercebido.
 */
export function captureDependencyDigest(rootDir: string): DependencyDigest {
  const files = DEPENDENCY_MANIFESTS.map((relative) => {
    const absolute = path.join(rootDir, relative);
    const present = existsSync(absolute) && lstatSync(absolute).isFile();
    return {
      path: relative,
      sha256: present ? createHash("sha256").update(readFileSync(absolute)).digest("hex") : null,
    };
  });
  return { files, digest: createHash("sha256").update(JSON.stringify(files)).digest("hex") };
}

/** Caminhos existentes na raiz que o sandbox precisa montar (dependências). */
export function presentDependencyPaths(rootDir: string): string[] {
  return DEPENDENCY_PATHS.map((relative) => path.join(rootDir, relative)).filter((absolute) => existsSync(absolute));
}

/**
 * Materializa o snapshot em um diretório descartável: só o que foi registrado é
 * copiado, então nada que o candidato crie depois entra na avaliação.
 */
export function materializeSnapshot(
  snapshot: CandidateSnapshot,
  destination: string,
  source: string,
): void {
  for (const entry of snapshot.files) {
    const target = path.join(destination, entry.path);
    mkdirSync(path.dirname(target), { recursive: true });
    if (entry.kind === "symlink") {
      symlinkSync(entry.target ?? "", target);
      continue;
    }
    copyFileSync(path.join(source, entry.path), target);
    chmodSync(target, entry.mode);
  }
}
