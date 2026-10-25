import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "./acceptance.js";

/**
 * Raiz do verificador independente: configuração, chaves e registros ficam FORA da
 * árvore do projeto. O candidato pode ler e escrever o repositório inteiro; nada
 * aqui pode estar em um caminho que ele controle, senão a autoridade de conclusão
 * volta a ser do próprio candidato.
 *
 * `PWN_VERIFIER_HOME` existe para testes e para instalações isoladas; é a única
 * forma de redirecionar a raiz e deve ser tratada como configuração do operador.
 */
export const VERIFIER_HOME_ENV = "PWN_VERIFIER_HOME";

/** Erro de pré-requisito do verificador: nunca vira "aceito" e nunca é ignorado. */
export class VerificationUnavailable extends Error {
  constructor(
    message: string,
    public readonly detail: string,
  ) {
    super(message);
    this.name = "VerificationUnavailable";
  }
}

export interface VerifierConfig {
  version: 1;
  verifier_id: string;
  created_at: string;
  /** Runtime aprovado para executar os checks de aceitação. */
  runtime: { bun: string };
  /** Isolamento exigido: sem ele não existe aceitação independente. */
  isolation: { mode: "bwrap"; bwrap: string | null; network: false };
  /** Ajustes de sandbox por raiz de projeto, escritos pelo operador. Ausente = política padrão. */
  projects?: Record<string, ProjectSandbox>;
}

/** Montagem somente leitura com destino diferente da origem (ex.: cache em $HOME do sandbox). */
export interface ProjectMount {
  source: string;
  dest: string;
}

/** Ajustes de sandbox de um projeto. Vêm da raiz protegida: o repositório avaliado não os controla. */
export interface ProjectSandbox {
  /** Diretórios absolutos prefixados ao PATH do sandbox; montados somente leitura. */
  path_prepend?: string[];
  /** Diretórios absolutos extras montados somente leitura (ex.: cache de módulos). */
  mounts_ro?: string[];
  /** Montagens somente leitura com destino próprio, para caches que dependem de um caminho fixo. */
  mounts?: ProjectMount[];
  /** HOME do sandbox. Ausente = `/nonexistent`. Nunca pode ficar dentro do repositório. */
  home?: string;
  /** Variáveis fixas do ambiente do sandbox. HOME, PATH e TMPDIR são reservadas. */
  env?: Record<string, string>;
}

const RESERVED_SANDBOX_ENV: Record<string, true> = { HOME: true, PATH: true, TMPDIR: true };
const RESERVED_MOUNT_DEST: Record<string, true> = { "/": true, "/tmp": true, "/proc": true, "/dev": true };

/** Caminho absoluto e normalizado; `null` quando o valor não é um caminho utilizável. */
function cleanAbsolute(value: unknown): string | null {
  if (typeof value !== "string" || !path.isAbsolute(value)) return null;
  const normalized = path.normalize(value);
  return normalized === "/" ? normalized : normalized.replace(/\/+$/, "");
}

function inside(parent: string, child: string): boolean {
  return child === parent || child.startsWith(`${parent}/`);
}

/**
 * Política de sandbox do projeto em `projectDir`. Falha fechada: entrada malformada
 * aborta a verificação; nunca cai silenciosamente no padrão.
 */
export function projectSandbox(projectDir: string, root: string = verifierRoot()): ProjectSandbox | null {
  const config = readConfig(root);
  if (!config?.projects) return null;
  const target = realpathSync(projectDir);
  const match = Object.keys(config.projects).find((key) => {
    try {
      return realpathSync(key) === target;
    } catch {
      return false;
    }
  });
  if (match === undefined) return null;
  const where = `projects["${match}"]`;
  const entry: unknown = config.projects[match];
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new VerificationUnavailable(`${where} inválido`, "esperado objeto");
  }
  const absolutePaths = (value: unknown, field: string): string[] => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) {
      throw new VerificationUnavailable(`${where}.${field} inválido`, "esperado array de caminhos absolutos");
    }
    return value.map((item, index) => {
      const cleaned = cleanAbsolute(item);
      if (!cleaned) {
        throw new VerificationUnavailable(`${where}.${field}[${index}] inválido`, "esperado caminho absoluto");
      }
      return cleaned;
    });
  };
  const mounts: ProjectMount[] = [];
  const rawMounts: unknown = (entry as ProjectSandbox).mounts ?? [];
  if (!Array.isArray(rawMounts)) {
    throw new VerificationUnavailable(`${where}.mounts inválido`, "esperado array de {source, dest}");
  }
  const destinations = new Set<string>();
  rawMounts.forEach((item, index) => {
    const mount = item as ProjectMount;
    const source = cleanAbsolute(mount?.source);
    const dest = cleanAbsolute(mount?.dest);
    if (!source || !dest) {
      throw new VerificationUnavailable(`${where}.mounts[${index}] inválido`, "esperado {source, dest} com caminhos absolutos");
    }
    if (RESERVED_MOUNT_DEST[dest] === true) {
      throw new VerificationUnavailable(`${where}.mounts[${index}].dest reservado`, `${dest} é reservado pelo sandbox`);
    }
    if (destinations.has(dest)) {
      throw new VerificationUnavailable(`${where}.mounts[${index}].dest duplicado`, `${dest} já é destino de outra montagem`);
    }
    destinations.add(dest);
    mounts.push({ source, dest });
  });
  let home: string | undefined;
  if ((entry as ProjectSandbox).home !== undefined) {
    const cleaned = cleanAbsolute((entry as ProjectSandbox).home);
    if (!cleaned || cleaned === "/nonexistent" || inside(target, cleaned)) {
      throw new VerificationUnavailable(`${where}.home inválido`, "esperado caminho absoluto fora do repositório");
    }
    home = cleaned;
  }
  const env: unknown = (entry as ProjectSandbox).env ?? {};
  if (typeof env !== "object" || env === null || Array.isArray(env)) {
    throw new VerificationUnavailable(`${where}.env inválido`, "esperado objeto de variáveis");
  }
  for (const [name, value] of Object.entries(env)) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(name) || RESERVED_SANDBOX_ENV[name] === true || typeof value !== "string" || value.includes("\n")) {
      throw new VerificationUnavailable(`${where}.env.${name} inválido`, "nome ou valor não permitido");
    }
  }
  return {
    path_prepend: absolutePaths((entry as ProjectSandbox).path_prepend, "path_prepend"),
    mounts_ro: absolutePaths((entry as ProjectSandbox).mounts_ro, "mounts_ro"),
    mounts,
    ...(home ? { home } : {}),
    env: env as Record<string, string>,
  };
}

export function verifierRoot(): string {
  const override = process.env[VERIFIER_HOME_ENV]?.trim();
  if (override) return path.resolve(override);
  return path.join(os.homedir(), ".config", "pwn", "verifier");
}

export function configFile(root: string = verifierRoot()): string {
  return path.join(root, "config.json");
}

export function keysDir(root: string = verifierRoot()): string {
  return path.join(root, "keys");
}

export function privateKeyFile(root: string = verifierRoot()): string {
  return path.join(keysDir(root), "verifier-private.pem");
}

export function publicKeyFile(root: string = verifierRoot()): string {
  return path.join(keysDir(root), "verifier-public.pem");
}

export function approvalsDir(root: string = verifierRoot()): string {
  return path.join(root, "approvals");
}

export function approvalFilesDir(approvalId: string, root: string = verifierRoot()): string {
  return path.join(approvalsDir(root), approvalId, "files");
}

export function receiptDir(root: string = verifierRoot()): string {
  return path.join(root, "receipts");
}

/** Caminho padrão do runtime: o próprio executável que roda o verificador. */
export function defaultRuntime(): string {
  return process.execPath;
}

export function findExecutable(name: string): string | null {
  const which = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
  const found = (which.stdout ?? "").trim();
  return which.status === 0 && found.length > 0 ? found : null;
}

/** Escrita atômica: um leitor nunca observa JSON truncado. */
export function writeJsonAtomic(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporary, file);
}

export function writeFileAtomic(file: string, content: string, mode?: number): void {
  mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, content, { encoding: "utf8", mode });
  if (mode !== undefined) chmodSync(temporary, mode);
  renameSync(temporary, file);
}

function ensurePrivateDir(directory: string): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try {
    chmodSync(directory, 0o700);
  } catch {
    // Sistemas sem semântica POSIX de permissão (Windows) não têm como aplicar.
  }
}

export function readConfig(root: string = verifierRoot()): VerifierConfig | null {
  const file = configFile(root);
  if (!existsSync(file)) return null;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as VerifierConfig;
    if (parsed?.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Cria a raiz protegida quando ausente: diretório 0700, par de chaves Ed25519 e
 * configuração com runtime e suporte a isolamento detectados no host.
 */
export function initializeVerifierHome(root: string = verifierRoot()): { root: string; config: VerifierConfig; created: boolean } {
  const existing = readConfig(root);
  ensurePrivateDir(root);
  ensurePrivateDir(keysDir(root));
  ensurePrivateDir(approvalsDir(root));
  ensurePrivateDir(receiptDir(root));

  if (!existsSync(privateKeyFile(root)) || !existsSync(publicKeyFile(root))) {
    const pair = generateKeyPairSync("ed25519");
    writeFileAtomic(
      privateKeyFile(root),
      pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      0o600,
    );
    writeFileAtomic(
      publicKeyFile(root),
      pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
      0o600,
    );
  }

  if (existing) return { root, config: existing, created: false };

  const config: VerifierConfig = {
    version: 1,
    verifier_id: `${os.hostname()}-${createHash("sha256").update(root).digest("hex").slice(0, 8)}`,
    created_at: new Date().toISOString(),
    runtime: { bun: defaultRuntime() },
    isolation: { mode: "bwrap", bwrap: findExecutable("bwrap"), network: false },
  };
  writeJsonAtomic(configFile(root), config);
  return { root, config, created: true };
}

function readKeyObject(file: string, kind: "private" | "public"): KeyObject | null {
  if (!existsSync(file)) return null;
  try {
    const pem = readFileSync(file, "utf8");
    return kind === "private" ? createPrivateKey(pem) : createPublicKey(pem);
  } catch {
    return null;
  }
}

/** Chave privada do verificador: só o processo que avalia pode carregá-la. */
export function loadPrivateKey(root: string = verifierRoot()): KeyObject | null {
  return readKeyObject(privateKeyFile(root), "private");
}

/** Chave pública: é tudo o que o status do projeto precisa para conferir recibos. */
export function loadPublicKey(root: string = verifierRoot()): KeyObject | null {
  return readKeyObject(publicKeyFile(root), "public");
}

/** Impressão digital da chave pública: identifica quem assinou sem expor a privada. */
export function publicKeyFingerprint(root: string = verifierRoot()): string | null {
  const key = loadPublicKey(root);
  if (!key) return null;
  const der = key.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

/** Prontidão do verificador: sem runtime, chave e isolamento não há aceitação. */
export interface VerifierReadiness {
  root: string;
  config: VerifierConfig;
  runtime: string;
  bwrap: string;
  publicKeyFingerprint: string;
}

export function requireVerifierReady(root: string = verifierRoot()): VerifierReadiness {
  const config = readConfig(root);
  if (!config) {
    throw new VerificationUnavailable(
      `verificador independente não configurado em ${root}`,
      "inicialize com 'pwn verify init' antes de pedir aceitação",
    );
  }
  const runtime = config.runtime?.bun ?? "";
  if (!runtime || !existsSync(runtime)) {
    throw new VerificationUnavailable(
      `runtime aprovado do verificador não encontrado: ${runtime || "(vazio)"}`,
      "reinstale o verificador ou atualize a configuração protegida",
    );
  }
  const bwrap = config.isolation?.bwrap ?? null;
  if (!bwrap || !existsSync(bwrap)) {
    throw new VerificationUnavailable(
      "isolamento indisponível: sem bwrap não existe aceitação independente",
      "instale bubblewrap ou marque a verificação como indisponível (nunca execute no host)",
    );
  }
  const fingerprint = publicKeyFingerprint(root);
  if (!fingerprint) {
    throw new VerificationUnavailable(
      `chave pública do verificador ausente em ${publicKeyFile(root)}`,
      "gere o par de chaves com 'pwn verify init'",
    );
  }
  return { root, config, runtime, bwrap, publicKeyFingerprint: fingerprint };
}

/** Diretórios que o sandbox de avaliação NUNCA pode enxergar. */
export function protectedPaths(root: string = verifierRoot()): string[] {
  return [root, path.dirname(root)];
}

/**
 * A raiz protegida não pode estar dentro do projeto avaliado: ela seria copiada
 * para o snapshot, ficaria visível ao código avaliado e poderia ser alterada por ele.
 * Recusar é melhor do que aceitar com uma fronteira que não existe.
 */
export function assertProtectedOutsideRepository(root: string, repositoryRoot: string): void {
  const verified = path.resolve(root);
  const repository = path.resolve(repositoryRoot);
  if (verified === repository || verified.startsWith(`${repository}${path.sep}`)) {
    throw new VerificationUnavailable(
      `raiz do verificador dentro do repositório avaliado: ${verified}`,
      `mova-a para fora de ${repository} (padrão: ~/.config/pwn/verifier) ou aponte PWN_VERIFIER_HOME para um caminho externo`,
    );
  }
}

export function listJsonFiles(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((entry) => entry.endsWith(".json"))
    .map((entry) => path.join(directory, entry))
    .sort();
}

export function isDirectory(target: string): boolean {
  try {
    return statSync(target).isDirectory();
  } catch {
    return false;
  }
}

export function digestOfFile(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

export function digestOfText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export { canonicalJson };
