import { cpSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "./acceptance.js";
import {
  captureDependencyDigest,
  captureSnapshot,
  materializeSnapshot,
  presentDependencyPaths,
} from "./candidate-snapshot.js";
import { approvedFileContent, type Approval, type ApprovedCheck } from "./acceptance-approval.js";
import {
  assertProtectedOutsideRepository,
  requireVerifierReady,
  verifierRoot,
  type VerifierReadiness,
} from "./verifier-home.js";

/**
 * Execução dos checks de aceitação dentro do sandbox do verificador.
 *
 * Regras que fazem a diferença entre "aceitação independente" e "mais um bun test":
 * - o diretório do candidato é montado como uma CÓPIA do snapshot registrado;
 * - os arquivos de aceitação aprovados são restaurados da raiz protegida por cima
 *   da cópia, então enfraquecer o teste no repositório não altera o que roda;
 * - `HOME` do sandbox não é o do operador, a rede está desligada e a raiz do
 *   verificador não é montada — o código avaliado não alcança chave nem registros;
 * - o veredicto é um resultado observado pelo verificador (exit code + assinatura
 *   de saída), nunca uma linha que o candidato imprimiu se declarando aprovado.
 */

export interface CheckObservation {
  id: string;
  command: string[];
  outcome: "pass" | "fail" | "blocked";
  exit_code: number;
  output_digest: string;
  output_tail: string;
  reason?: string;
  /** Resultado da mesma asserção com a implementação revertida ao baseline. */
  baseline?: {
    exit_code: number;
    output_digest: string;
    output_tail: string;
    /** `true` quando a falha do baseline parece ambiente/import, não a asserção. */
    suspect_environmental: boolean;
  };
}

export interface VerificationRunResult {
  checks: CheckObservation[];
  snapshot_digest: string;
  dependency_digest: string;
  sandbox_digest: string;
  sandbox_policy: SandboxPolicy;
}

export interface SandboxPolicy {
  engine: "bwrap";
  network: false;
  user_namespace: true;
  pid_namespace: true;
  mounts_ro: string[];
  home: string;
  env_allowlist: string[];
}

const TOOLCHAIN_PATTERNS = [
  /cannot find module/i,
  /cannot find package/i,
  /module not found/i,
  /no such file or directory/i,
  /command not found/i,
  /is not in the dependency tree/i,
  /failed to resolve/i,
];

export function looksEnvironmental(output: string): boolean {
  return TOOLCHAIN_PATTERNS.some((pattern) => pattern.test(output));
}

/** Diretório do runtime precisa entrar no sandbox: ele pode viver fora de /usr. */
function runtimeMounts(runtime: string): string[] {
  const resolved = path.resolve(runtime);
  if (resolved.startsWith("/usr/") || resolved.startsWith("/bin/")) return [];
  return [path.dirname(path.dirname(resolved))];
}

function executableRoot(executable: string): string | null {
  if (!path.isAbsolute(executable)) return null;
  return path.dirname(path.dirname(executable));
}

/**
 * Vínculos dos executáveis declarados nos checks.
 *
 * O plano pode citar um caminho simbólico do runtime (`…/bun/latest/bin/bun`)
 * enquanto o processo real é `…/bun/1.4.2/bin/bun`. Sem ligar o diretório real ao
 * caminho declarado, o sandbox executaria um caminho que não existe — e o check
 * falharia por ambiente, não por comportamento.
 */
export function executableBinds(command: string[]): Array<[string, string]> {
  const executable = command[0];
  if (!executable) return [];
  const declaredRoot = executableRoot(executable);
  if (!declaredRoot) return [];
  let realRoot: string;
  try {
    realRoot = executableRoot(realpathSync(executable)) ?? declaredRoot;
  } catch {
    realRoot = declaredRoot;
  }
  const binds: Array<[string, string]> = [[realRoot, realRoot]];
  if (realRoot !== declaredRoot) binds.push([realRoot, declaredRoot]);
  return binds;
}

export function sandboxPolicy(runtime: string, commands: string[][] = []): SandboxPolicy {
  const mounts = ["/usr", "/bin", "/lib", "/lib64", "/etc", ...runtimeMounts(runtime)];
  const execRoots = commands
    .flatMap((command) => executableBinds(command).map(([source]) => source))
    .filter((root) => !root.startsWith("/usr/") && !root.startsWith("/bin/"));
  return {
    engine: "bwrap",
    network: false,
    user_namespace: true,
    pid_namespace: true,
    mounts_ro: [...new Set([...mounts, ...execRoots])].sort(),
    home: "/nonexistent",
    env_allowlist: ["PATH", "TMPDIR", "LANG", "LC_ALL", "TERM"],
  };
}

interface SandboxSpawnResult {
  status: number;
  output: string;
  timedOut: boolean;
}

/**
 * Monta o sandbox mínimo: o host inteiro NÃO é montado. Sem isso, ler a chave do
 * verificador (ou qualquer arquivo do operador) seria trivial para o código avaliado.
 */
function spawnInSandbox(
  readiness: VerifierReadiness,
  policy: SandboxPolicy,
  workDir: string,
  extraRoBinds: Array<[string, string]>,
  command: string[],
  timeoutMs: number,
): SandboxSpawnResult {
  const args: string[] = [];
  for (const mount of policy.mounts_ro) args.push("--ro-bind", mount, mount);
  for (const [source, destination] of extraRoBinds) args.push("--ro-bind", source, destination);
  args.push("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");
  args.push("--bind", workDir, workDir, "--chdir", workDir);
  args.push("--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent");
  args.push("--clearenv");
  args.push("--setenv", "HOME", policy.home);
  args.push("--setenv", "TMPDIR", "/tmp");
  args.push("--setenv", "PATH", "/usr/bin:/bin");
  args.push("--", ...command);

  const result = spawnSync(readiness.bwrap, args, {
    encoding: "utf8",
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: 16 * 1024 * 1024,
  });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const timedOut = (result.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
  return { status: result.status ?? 1, output: `${stdout}${stderr}`, timedOut };
}

function digestOutput(output: string): string {
  return createHash("sha256").update(output).digest("hex");
}

function tail(output: string, limit = 2000): string {
  const trimmed = output.trim();
  return trimmed.length > limit ? trimmed.slice(trimmed.length - limit) : trimmed;
}

/** Reverte os arquivos de implementação ao conteúdo do commit aprovado. */
function applyBaselineImplementation(workDir: string, rootDir: string, approval: Approval): void {
  for (const relative of approval.implementation_files) {
    const target = path.join(workDir, relative);
    const shown = spawnSync("git", ["show", `${approval.baseline_commit}:${relative}`], {
      cwd: rootDir,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    if (shown.status === 0) {
      writeFileSync(target, shown.stdout, "utf8");
      continue;
    }
    // Não existia no baseline: a implementação da task é o arquivo novo.
    if (existsSync(target)) rmSync(target, { force: true });
  }
}

function copyTree(source: string, destination: string): void {
  cpSync(source, destination, { recursive: true, dereference: false, force: true, verbatimSymlinks: true });
}

export interface RunVerificationOptions {
  rootDir: string;
  approval: Approval;
  /** Sinaliza checks que devem falhar com a implementação revertida. */
  timeoutSeconds?: number;
  verifierRootDir?: string;
}

export function runVerification(options: RunVerificationOptions): VerificationRunResult {
  const root = options.verifierRootDir ?? verifierRoot();
  const readiness = requireVerifierReady(root);
  assertProtectedOutsideRepository(root, options.rootDir);
  const policy = sandboxPolicy(
    readiness.runtime,
    options.approval.checks.map((check) => check.command),
  );
  const timeoutMs = (options.timeoutSeconds ?? 600) * 1000;

  const snapshot = captureSnapshot(options.rootDir);
  const dependency = captureDependencyDigest(options.rootDir);
  const dependencyMounts = presentDependencyPaths(options.rootDir);

  const scratch = mkdtempSync(path.join(os.tmpdir(), "pwn-verify-"));
  const workDir = path.join(scratch, "candidate");
  const baselineDir = path.join(scratch, "baseline");
  const checks: CheckObservation[] = [];

  try {
    materializeSnapshot(snapshot, workDir, options.rootDir);

    // Restaura o conteúdo aprovado: o que roda é a versão guardada na raiz protegida.
    for (const entry of options.approval.approved_files) {
      const content = approvedFileContent(options.approval, entry.path, root);
      if (content === null) {
        throw new Error(`arquivo aprovado ausente na raiz protegida: ${entry.path}`);
      }
      const digest = createHash("sha256").update(content).digest("hex");
      if (digest !== entry.sha256) {
        throw new Error(`arquivo aprovado corrompido na raiz protegida: ${entry.path}`);
      }
      const target = path.join(workDir, entry.path);
      writeFileSync(target, content, "utf8");
    }

    // node_modules montado read-only DENTRO do diretório avaliado: o candidato pode
    // adulterar sua árvore de dependências, então ela nunca é gravável durante a
    // avaliação, e a integridade é vinculada pelo digest dos manifestos.
    const dependencyMounts = presentDependencyPaths(options.rootDir);

    for (const check of options.approval.checks) {
      checks.push(
        executeCheck({
          check,
          readiness,
          policy,
          rootDir: options.rootDir,
          approval: options.approval,
          workDir,
          baselineDir,
          execBinds: executableBinds(check.command),
          dependencySources: dependencyMounts,
          timeoutMs,
          timeoutSeconds: options.timeoutSeconds ?? 600,
        }),
      );
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  return {
    checks,
    snapshot_digest: snapshot.digest,
    dependency_digest: dependency.digest,
    sandbox_digest: createHash("sha256").update(canonicalJson(policy)).digest("hex"),
    sandbox_policy: policy,
  };
}

interface ExecuteCheckOptions {
  check: ApprovedCheck;
  readiness: VerifierReadiness;
  policy: SandboxPolicy;
  rootDir: string;
  approval: Approval;
  workDir: string;
  baselineDir: string;
  /** Executáveis: mesmo destino nos dois lados (caminho absoluto declarado). */
  execBinds: Array<[string, string]>;
  /** Dependências: ligadas read-only dentro de cada árvore avaliada. */
  dependencySources: string[];
  timeoutMs: number;
  timeoutSeconds: number;
}

function executeCheck(options: ExecuteCheckOptions): CheckObservation {
  const { check, readiness, policy, workDir } = options;
  const bindsFor = (tree: string): Array<[string, string]> => [
    ...options.execBinds,
    ...options.dependencySources.map((source) => [source, path.join(tree, path.basename(source))] as [string, string]),
  ];
  const candidate = spawnInSandbox(readiness, policy, workDir, bindsFor(workDir), check.command, options.timeoutMs);
  const base: CheckObservation = {
    id: check.id,
    command: check.command,
    outcome: "pass",
    exit_code: candidate.status,
    output_digest: digestOutput(candidate.output),
    output_tail: tail(candidate.output),
  };
  if (candidate.timedOut) {
    return { ...base, outcome: "blocked", reason: `check ${check.id} excedeu ${options.timeoutSeconds}s` };
  }
  if (candidate.status !== 0) {
    return { ...base, outcome: "fail", reason: `check ${check.id} terminou com exit ${candidate.status}` };
  }
  if (check.expect_output && !candidate.output.includes(check.expect_output)) {
    return { ...base, outcome: "fail", reason: `check ${check.id} não produziu o texto aprovado ${JSON.stringify(check.expect_output)}` };
  }
  if (!check.require_baseline_failure) return base;

  // Causalidade: a mesma asserção, com a implementação da task revertida ao commit
  // aprovado, precisa FALHAR. Um AC que passa sem a implementação não aceita nada.
  copyTree(workDir, options.baselineDir);
  applyBaselineImplementation(options.baselineDir, options.rootDir, options.approval);
  const baseline = spawnInSandbox(readiness, policy, options.baselineDir, bindsFor(options.baselineDir), check.command, options.timeoutMs);
  const suspect = looksEnvironmental(baseline.output);
  const observation = {
    exit_code: baseline.status,
    output_digest: digestOutput(baseline.output),
    output_tail: tail(baseline.output),
    suspect_environmental: suspect,
  };
  if (baseline.timedOut) {
    return { ...base, outcome: "blocked", baseline: observation, reason: `baseline de ${check.id} excedeu o tempo do check` };
  }
  if (baseline.status === 0) {
    return {
      ...base,
      outcome: "fail",
      baseline: observation,
      reason: `${check.id} passa sem a implementação da task (prova vácua; não demonstra causalidade)`,
    };
  }
  if (suspect) {
    return {
      ...base,
      outcome: "fail",
      baseline: observation,
      reason: `${check.id}: a falha no baseline parece erro de ambiente/import; a asserção não demonstrou depender da implementação`,
    };
  }
  return { ...base, baseline: observation };
}

