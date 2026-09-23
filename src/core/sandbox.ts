import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
export class SandboxError extends Error {
  constructor(message: string, public readonly runId: string, public readonly reason: string) {
    super(message);
    this.name = 'SandboxError';
  }
}

export interface SandboxSession {
  runId: string;
  worktreePath: string;
  branchName: string;
  created: boolean;
  /**
   * `git rev-parse --absolute-git-dir` do worktree no momento da criação.
   * Identifica o repositório exato: sem isso, apagar o `.git` do sandbox faz o
   * Git subir para o repositório-pai e o inventário do diff guard passa a
   * descrever outra árvore (ou nenhuma).
   */
  gitDir: string;
}

/** Diretório git absoluto de `cwd`, ou `null` quando não há repositório válido. */
export function resolveGitDir(cwd: string): string | null {
  const proc = spawnSync('git', ['rev-parse', '--absolute-git-dir'], { cwd, encoding: 'utf8' });
  if (proc.status !== 0) return null;
  const gitDir = (proc.stdout ?? '').trim();
  return gitDir.length > 0 ? gitDir : null;
}

export function createGitWorktreeSandbox(runId: string, rootDir: string = process.cwd()): SandboxSession {
  const sanitizeId = runId.replace(/[^a-zA-Z0-9_-]/g, '_');
  const worktreeDir = path.resolve(rootDir, '.pwn/sandboxes', sanitizeId);
  const branchName = `pwn-sandbox-${sanitizeId}`;

  if (!fs.existsSync(path.resolve(rootDir, '.pwn/sandboxes'))) {
    fs.mkdirSync(path.resolve(rootDir, '.pwn/sandboxes'), { recursive: true });
  }

  if (fs.existsSync(worktreeDir)) {
    // Run id previsível pode colidir com uma sobra de execução anterior. Reusar um
    // diretório que NÃO é um worktree faria o comando rodar em qualquer lugar — e o
    // diff guard inventariaria outra árvore. Recusa em vez de adotar.
    const existingGitDir = resolveGitDir(worktreeDir);
    if (!existingGitDir) {
      throw new SandboxError(
        `[SANDBOX ABORT] ${worktreeDir} já existe e não é um worktree Git válido (${runId}). ` +
        `Remova o diretório antes de reexecutar.`,
        runId,
        'pre-existing path is not a git worktree',
      );
    }
    return {
      runId,
      worktreePath: worktreeDir,
      branchName,
      created: true,
      gitDir: existingGitDir,
    };
  }

  const proc = spawnSync('git', ['worktree', 'add', '-b', branchName, worktreeDir, 'HEAD'], {
    cwd: rootDir,
    encoding: 'utf8',
  });

  if (proc.status !== 0) {
    const stderr = proc.stderr || '';
    const reason = proc.error?.message || stderr || `git worktree add exited with code ${proc.status}`;
    throw new SandboxError(
      `[SANDBOX ABORT] Falha ao criar worktree para run ${sanitizeId}. ` +
      `Execução bloqueada — agente NÃO será executado no rootDir. ` +
      `Motivo: ${reason}`,
      runId,
      reason,
    );
  }

  const gitDir = resolveGitDir(worktreeDir);
  if (!gitDir) {
    throw new SandboxError(
      `[SANDBOX ABORT] Worktree recém-criado em ${worktreeDir} não resolve para um repositório Git (${runId}).`,
      runId,
      'git worktree add succeeded but rev-parse failed',
    );
  }

  return {
    runId,
    worktreePath: worktreeDir,
    branchName,
    created: true,
    gitDir,
  };
}

export function cleanupGitWorktreeSandbox(session: SandboxSession, rootDir: string = process.cwd()): void {
  if (!session.created) {
    return;
  }

  spawnSync('git', ['worktree', 'remove', '--force', session.worktreePath], {
    cwd: rootDir,
    encoding: 'utf8',
  });

  spawnSync('git', ['branch', '-D', session.branchName], {
    cwd: rootDir,
    encoding: 'utf8',
  });
}

let cachedBwrapSupport: boolean | null = null;

/** Verifica se o host suporta bwrap para isolamento de sandbox no SO. */
export function isBwrapSupported(): boolean {
  if (cachedBwrapSupport !== null) return cachedBwrapSupport;
  try {
    const res = spawnSync('bwrap', ['--ro-bind', '/', '/', '--', 'true'], { stdio: 'ignore' });
    cachedBwrapSupport = res.status === 0;
  } catch {
    cachedBwrapSupport = false;
  }
  return cachedBwrapSupport;
}

export interface BwrapOptions {
  allowNetwork?: boolean;
  extraWritePaths?: string[];
}

/**
 * Envelopa um comando para execução isolada via bwrap (Bubblewrap):
 * - Todo o SO montado como read-only (--ro-bind / /)
 * - /dev e /proc mínimos seguros
 * - /tmp privado em tmpfs
 * - Somente a pasta cwd (e caminhos extras declarados) com permissão de escrita
 * - Rede desligada (--unshare-net), exceto se expressamente permitida pela política
 * - Namespace de processos isolado (--unshare-pid)
 */
export function wrapWithBwrap(
  command: string,
  args: string[],
  cwd: string,
  options: BwrapOptions = {},
): { command: string; args: string[] } {
  const realCwd = fs.existsSync(cwd) ? fs.realpathSync(cwd) : cwd;
  const bwrapArgs: string[] = [
    '--ro-bind', '/', '/',
    '--dev', '/dev',
    '--proc', '/proc',
    '--tmpfs', '/tmp',
    '--bind', realCwd, realCwd,
    '--chdir', realCwd,
    '--unshare-pid',
    '--die-with-parent',
  ];

  // Mascaramento de credenciais do host para evitar leitura por agente não confiável
  const sensitiveDirs = [
    path.join(os.homedir(), '.ssh'),
    path.join(os.homedir(), '.aws'),
  ];
  for (const sDir of sensitiveDirs) {
    if (fs.existsSync(sDir)) {
      bwrapArgs.push('--tmpfs', sDir);
    }
  }

  // Mascarar a chave do verificador se existir dentro da árvore de trabalho
  const verifierKeyPath = path.join(realCwd, '.pwn', '.verifier_key');
  if (fs.existsSync(verifierKeyPath)) {
    bwrapArgs.push('--ro-bind', '/dev/null', verifierKeyPath);
  }
  if (options.extraWritePaths) {
    for (const p of options.extraWritePaths) {
      if (fs.existsSync(p)) {
        const realP = fs.realpathSync(p);
        bwrapArgs.push('--bind', realP, realP);
      }
    }
  }

  if (!options.allowNetwork) {
    bwrapArgs.push('--unshare-net');
  }

  bwrapArgs.push('--', command, ...args);

  return { command: 'bwrap', args: bwrapArgs };
}
