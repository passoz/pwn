import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
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
}

export function createGitWorktreeSandbox(runId: string, rootDir: string = process.cwd()): SandboxSession {
  const sanitizeId = runId.replace(/[^a-zA-Z0-9_-]/g, '_');
  const worktreeDir = path.resolve(rootDir, '.piwerness/sandboxes', sanitizeId);
  const branchName = `pwn-sandbox-${sanitizeId}`;

  if (!fs.existsSync(path.resolve(rootDir, '.piwerness/sandboxes'))) {
    fs.mkdirSync(path.resolve(rootDir, '.piwerness/sandboxes'), { recursive: true });
  }

  if (fs.existsSync(worktreeDir)) {
    return {
      runId,
      worktreePath: worktreeDir,
      branchName,
      created: true,
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

  return {
    runId,
    worktreePath: worktreeDir,
    branchName,
    created: true,
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
