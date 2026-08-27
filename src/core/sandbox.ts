import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

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
    // Fallback: return direct rootDir if worktree creation fails (e.g. not in git repo or detached HEAD)
    return {
      runId,
      worktreePath: rootDir,
      branchName: 'main',
      created: false,
    };
  }

  return {
    runId,
    worktreePath: worktreeDir,
    branchName,
    created: true,
  };
}

export function cleanupGitWorktreeSandbox(session: SandboxSession, rootDir: string = process.cwd()): void {
  if (!session.created || session.worktreePath === rootDir) {
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
