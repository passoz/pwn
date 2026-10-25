import { spawn } from 'node:child_process';
import os from 'node:os';

export interface PoolJob {
  id: string;
  command: string[];
  cwd?: string;
  env?: Record<string, string>;
}

export interface PoolResult {
  id: string;
  status: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export function defaultConcurrency(): number {
  return Math.max(1, Math.min(os.availableParallelism() - 1, 8));
}

function runOne(job: PoolJob, timeoutMs?: number): Promise<PoolResult> {
  const started = Date.now();
  const { promise, resolve } = Promise.withResolvers<PoolResult>();
  {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    const finish = (status: number, extraErr = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        id: job.id,
        status,
        stdout,
        stderr: stderr + extraErr,
        durationMs: Date.now() - started,
        timedOut,
      });
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const [cmd, ...args] = job.command;
    const child = spawn(cmd, args, {
      cwd: job.cwd,
      env: job.env ? { ...process.env, ...job.env } : process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Grupo próprio: matar só o shell deixaria os netos (sleep, go test) vivos
      // segurando os pipes, e o pool esperaria o processo original terminar.
      detached: process.platform !== 'win32',
    });
    child.stdout.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    child.on('error', (err) => finish(127, `falha ao iniciar processo: ${err.message}\n`));
    child.on('close', (code, signal) => finish(code ?? (signal ? 128 : 1)));
    if (timeoutMs && timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        const pid = child.pid;
        if (process.platform !== 'win32' && pid !== undefined) {
          try {
            process.kill(-pid, 'SIGKILL');
          } catch {
            child.kill('SIGKILL');
          }
        } else {
          child.kill('SIGKILL');
        }
        finish(137);
      }, timeoutMs);
    }
  }
  return promise;
}

export async function runPool(
  jobs: PoolJob[],
  opts: { concurrency: number; timeoutMs?: number; onResult?: (r: PoolResult) => void },
): Promise<PoolResult[]> {
  const results: PoolResult[] = new Array(jobs.length);
  const limit = Math.max(1, Math.min(Math.floor(opts.concurrency) || 1, jobs.length || 1));
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const index = next++;
      const result = await runOne(jobs[index], opts.timeoutMs);
      results[index] = result;
      opts.onResult?.(result);
    }
  };
  await Promise.all(Array.from({ length: limit }, worker));
  return results;
}
