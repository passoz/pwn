import fs from 'node:fs';
import path from 'node:path';

/**
 * Lock de arquivo entre PROCESSOS (o PWN paraleliza por subprocessos `pwn`).
 *
 * Aquisição atômica via `mkdir` do diretório `<alvo>.lock`: ou cria, ou falha com
 * EEXIST. Um lock mais velho que `staleMs` é tomado (dono morto). Bloqueio por
 * espera ativa com `Atomics.wait`, para não depender de timers assíncronos — o
 * core do PWN é síncrono.
 */
export interface LockOptions {
  /** Tempo máximo esperando o lock. */
  timeoutMs?: number;
  /** Idade a partir da qual um lock é considerado abandonado. */
  staleMs?: number;
  /** Intervalo entre tentativas. */
  retryMs?: number;
}

const DEFAULTS = { timeoutMs: 30_000, staleMs: 60_000, retryMs: 25 };

function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export class LockTimeoutError extends Error {
  constructor(target: string, timeoutMs: number) {
    super(`lock de ${target} não obtido em ${timeoutMs}ms`);
    this.name = 'LockTimeoutError';
  }
}

export function withFileLock<T>(target: string, fn: () => T, options: LockOptions = {}): T {
  const { timeoutMs, staleMs, retryMs } = { ...DEFAULTS, ...options };
  const lockDir = `${target}.lock`;
  fs.mkdirSync(path.dirname(lockDir), { recursive: true });
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    try {
      fs.mkdirSync(lockDir);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      try {
        const age = Date.now() - fs.statSync(lockDir).mtimeMs;
        if (age > staleMs) {
          fs.rmSync(lockDir, { recursive: true, force: true });
          continue;
        }
      } catch {
        // O dono liberou entre o mkdir e o stat: tenta de novo.
        continue;
      }
      if (Date.now() >= deadline) throw new LockTimeoutError(target, timeoutMs);
      sleep(retryMs);
    }
  }

  try {
    return fn();
  } finally {
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
}

/** Acrescenta uma linha sob lock (a cadeia/metrics são lidas por outros processos). */
export function appendLine(target: string, line: string, options?: LockOptions): void {
  withFileLock(target, () => {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.appendFileSync(target, line.endsWith('\n') ? line : `${line}\n`, 'utf8');
  }, options);
}

/** Escrita atômica (tmp + rename): leitores nunca veem arquivo pela metade. */
export function writeFileAtomic(target: string, content: string): void {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const tmp = `${target}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, target);
}
