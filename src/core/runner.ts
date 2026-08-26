import { spawnSync, SpawnSyncOptions } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';

export interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

export function runPackScript(scriptName: string, args: string[] = [], cwd: string = process.cwd()): RunResult {
  const packScriptPath = path.resolve(cwd, 'packs/software-engineering/scripts', scriptName);
  
  if (!fs.existsSync(packScriptPath)) {
    return {
      status: 1,
      stdout: '',
      stderr: `Script not found in pack: ${packScriptPath}`,
    };
  }

  const options: SpawnSyncOptions = {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
    },
  };

  const proc = spawnSync('node', [packScriptPath, ...args], options);

  return {
    status: proc.status ?? 1,
    stdout: proc.stdout as string || '',
    stderr: proc.stderr as string || '',
  };
}
