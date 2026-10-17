import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { readDeciderConfig } from '../src/core/decider/config.js';

const CLI = path.resolve(import.meta.dirname, '../src/cli.ts');

function setup() {
  const repo = mkdtempSync(path.join(tmpdir(), 'pwn-decider-repo-'));
  const verifier = mkdtempSync(path.join(tmpdir(), 'pwn-decider-verifier-'));
  spawnSync('git', ['init', '-q'], { cwd: repo });
  const env: NodeJS.ProcessEnv = { ...process.env, PWN_VERIFIER_HOME: verifier };
  delete env.TYPESAFE_API_KEY;
  const pwn = (cwd: string, ...args: string[]) =>
    spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const cleanup = () => {
    rmSync(repo, { recursive: true, force: true });
    rmSync(verifier, { recursive: true, force: true });
  };
  return { repo, verifier, pwn, cleanup };
}

describe('configuração do decisor', () => {
  test('init sem terminal: flags configuram; sem flags registra sem decisor e não trava; re-init mantém', () => {
    const fx = setup();
    try {
      const bare = fx.pwn(fx.repo, 'init');
      expect(bare.status).toBe(0);
      expect(bare.stderr).toMatch(/Sem terminal .* sem decisor/);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ enabled: false });

      const configured = fx.pwn(fx.repo, 'init', '--decider', 'jev:jev-latest', '--decider-max-risk', 'l2');
      expect(configured.status).toBe(0);
      expect(configured.stderr).toMatch(/\$TYPESAFE_API_KEY não está definida/);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ enabled: true, decider: 'jev:jev-latest', key_env: 'TYPESAFE_API_KEY', max_risk: 'L2' });

      expect(fx.pwn(fx.repo, 'init').stdout).toMatch(/configuração do decisor mantida/);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ enabled: true, max_risk: 'L2' });
    } finally {
      fx.cleanup();
    }
  });

  test('set altera só os campos informados; remove apaga; set acrescenta de novo', () => {
    const fx = setup();
    try {
      expect(fx.pwn(fx.repo, 'decider', 'set').stderr).toMatch(/informe --decider/);
      expect(fx.pwn(fx.repo, 'decider', 'set', '--decider', 'jev:jev-latest', '--decider-key-env', 'MY_KEY').status).toBe(0);
      expect(fx.pwn(fx.repo, 'decider', 'set', '--decider-max-risk', 'L4').status).toBe(0);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ decider: 'jev:jev-latest', key_env: 'MY_KEY', max_risk: 'L4' });

      expect(fx.pwn(fx.repo, 'decider', 'remove').stdout).toMatch(/removida/);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toBeNull();
      expect(fx.pwn(fx.repo, 'decider', 'show').stdout).toMatch(/nenhuma configuração/);
      expect(fx.pwn(fx.repo, 'decider', 'set', '--decider', 'jev:jev-latest').status).toBe(0);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ enabled: true, key_env: 'TYPESAFE_API_KEY', max_risk: 'L3' });
    } finally {
      fx.cleanup();
    }
  });

  test('valores inválidos são recusados sem gravar; config fica fora do repositório, por projeto, com modo 0600', () => {
    const fx = setup();
    try {
      for (const args of [['--decider', 'foo:bar'], ['--decider', 'jev'], ['--decider', 'jev:x', '--decider-max-risk', 'L9'], ['--decider', 'jev:x', '--decider-key-env', 'bad-name']]) {
        expect(fx.pwn(fx.repo, 'decider', 'set', ...args).status).toBe(1);
      }
      expect(readDeciderConfig(fx.repo, fx.verifier)).toBeNull();

      const sub = path.join(fx.repo, 'pkg');
      mkdirSync(sub);
      expect(fx.pwn(sub, 'decider', 'set', '--decider', 'jev:jev-latest').status).toBe(0);
      expect(readDeciderConfig(fx.repo, fx.verifier)).toMatchObject({ enabled: true });
      const files = readdirSync(path.join(fx.verifier, 'deciders'));
      expect(files).toHaveLength(1);
      expect(statSync(path.join(fx.verifier, 'deciders', files[0])).mode & 0o777).toBe(0o600);
      expect(existsSync(path.join(fx.repo, '.pwn'))).toBe(false);
    } finally {
      fx.cleanup();
    }
  });
});
