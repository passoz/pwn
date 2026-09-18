import { afterEach, describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_SHELL_POLICY } from '../src/core/policy-engine.js';
import { loadPolicyFile, policyFilePath, resolvePolicy, DEFAULT_RISK_KEYWORDS } from '../src/core/policy-config.js';

const tempRoots: string[] = [];

function tempRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-policy-'));
  tempRoots.push(root);
  return root;
}

function writePolicy(root: string, content: unknown): void {
  const filePath = policyFilePath(root);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, typeof content === 'string' ? content : JSON.stringify(content, null, 2), 'utf8');
}

/** Roda `fn` capturando `console.warn` (os avisos de política são esperados nos casos inválidos). */
function captureWarnings<T>(fn: () => T): { value: T; warnings: string[] } {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => void warnings.push(args.map(String).join(' '));
  try {
    return { value: fn(), warnings };
  } finally {
    console.warn = original;
  }
}

afterEach(() => {
  while (tempRoots.length > 0) fs.rmSync(tempRoots.pop()!, { recursive: true, force: true });
});

describe('policyFilePath', () => {
  test('aponta para .piwerness/policy.json', () => {
    const root = tempRoot();
    expect(policyFilePath(root)).toBe(path.join(root, '.piwerness', 'policy.json'));
    expect(policyFilePath()).toBe(path.join(process.cwd(), '.piwerness', 'policy.json'));
  });
});

describe('resolvePolicy — defaults', () => {
  test('sem arquivo retorna source defaults com as listas espelhadas de v3-import', () => {
    const resolved = resolvePolicy(tempRoot());

    expect(resolved.source).toBe('defaults');
    expect(resolved.risk_keywords.l3).toContain('auth');
    expect(resolved.risk_keywords.l3).toContain('webhook');
    expect(resolved.risk_keywords.l1).toContain('readme');
    expect(resolved.shell).toEqual(DEFAULT_SHELL_POLICY);
    expect(resolved.network.allowAllNetwork).toBe(false);
    expect(resolved.gate_thresholds).toEqual({ max_findings_before_block: 0, max_acs_per_task: 0 });
  });

  test('a política resolvida não compartilha estado mutável com os defaults', () => {
    const root = tempRoot();
    const first = resolvePolicy(root);
    first.shell.deniedCommands.push({ command: 'mutado' });
    first.risk_keywords.l3.push('mutado');

    const second = resolvePolicy(root);
    expect(second.shell.deniedCommands).toEqual(DEFAULT_SHELL_POLICY.deniedCommands);
    expect(second.risk_keywords.l3).not.toContain('mutado');
  });
});

describe('resolvePolicy — arquivo declarativo', () => {
  test('arquivo válido substitui shell/rede e mescla o restante', () => {
    const root = tempRoot();
    writePolicy(root, {
      risk_keywords: { l3: ['checkout', 'pix'], l1: ['docs'] },
      gate_thresholds: { max_findings_before_block: 2, max_acs_per_task: 5 },
      shell: {
        allowed_commands: [{ command: 'bun', args: ['test'] }, { command: 'git', args: ['status'] }],
        denied_commands: [{ command: 'curl' }],
        allow_all_shell: false,
      },
      network: {
        allowed_domains: ['registry.npmjs.org'],
        denied_domains: ['evil.example'],
        allow_all_network: false,
      },
    });

    const resolved = resolvePolicy(root);
    expect(resolved.source).toBe('file');
    expect(resolved.risk_keywords).toEqual({ l3: ['checkout', 'pix'], l1: ['docs'] });
    expect(resolved.gate_thresholds).toEqual({ max_findings_before_block: 2, max_acs_per_task: 5 });
    // O arquivo usa snake_case; a política efetiva usa os tipos do PolicyEngine.
    expect(resolved.shell.allowedCommands).toEqual([
      { command: 'bun', args: ['test'] },
      { command: 'git', args: ['status'] },
    ]);
    expect(resolved.shell.deniedCommands).toEqual([{ command: 'curl' }]);
    expect(resolved.network.allowedDomains).toEqual(['registry.npmjs.org']);
    expect(resolved.network.deniedDomains).toEqual(['evil.example']);
    expect(loadPolicyFile(root)?.shell?.allowAllShell).toBe(false);
  });

  test('seções parciais preservam os defaults do que não foi declarado', () => {
    const root = tempRoot();
    writePolicy(root, { risk_keywords: { l1: ['somente-docs'] }, shell: { allow_all_shell: true } });

    const resolved = resolvePolicy(root);
    expect(resolved.source).toBe('file');
    expect(resolved.risk_keywords).toEqual({ l1: ['somente-docs'], l3: DEFAULT_RISK_KEYWORDS.l3 });
    expect(resolved.shell.allowAllShell).toBe(true);
    expect(resolved.shell.allowedCommands).toEqual([]);
    expect(resolved.shell.deniedCommands).toEqual(DEFAULT_SHELL_POLICY.deniedCommands);
  });
});

describe('resolvePolicy — arquivos rejeitados', () => {
  test('arquivo fora do schema (ou malformado) cai nos defaults, com aviso e sem lançar', () => {
    const root = tempRoot();
    expect(loadPolicyFile(root)).toBeNull();

    const rejected: Array<string | Record<string, unknown>> = [
      '{"shell": ', // JSON malformado
      { shell: 42 }, // tipo errado (caso de aceitação)
      { shell: { allowAllShell: true } }, // chave desconhecida (typo em camelCase)
      { campo_desconhecido: 1 }, // chave desconhecida na raiz
      { gate_thresholds: { max_acs_per_task: -1 } }, // abaixo do mínimo
    ];

    for (const content of rejected) {
      writePolicy(root, content);
      const { value, warnings } = captureWarnings(() => ({ resolved: resolvePolicy(root), loaded: loadPolicyFile(root) }));
      expect(value.loaded).toBeNull();
      expect(value.resolved.source).toBe('defaults');
      expect(value.resolved.risk_keywords.l3).toContain('auth');
      expect(warnings.length).toBeGreaterThan(0);
      expect(warnings.every((warning) => warning.includes(path.join('.piwerness', 'policy.json')))).toBe(true);
    }
  });
});
