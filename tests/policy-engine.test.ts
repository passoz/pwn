import assert from 'node:assert/strict';
import test from 'node:test';
import { createDefaultContractV4 } from '../src/core/contract-engine.js';
import { PolicyEngine } from '../src/core/policy-engine.js';

function makePolicy(writeAllow = ['src/**', 'tests/**'], writeDeny = ['.git/**', 'package.json']) {
  const contract = createDefaultContractV4('T-001', '0001', 'Policy Test', 'L1', {
    writeAllow,
    writeDeny,
  });
  return new PolicyEngine(contract);
}

test('PolicyEngine permite escrita dentro da allowlist', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'write_file', path: 'src/cli.ts' });
  assert.equal(decision.allowed, true);
  assert.equal(decision.domain, 'filesystem');
});

test('PolicyEngine bloqueia escrita fora da allowlist', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'write_file', path: 'secret.env' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'not_in_write_allow');
});

test('PolicyEngine bloqueia escrita em arquivos da deny list', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'write_file', path: 'package.json' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'write_deny');
});

test('PolicyEngine permite leitura de qualquer arquivo', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'read_file', path: 'any-file.txt' });
  assert.equal(decision.allowed, true);
});

// ── FAIL-CLOSED: shell ─────────────────────────────────────────────────

test('PolicyEngine FAIL-CLOSED: shell allowlist vazia = DENY ALL', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'shell_exec', command: 'bun', args: ['test'] });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'shell_denied');
  assert.ok(decision.reason.includes('allowlist vazia'));
});

test('PolicyEngine permite shell quando allowAllShell=true', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Shell Test', 'L1'),
    {
      shell: {
        allowedCommands: [],
        deniedCommands: [],
        allowAllShell: true,
      },
    },
  );
  const decision = policy.evaluate({ type: 'shell_exec', command: 'bun', args: ['test'] });
  assert.equal(decision.allowed, true);
});

test('PolicyEngine bloqueia comandos shell na deny list (structural)', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Shell Deny Test', 'L1'),
    {
      shell: {
        allowedCommands: [{ command: 'git' }],
        deniedCommands: [{ command: 'rm', args: ['-rf', '/'] }],
      },
    },
  );
  const decision = policy.evaluate({ type: 'shell_exec', command: 'rm', args: ['-rf', '/'] });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'shell_denied');
});

test('PolicyEngine structural matching: git status ≠ git push', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Structural Test', 'L1'),
    {
      shell: {
        allowedCommands: [{ command: 'git', args: ['status'] }],
        deniedCommands: [],
      },
    },
  );
  const allow = policy.evaluate({ type: 'shell_exec', command: 'git', args: ['status'] });
  assert.equal(allow.allowed, true);

  const deny = policy.evaluate({ type: 'shell_exec', command: 'git', args: ['push'] });
  assert.equal(deny.allowed, false);
});

test('PolicyEngine structural matching: git (sem args) permite qualquer subcomando', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Structural Args Test', 'L1'),
    {
      shell: {
        allowedCommands: [{ command: 'git' }],
        deniedCommands: [],
      },
    },
  );
  const decision = policy.evaluate({ type: 'shell_exec', command: 'git', args: ['push', 'origin', 'main'] });
  assert.equal(decision.allowed, true);
});

// ── FAIL-CLOSED: network ────────────────────────────────────────────────

test('PolicyEngine FAIL-CLOSED: network allowlist vazia = DENY ALL', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Net Test', 'L1'),
    {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
    },
  );
  const decision = policy.evaluate({ type: 'http_request', method: 'GET', url: 'https://example.com' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'network_denied');
  assert.ok(decision.reason.includes('allowlist vazia'));
});

test('PolicyEngine permite network quando allowAllNetwork=true', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Net All Test', 'L1'),
    {
      network: {
        allowedDomains: [],
        deniedDomains: [],
        allowAllNetwork: true,
      },
    },
  );
  const decision = policy.evaluate({ type: 'http_request', method: 'GET', url: 'https://example.com' });
  assert.equal(decision.allowed, true);
});

test('PolicyEngine permite domínio na allowlist de rede', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Net Allow Test', 'L1'),
    {
      network: {
        allowedDomains: ['api.github.com'],
        deniedDomains: [],
      },
    },
  );
  const decision = policy.evaluate({ type: 'http_request', method: 'GET', url: 'https://api.github.com/repos' });
  assert.equal(decision.allowed, true);
});

test('PolicyEngine bloqueia domínios de rede na deny list', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Net Deny Test', 'L1'),
    {
      network: {
        allowedDomains: ['*'],
        deniedDomains: ['evil.com'],
      },
    },
  );
  const decision = policy.evaluate({ type: 'http_request', method: 'GET', url: 'https://evil.com/data' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'network_denied');
});

// ── Batch evaluation ────────────────────────────────────────────────

test('PolicyEngine avalia múltiplas operações via evaluateAll', () => {
  const policy = makePolicy();
  const result = policy.evaluateAll([
    { type: 'write_file', path: 'src/cli.ts' },
    { type: 'write_file', path: 'package.json' },
    { type: 'read_file', path: 'anything.txt' },
  ]);
  assert.equal(result.allAllowed, false);
  assert.equal(result.denials.length, 1);
  assert.equal(result.denials[0].violationType, 'write_deny');
});

// ── Operações desconhecidas ─────────────────────────────────────────

test('PolicyEngine retorna DENY para operação desconhecida', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'unknown_op' as any });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'denied_by_policy');
});
