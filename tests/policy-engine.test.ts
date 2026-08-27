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

test('PolicyEngine bloqueia comandos shell na deny list', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'shell_exec', command: 'rm -rf /' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'shell_denied');
  assert.equal(decision.domain, 'shell');
});

test('PolicyEngine permite comandos shell quando allowlist está vazia', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'shell_exec', command: 'bun test' });
  assert.equal(decision.allowed, true);
  assert.equal(decision.domain, 'shell');
});

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

test('PolicyEngine bloqueia domínios de rede na deny list', () => {
  const policy = new PolicyEngine(
    createDefaultContractV4('T-001', '0001', 'Net Test', 'L1'),
    {
      network: {
        allowedDomains: [],
        deniedDomains: ['evil.com'],
      },
    },
  );
  const decision = policy.evaluate({ type: 'http_request', method: 'GET', url: 'https://evil.com/data' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'network_denied');
});

test('PolicyEngine retorna DENY para operação desconhecida', () => {
  const policy = makePolicy();
  const decision = policy.evaluate({ type: 'unknown_op' as any });
  assert.equal(decision.allowed, false);
  assert.equal(decision.violationType, 'denied_by_policy');
});
