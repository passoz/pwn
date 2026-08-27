import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { createDefaultContractV4, BudgetController } from '../src/core/contract-engine.js';
import { PolicyEngine } from '../src/core/policy-engine.js';
import { ToolAPI } from '../src/core/tool-api.js';

function makeToolAPI(cwd: string) {
  const contract = createDefaultContractV4('T-001', '0001', 'Tool Test', 'L1', {
    writeAllow: ['src/**', 'tests/**'],
    writeDeny: ['.git/**', 'package.json'],
  });
  const policy = new PolicyEngine(contract, {
    shell: {
      allowedCommands: [{ command: 'echo' }],
      deniedCommands: [{ command: 'rm', args: ['-rf', '/'] }],
    },
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: ['evil.com'],
    },
  });
  const budget = new BudgetController(contract);
  return new ToolAPI({ policy, budget, cwd });
}

test('ToolAPI.writeFile grava arquivo e conta tool call', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.writeFile('src/test.ts', 'export const x = 1;');
  assert.equal(result.success, true);

  const content = fs.readFileSync(path.join(tmpDir, 'src/test.ts'), 'utf8');
  assert.equal(content, 'export const x = 1;');

  const usage = tools['budget'].getUsage();
  assert.equal(usage.toolCalls, 1);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.writeFile respeita policy (bloqueia fora do allow)', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.writeFile('secret.env', 'KEY=VALUE');
  assert.equal(result.success, false);
  assert.ok(result.policyDecision);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.readFile lê arquivo e conta tool call', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'src/hello.ts'), 'hello', 'utf8');

  const tools = makeToolAPI(tmpDir);
  const result = tools.readFile('src/hello.ts');
  assert.equal(result.success, true);
  assert.equal(result.data, 'hello');

  const usage = tools['budget'].getUsage();
  assert.equal(usage.toolCalls, 1);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.deleteFile remove arquivo e conta tool call', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'src/to-delete.ts'), 'bye', 'utf8');

  const tools = makeToolAPI(tmpDir);
  const result = tools.deleteFile('src/to-delete.ts');
  assert.equal(result.success, true);
  assert.equal(fs.existsSync(path.join(tmpDir, 'src/to-delete.ts')), false);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.exec executa comando permitido e conta shell execution', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.exec('echo', ['hello']);
  assert.equal(result.success, true);
  assert.equal(result.data?.stdout.trim(), 'hello');

  const usage = tools['budget'].getUsage();
  assert.equal(usage.shellExecutions, 1);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.exec bloqueia comando não permitido', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.exec('cat', ['/etc/passwd']);
  assert.equal(result.success, false);
  assert.ok(result.policyDecision);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.httpRequest aprova domínio permitido e conta tool call', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.httpRequest('GET', 'https://example.com/api');
  assert.equal(result.success, true);

  const usage = tools['budget'].getUsage();
  assert.equal(usage.toolCalls, 1);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI.httpRequest bloqueia domínio não permitido', () => {
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = makeToolAPI(tmpDir);

  const result = tools.httpRequest('GET', 'https://other.com/api');
  assert.equal(result.success, false);
  assert.ok(result.policyDecision);

  fs.rmSync(tmpDir, { recursive: true });
});

test('ToolAPI respeita budget: bloqueia quando limite excedido', () => {
  const contract = createDefaultContractV4('T-001', '0001', 'Budget Tool Test', 'L0', {
    writeAllow: ['src/**'],
  });
  // L0 default max_tool_calls = 20, max_shell_executions = 5
  const policy = new PolicyEngine(contract);
  const budget = new BudgetController(contract);
  const tmpDir = fs.mkdtempSync('/tmp/tool-api-test-');
  const tools = new ToolAPI({ policy, budget, cwd: tmpDir });

  // Exhaust tool calls budget
  for (let i = 0; i < 20; i++) {
    tools.writeFile('src/fill.ts', `// ${i}`);
  }

  // Next tool call should be blocked by budget
  const result = tools.writeFile('src/overflow.ts', 'overflow');
  assert.equal(result.success, false);
  assert.ok(result.budgetViolation);

  fs.rmSync(tmpDir, { recursive: true });
});
