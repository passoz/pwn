import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  deriveContract,
  deriveTaskRisk,
  findV3Work,
  importV3Work,
  listV3WorkIds,
  mapTaskToCapability,
  parseCapabilityMap,
  parsePromptDigest,
  parseV3PlanMarkdown,
} from '../src/core/v3-import.js';
import { normalizeMarkers, renderTasksMarkdown } from '../src/core/plan-renderer.js';
import {
  evaluateGateDiscReq,
  evaluateGatePlanContract,
  evaluateGatePrdSpec,
  evaluateGateReqPrd,
  evaluateGateSpecPlan,
} from '../src/core/gates.js';

const PLAN_MD = `# Tasks: Migração de Autenticação

**Contract version:** 3
**Work ID:** 0004

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| jachegai-bun | \`.\` | \`bun test\` | \`bun run check\` | \`bun run check\` | \`N/A\` | \`N/A\` | \`N/A\` |

## Global gates
- [x] \`bun test\` — toda a regressão passa com exit 0.
- [x] \`bun run check\` — typecheck estrito com exit 0.

### [x] [4.1] Inicialização do Auth

**Requirement:** FR-001
**Depends on:** none
**Behavior:** inicializa o cliente de autenticação com adapter Drizzle sobre SQLite.
**Components:** jachegai-bun
**Files:** \`src/auth/index.ts\`, \`tests/auth/init.test.ts\`
**Implementation files:** \`src/auth/index.ts\`
**Test files:** \`tests/auth/init.test.ts\`

**RED:**
- \`bun test tests/auth/init.test.ts\` — exit 1 pela asserção de inicialização.

**Implementation:**
1. Configurar o adapter.
2. Exportar o singleton.

**ACs:**
- [x] \`bun test tests/auth/init.test.ts\` — a instância inicializa e expõe a API.

**Visual:** N/A
**Documentation:** N/A

### [x] [4.2] Sessões

**Requirement:** FR-002
**Depends on:** 4.1
**Behavior:** emite e revoga sessões com suporte a logout.
**Components:** jachegai-bun
**Files:** \`src/auth/session.ts\`, \`tests/auth/session.test.ts\`
**Implementation files:** \`src/auth/session.ts\`
**Test files:** \`tests/auth/session.test.ts\`

**RED:**
- \`bun test tests/auth/session.test.ts\` — exit 1 pela asserção de sessão.

**Implementation:**
1. Persistir sessão.

**ACs:**
- [x] \`bun test tests/auth/session.test.ts\` — sessão válida é emitida.

**Visual:** N/A
**Documentation:** N/A
`;

const PROMPT_MD = `# PROMPT: Migração de Autenticação

**Status:** Pronto para planejamento
**Work ID:** 0004

## Problema e resultado

**Problema:** O subsistema de autenticação atual usa gerenciamento manual de sessões e limita a padronização da pilha.
**Resultado esperado:** A aplicação integra um motor de autenticação padronizado sobre Drizzle e SQLite.

## Atores e valor

- **Cliente:** realiza login mantendo o carrinho.
- **Administrador:** opera com privilégios completos.

## Escopo

### Inclui

- \`src/auth/\` — motor de autenticação.
- \`tests/auth/\` — regressão do fluxo.

### Não inclui

- Migração de dados históricos.

## Requisitos

### Funcionais

- **FR-001:** configurar a instância de autenticação com adapter Drizzle.
- **FR-002:** emitir e revogar sessões gerenciadas.

### Qualidade e restrições

- **QR-001:** manter compatibilidade com toda a suíte existente.

## Critérios de sucesso

- **SC-001:** login emite sessão válida (FR-001, FR-002).
`;

const SYSTEM_MD = `# System Specification

## 5. Capability Map

\`\`\`text
Public Experience
Identity and Access
Customer Management
Cart and Checkout
\`\`\`

### 5.1 Capability dependency direction

- Public Experience reads approved seller data.
- Checkout depends on Customer and Cart capabilities.

## 6. Next
`;

function fixture(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-v3-'));
  mkdirSync(path.join(root, '.work'), { recursive: true });
  mkdirSync(path.join(root, '.todo'), { recursive: true });
  mkdirSync(path.join(root, '.prompts'), { recursive: true });
  mkdirSync(path.join(root, '.sources'), { recursive: true });
  mkdirSync(path.join(root, '.specs'), { recursive: true });
  writeFileSync(path.join(root, '.work', '0004.json'), JSON.stringify({ version: 1, work_id: '0004', state: 'planned' }), 'utf8');
  writeFileSync(path.join(root, '.todo', '0004-tasks.md'), PLAN_MD, 'utf8');
  writeFileSync(path.join(root, '.prompts', '0004-change.md'), PROMPT_MD, 'utf8');
  writeFileSync(path.join(root, '.sources', '0004-local.md'), '# Origem\n\nPedido original.\n', 'utf8');
  writeFileSync(path.join(root, '.specs', 'system.md'), SYSTEM_MD, 'utf8');
  return root;
}

test('parseV3PlanMarkdown extrai tasks, tabela estendida e gates', () => {
  const plan = parseV3PlanMarkdown(PLAN_MD, '0004');
  assert.equal(plan.title, 'Migração de Autenticação');
  assert.equal(plan.work_id, '0004');
  assert.equal(plan.tasks.length, 2);
  assert.equal(plan.global_gates.length, 2);
  assert.equal(plan.components[0].name, 'jachegai-bun');
  assert.equal(plan.components[0].regression, 'bun test');
  assert.equal(plan.components[0].health, 'N/A');

  const [first, second] = plan.tasks;
  assert.equal(first.id, '4.1');
  assert.equal(first.requirement_id, 'FR-001');
  assert.deepEqual(first.depends_on, []);
  assert.deepEqual(first.implementation_files, ['src/auth/index.ts']);
  assert.deepEqual(first.test_files, ['tests/auth/init.test.ts']);
  assert.equal(first.red.command, 'bun test tests/auth/init.test.ts');
  assert.equal(first.acceptance_criteria[0].command, 'bun test tests/auth/init.test.ts');
  assert.equal(first.implementation_steps.length, 2);
  assert.equal(first.status, 'done');
  assert.equal(first.contract_id, 'CTR-001');
  assert.deepEqual(second.depends_on, ['4.1']);
  assert.equal(second.contract_id, 'CTR-002');
});

test('plan importado dá round-trip byte-a-byte no markdown v3 (drift guard não bloqueia)', () => {
  const plan = parseV3PlanMarkdown(PLAN_MD, '0004');
  const rendered = renderTasksMarkdown(plan);
  assert.equal(
    normalizeMarkers(rendered),
    normalizeMarkers(PLAN_MD),
    'render(parse(md)) deve ser idêntico ao markdown v3 (ignorando marcadores)',
  );
});

test('parsePromptDigest extrai problema, solução, requisitos, atores e escopo', () => {
  const digest = parsePromptDigest(PROMPT_MD);
  assert.match(digest.problem, /gerenciamento manual de sessões/);
  assert.match(digest.solution, /motor de autenticação padronizado/);
  assert.deepEqual(digest.actors, ['Cliente', 'Administrador']);
  assert.deepEqual(digest.inScope, ['`src/auth/` — motor de autenticação.', '`tests/auth/` — regressão do fluxo.']);
  assert.deepEqual(digest.outOfScope, ['Migração de dados históricos.']);
  assert.ok(digest.requirements.some((entry) => entry.id === 'FR-001'));
  assert.ok(digest.constraints.some((entry) => entry.startsWith('QR-001')));
});

test('parseCapabilityMap lê as capabilities e regras da system spec', () => {
  const map = parseCapabilityMap(SYSTEM_MD);
  assert.equal(map.capabilities.length, 4);
  assert.equal(map.capabilities[1].name, 'Identity and Access');
  assert.equal(map.capabilities[1].id, 'CAP-002');
  assert.equal(map.rules.length, 2);
  assert.equal(map.rules[0].id, 'BR-001');
});

test('deriveContract usa comandos e escopo reais da task', () => {
  const plan = parseV3PlanMarkdown(PLAN_MD, '0004');
  const contract = deriveContract(plan, plan.tasks[0], '0004', 'L2');
  assert.equal(contract.contract_version, '4.0');
  assert.equal(contract.risk.level, 'L2');
  assert.equal(contract.validation_strategy, 'tdd-strict');
  assert.ok(contract.acceptance_contract.commands.includes('bun test tests/auth/init.test.ts'));
  assert.ok(contract.acceptance_contract.commands.includes('bun run check'));
  assert.deepEqual(contract.scope_contract.write_allow, [
    'src/auth/index.ts',
    'tests/auth/init.test.ts',
  ]);
  assert.ok(contract.scope_contract.write_deny.includes('package.json'));
  assert.ok(contract.behavioral_contract.scenarios.length > 0);
});

test('listV3WorkIds e findV3Work localizam os artefatos v3', () => {
  const root = fixture();
  try {
    assert.deepEqual(listV3WorkIds(root), ['0004']);
    const files = findV3Work(root, '0004');
    assert.ok(files);
    assert.equal(path.basename(files.planPath), '0004-tasks.md');
    assert.equal(path.basename(files.promptPath ?? ''), '0004-change.md');
    assert.equal(findV3Work(root, '9999'), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('importV3Work gera plan.json e contratos sem tocar nos artefatos v3', () => {
  const root = fixture();
  try {
    const result = importV3Work({ rootDir: root, workId: '0004' });
    const workDir = path.join(root, '.pwn', 'work', '0004');

    assert.ok(existsSync(path.join(workDir, 'plan.json')));
    assert.ok(existsSync(path.join(workDir, 'CTR-001.json')));
    assert.ok(existsSync(path.join(workDir, 'CTR-002.json')));
    assert.ok(result.generated.includes('plan.json'));

    const plan = JSON.parse(readFileSync(path.join(workDir, 'plan.json'), 'utf8'));
    assert.equal(plan.tasks.length, 2);
    assert.ok(plan.tasks.every((task: { spec_reference: string }) => task.spec_reference.startsWith('CAP-')));

    // Segunda execução é no-op sem --force.
    const again = importV3Work({ rootDir: root, workId: '0004' });
    assert.equal(again.generated.length, 0);
    assert.ok(again.skipped.every((entry) => entry.reason.includes('já existe')));

    // O markdown v3 permanece intacto.
    assert.equal(readFileSync(path.join(root, '.todo', '0004-tasks.md'), 'utf8'), PLAN_MD);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('importV3Work --gate-chain produz uma cadeia que passa nos 5 gates', () => {
  const root = fixture();
  try {
    const result = importV3Work({ rootDir: root, workId: '0004', gateChain: true, force: true });
    const workDir = path.join(root, '.pwn', 'work', '0004');
    for (const name of ['discovery.json', 'requirements.json', 'prd.json', 'spec.json', 'traceability-matrix.json']) {
      assert.ok(result.generated.includes(name), `faltou ${name}`);
    }

    const gates = [
      evaluateGateDiscReq('0004', workDir),
      evaluateGateReqPrd('0004', workDir),
      evaluateGatePrdSpec('0004', workDir),
      evaluateGateSpecPlan('0004', workDir),
      evaluateGatePlanContract('0004', workDir),
    ];
    for (const gate of gates) {
      assert.notEqual(gate.result, 'blocked', `${gate.gate} bloqueou: ${JSON.stringify(gate.findings)}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('deriveTaskRisk classifica superfícies sensíveis como L3 e docs como L1', () => {
  const base = parseV3PlanMarkdown(PLAN_MD, '0004').tasks[0];
  assert.equal(deriveTaskRisk({ ...base, title: 'Validar sessão e credenciais de login' }), 'L3');
  assert.equal(deriveTaskRisk({ ...base, title: 'Verificação de assinatura HMAC em webhooks de pagamento' }), 'L3');
  const docsTask = {
    ...base,
    title: 'Atualizar README e documentação do módulo',
    behavior: 'descreve o formato do changelog',
    files: ['README.md', 'docs/modulo.md'],
    red: { command: 'bun test', description: 'validação de documentação' },
    acceptance_criteria: [{ command: 'bun test', description: 'documentação publicada' }],
  };
  assert.equal(deriveTaskRisk(docsTask), 'L1');
  const domainTask = {
    ...base,
    title: 'Refatorar cálculo de saldo do domínio',
    behavior: 'consolida lançamentos e valida o saldo',
    files: ['src/domain/money.ts'],
    red: { command: 'bun test tests/domain/money.test.ts', description: 'saldo incorreto antes da implementação' },
    acceptance_criteria: [{ command: 'bun test tests/domain/money.test.ts', description: 'saldo consolidado correto' }],
  };
  assert.equal(deriveTaskRisk(domainTask), 'L2');
  // L4 nunca é automático: exige decisão humana.
  assert.notEqual(deriveTaskRisk({ ...base, title: 'Migração de autenticação' }), 'L4');
});

test('mapTaskToCapability usa RED/ACs e normaliza acento/plural', () => {
  const map = parseCapabilityMap(SYSTEM_MD);
  const plan = parseV3PlanMarkdown(PLAN_MD, '0004');

  // "healthz"/"readyz" só aparecem no RED/AC, não no título/behavior.
  const scaffoldTask = {
    ...plan.tasks[0],
    title: 'Scaffold de projeto e persistência SQLite',
    behavior: 'sobe o runtime com migrações versionadas',
    files: ['src/config/env.ts'],
    red: { command: 'bun test tests/http/api.test.ts', description: 'exit 1 porque /healthz e /readyz ainda não respondem 200' },
    acceptance_criteria: [{ command: 'bun test', description: '/healthz e /readyz retornam 200' }],
  };
  // SYSTEM_MD não tem Observability; usa o mapa real do projeto apenas se existir.
  assert.ok(mapTaskToCapability(scaffoldTask, map).id.startsWith('CAP-'));

  // Acento/plural: "endereços" deve casar com "address/endereco" via aliases de Customer.
  const customerTask = { ...plan.tasks[0], title: 'Exportação de dados e endereços do titular (LGPD)', behavior: '', files: [], red: { command: 'bun test', description: '' }, acceptance_criteria: [{ command: 'bun test', description: '' }] };
  const mapped = mapTaskToCapability(customerTask, map);
  assert.ok(mapped.score > 0, 'deve casar por palavra-chave, não cair no fallback');
});

test('importV3Work --risk auto congela risco por task nos contratos', () => {
  const root = fixture();
  try {
    const result = importV3Work({ rootDir: root, workId: '0004', risk: 'auto', force: true });
    assert.equal(result.riskMapping.length, 2);
    assert.deepEqual(result.riskMapping.map((entry) => entry.risk), ['L3', 'L3']);

    const ctr = JSON.parse(readFileSync(path.join(root, '.pwn', 'work', '0004', 'CTR-001.json'), 'utf8'));
    assert.equal(ctr.risk.level, 'L3');

    const plan = JSON.parse(readFileSync(path.join(root, '.pwn', 'work', '0004', 'plan.json'), 'utf8'));
    for (const task of plan.tasks) {
      assert.ok(task.spec_reference, 'spec_reference não pode ser vazio');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
