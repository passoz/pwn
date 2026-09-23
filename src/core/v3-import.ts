import fs from 'node:fs';
import path from 'node:path';
import { createDefaultContractV4, type RiskLevel, type TaskContractV4 } from './contract-engine.js';
import type { Plan, PlanAC, PlanComponent, PlanTask } from './plan-renderer.js';

// ── v3 → pwn import ──────────────────────────────────────────
//
// Projects that were governed by the v3 pack keep their artifacts in
// `.work/<id>.json`, `.todo/<id>-tasks.md`, `.prompts/<id>-change.md`,
// `.sources/<id>-*.md` and `.specs/system.md`. PWN governs
// `.pwn/work/<id>/` with a canonical `plan.json` plus frozen `CTR-*.json`.
//
// This module translates the v3 layout into the pwn layout. It only READS
// the v3 artifacts and never deletes or rewrites them.

const TASK_HEADING = /^### \[([ x!])\] \[(\d+\.\d+)\] (.+)$/;
const FIELD = /^\*\*([^:*]+):\*\*\s*(.*)$/;
const LIST_BULLET = /^-\s*(?:\[([ xX!])\]\s*)?`([^`]+)`\s*(.*)$/;
const NUMBERED_STEP = /^\d+\.\s+(.*)$/;
const GATE_LINE = /^-\s*\[[ xX!]\]\s*(.+)$/;
const REQUIREMENT_BULLET = /^-\s*\*\*((?:FR|QR|EC|SC|A|US)-\d{3}):\*\*\s*(.*)$/;
const PROMPT_SECTION = /^(#{2,3})\s+(.*)$/;
const ACTOR_BULLET = /^\*\*([^:*]+):\*\*\s*(.*)$/;

// ── small helpers ──────────────────────────────────────────────────

function stripTicks(value: string): string {
  return value.trim().replace(/^`+|`+$/g, '').trim();
}

function inlineCode(value: string): string[] {
  return [...value.matchAll(/`([^`]+)`/g)].map((match) => match[1].trim());
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((part) => stripTicks(part))
    .filter((part) => part.length > 0 && part !== 'N/A');
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

interface CommandBullet {
  command: string;
  description: string;
  checked: boolean;
}

function parseCommandBullet(line: string): CommandBullet | null {
  const match = line.match(LIST_BULLET);
  if (!match) return null;
  const rest = match[3].trim().replace(/^[—–-]\s*/, '');
  return { command: match[2].trim(), description: rest, checked: match[1] === 'x' };
}

function splitTableRow(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim());
}

function parseTableAfter(lines: string[], heading: string): { headers: string[]; rows: string[][] } | null {
  const start = lines.indexOf(heading);
  if (start === -1) return null;
  let index = start + 1;
  while (index < lines.length && !lines[index].startsWith('|')) {
    if (lines[index].startsWith('## ')) return null;
    index += 1;
  }
  if (index >= lines.length) return null;
  const headers = splitTableRow(lines[index]);
  index += 1;
  if (index < lines.length && /^\|[\s:|-]+\|$/.test(lines[index])) index += 1;
  const rows: string[][] = [];
  for (; index < lines.length && lines[index].startsWith('|'); index += 1) {
    rows.push(splitTableRow(lines[index]));
  }
  return { headers, rows };
}

// ── plan markdown parsing ──────────────────────────────────────────

function parseComponents(lines: string[]): PlanComponent[] {
  const table = parseTableAfter(lines, '## Execution contract');
  if (!table) return [];
  const indexOf = (name: string): number =>
    table.headers.findIndex((header) => header.toLowerCase() === name.toLowerCase());

  const componentIndex = indexOf('component');
  const purposeIndex = indexOf('purpose');
  const assurance: Array<[keyof PlanComponent, number]> = [
    ['root', indexOf('root')],
    ['regression', indexOf('regression')],
    ['lint', indexOf('lint')],
    ['build', indexOf('build')],
    ['security', indexOf('security')],
    ['dev', indexOf('dev')],
    ['health', indexOf('health')],
  ];

  return table.rows.map((row) => {
    const component: PlanComponent = {
      name: componentIndex >= 0 ? stripTicks(row[componentIndex] ?? '') : stripTicks(row[0] ?? ''),
      purpose: purposeIndex >= 0 ? stripTicks(row[purposeIndex] ?? '') : '',
    };
    for (const [key, column] of assurance) {
      if (column >= 0) component[key] = stripTicks(row[column] ?? '') || 'N/A';
    }
    return component;
  });
}

function parseGlobalGates(lines: string[]): string[] {
  const start = lines.indexOf('## Global gates');
  if (start === -1) return [];
  const gates: string[] = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.startsWith('## ') || line.startsWith('### ')) break;
    const match = line.match(GATE_LINE);
    if (match) gates.push(match[1].trim());
  }
  return gates;
}

function collectBullets(block: string[], from: number): CommandBullet[] {
  const bullets: CommandBullet[] = [];
  for (let index = from; index < block.length; index += 1) {
    const line = block[index];
    if (line.trim() === '') {
      if (bullets.length > 0) break;
      continue;
    }
    const bullet = parseCommandBullet(line);
    if (!bullet) break;
    bullets.push(bullet);
  }
  return bullets;
}

function parseTasks(lines: string[], workId: string): PlanTask[] {
  const headings: Array<{ index: number; match: RegExpMatchArray }> = [];
  lines.forEach((line, index) => {
    const match = line.match(TASK_HEADING);
    if (match) headings.push({ index, match });
  });

  let contractCounter = 0;
  return headings.map((heading, position) => {
    const start = heading.index;
    const end = position + 1 < headings.length ? headings[position + 1].index : lines.length;
    const block = lines.slice(start + 1, end);

    const fields = new Map<string, string>();
    let redIndex = -1;
    let implementationIndex = -1;
    let acsIndex = -1;
    block.forEach((line, index) => {
      const field = line.match(FIELD);
      if (field) {
        const name = field[1].trim();
        if (!fields.has(name)) fields.set(name, field[2].trim());
        if (name === 'RED') redIndex = index;
        if (name === 'Implementation') implementationIndex = index;
        if (name === 'ACs') acsIndex = index;
      }
    });

    const red = redIndex >= 0 ? collectBullets(block, redIndex + 1)[0] ?? null : null;
    const acceptance = acsIndex >= 0 ? collectBullets(block, acsIndex + 1) : [];
    const steps: string[] = [];
    if (implementationIndex >= 0) {
      for (let index = implementationIndex + 1; index < block.length; index += 1) {
        const match = block[index].match(NUMBERED_STEP);
        if (!match) {
          if (steps.length > 0 && block[index].trim() === '') break;
          continue;
        }
        steps.push(match[1].trim());
      }
    }

    const status = heading.match[1] === 'x' ? 'done' : heading.match[1] === '!' ? 'blocked' : 'pending';
    contractCounter += 1;
    const acceptanceCriteria: PlanAC[] = acceptance.length > 0
      ? acceptance.map((entry) => ({ command: entry.command, description: entry.description }))
      : [{ command: 'bun test', description: `Aceitação de ${heading.match[2]}` }];

    const visual = fields.get('Visual');
    const documentation = fields.get('Documentation');

    return {
      id: heading.match[2],
      title: heading.match[3].trim(),
      requirement_id: stripTicks(fields.get('Requirement') ?? `FR-${String(contractCounter).padStart(3, '0')}`),
      depends_on: (() => {
        const value = stripTicks(fields.get('Depends on') ?? 'none');
        return value === 'none' || value === '' ? [] : splitList(value.replaceAll('`', ''));
      })(),
      behavior: fields.get('Behavior') ?? '',
      components: splitList(fields.get('Components') ?? ''),
      files: splitList(fields.get('Files') ?? ''),
      implementation_files: splitList(fields.get('Implementation files') ?? ''),
      test_files: splitList(fields.get('Test files') ?? ''),
      red: {
        command: red?.command ?? 'bun test',
        description: red?.description ?? `RED de ${heading.match[2]}`,
      },
      implementation_steps: steps.length > 0 ? steps : ['Implementar o comportamento declarado'],
      acceptance_criteria: acceptanceCriteria,
      visual: visual === 'REQUIRED' ? 'REQUIRED' : 'N/A',
      documentation: documentation === 'REQUIRED' ? 'REQUIRED' : 'N/A',
      spec_reference: '',
      contract_id: `CTR-${String(contractCounter).padStart(3, '0')}`,
      complexity: 'standard',
      status,
    } satisfies PlanTask;
  });
}

/**
 * Parse a v3 task-contract markdown plan into the canonical Plan model.
 * `workId` is only used as a fallback title.
 */
export function parseV3PlanMarkdown(markdown: string, workId: string): Plan {
  const lines = markdown.split(/\r?\n/);
  const titleLine = lines.find((line) => line.startsWith('# Tasks: '));
  const title = titleLine ? titleLine.slice('# Tasks: '.length).trim() : `Work ${workId}`;
  return {
    work_id: workId,
    title,
    components: parseComponents(lines),
    global_gates: parseGlobalGates(lines),
    tasks: parseTasks(lines, workId),
  };
}

// ── prompt / source digest ─────────────────────────────────────────

export interface PromptDigest {
  problem: string;
  solution: string;
  requirements: Array<{ id: string; statement: string }>;
  inScope: string[];
  outOfScope: string[];
  actors: string[];
  successCriteria: string[];
  constraints: string[];
}

function parseBullets(lines: string[], heading: string): string[] {
  const start = lines.indexOf(heading);
  if (start === -1) return [];
  const values: string[] = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (PROMPT_SECTION.test(line)) break;
    if (line.startsWith('- ')) values.push(line.slice(2).trim());
  }
  return values;
}

function fieldIn(lines: string[], name: string): string | null {
  const prefix = `**${name}:**`;
  for (const line of lines) {
    if (line.startsWith(prefix)) return line.slice(prefix.length).trim();
  }
  return null;
}

/**
 * Extract the authored content of a v3 change prompt. Every value comes from the
 * prompt text itself; nothing is synthesized.
 */
export function parsePromptDigest(markdown: string): PromptDigest {
  const lines = markdown.split(/\r?\n/);

  const requirements = lines
    .map((line) => line.match(REQUIREMENT_BULLET))
    .filter((match): match is RegExpMatchArray => Boolean(match))
    .map((match) => ({ id: match[1], statement: match[2].trim() }));

  const functional = requirements.filter((entry) => entry.id.startsWith('FR-'));
  const quality = requirements.filter((entry) => entry.id.startsWith('QR-'));
  const success = requirements.filter((entry) => entry.id.startsWith('SC-'));

  const actors = parseBullets(lines, '## Atores e valor')
    .map((line) => line.match(ACTOR_BULLET)?.[1]?.trim())
    .filter((name): name is string => Boolean(name));

  const inScope = parseBullets(lines, '### Inclui');
  const outOfScope = parseBullets(lines, '### Não inclui');

  return {
    problem: fieldIn(lines, 'Problema') ?? '',
    solution: fieldIn(lines, 'Resultado esperado') ?? '',
    requirements,
    inScope,
    outOfScope,
    actors,
    successCriteria: success.map((entry) => `${entry.id}: ${entry.statement}`),
    constraints: quality.map((entry) => `${entry.id}: ${entry.statement}`),
  };
}

// ── v3 work discovery ──────────────────────────────────────────────

export interface V3WorkFiles {
  workId: string;
  manifestPath: string | null;
  planPath: string;
  promptPath: string | null;
  sourcePath: string | null;
  systemSpecPath: string | null;
}

function firstMatch(directory: string, expression: RegExp): string | null {
  if (!fs.existsSync(directory)) return null;
  const entry = fs.readdirSync(directory).find((name) => expression.test(name));
  return entry ? path.join(directory, entry) : null;
}

/** Locate the v3 artifacts of a Work inside a project root. */
export function findV3Work(rootDir: string, workId: string): V3WorkFiles | null {
  const planPath = path.join(rootDir, '.todo', `${workId}-tasks.md`);
  if (!fs.existsSync(planPath)) return null;
  const manifestPath = path.join(rootDir, '.work', `${workId}.json`);
  const systemSpec = path.join(rootDir, '.specs', 'system.md');
  return {
    workId,
    manifestPath: fs.existsSync(manifestPath) ? manifestPath : null,
    planPath,
    promptPath: firstMatch(path.join(rootDir, '.prompts'), new RegExp(`^${workId}-.*\\.md$`)),
    sourcePath: firstMatch(path.join(rootDir, '.sources'), new RegExp(`^${workId}-.*\\.md$`)),
    systemSpecPath: fs.existsSync(systemSpec) ? systemSpec : null,
  };
}

/** Work IDs present in the v3 layout (`.todo/NNNN-tasks.md`). */
export function listV3WorkIds(rootDir: string): string[] {
  const directory = path.join(rootDir, '.todo');
  if (!fs.existsSync(directory)) return [];
  return fs
    .readdirSync(directory)
    .map((name) => name.match(/^(\d{4})-tasks\.md$/)?.[1])
    .filter((id): id is string => Boolean(id))
    .sort();
}

// ── contracts ──────────────────────────────────────────────────────

function gateCommands(plan: Plan): string[] {
  return plan.global_gates.flatMap((gate) => inlineCode(gate)).filter((command) => command.length > 0);
}

/**
 * Derive a frozen V4 contract from an imported task. Every command and path comes
 * from the task's own RED/AC/Files declarations (plus the plan's global gates).
 */
export function deriveContract(plan: Plan, task: PlanTask, workId: string, risk: RiskLevel): TaskContractV4 {
  const writeAllow = unique([
    ...task.implementation_files,
    ...task.test_files,
    ...task.files,
  ]);
  const commands = unique([
    ...task.acceptance_criteria.map((entry) => entry.command),
    ...gateCommands(plan),
  ]);

  const scenarios = task.acceptance_criteria.map((entry, index) => ({
    id: `SCENARIO-${task.id}-${String(index + 1).padStart(2, '0')}`,
    given: `Dado o comportamento declarado: ${task.behavior || task.title}`,
    when: `Quando \`${entry.command}\` é executado`,
    then: `Então ${entry.description || 'a aceitação é satisfeita'}`,
  }));

  const contract = createDefaultContractV4(task.id, workId, task.title, risk, {
    writeAllow: writeAllow.length > 0 ? writeAllow : ['src/**', 'tests/**'],
    scenarios: scenarios.length > 0 ? scenarios : undefined,
  });

  contract.validation_strategy = 'tdd-strict';
  contract.acceptance_contract.commands = commands.length > 0 ? commands : ['bun test'];
  contract.change_contract.target_files = writeAllow;
  contract.change_contract.affected_components = task.components.length > 0 ? task.components : ['jachegai-bun'];
  contract.behavioral_contract.scenarios = scenarios;
  contract.scope_contract.out_of_scope = task.files.length > 0
    ? [`Arquivos fora de: ${writeAllow.join(', ')}`]
    : contract.scope_contract.out_of_scope;

  return contract;
}

// ── capability mapping (best effort, reported) ─────────────────────

export interface Capability {
  id: string;
  name: string;
  description: string;
  rules: string[];
}

export interface CapabilityMap {
  capabilities: Capability[];
  rules: Array<{ id: string; statement: string }>;
}

/** Parse the "Capability Map" text block of a v3 system spec. */
export function parseCapabilityMap(systemSpec: string): CapabilityMap {
  const lines = systemSpec.split(/\r?\n/);
  const capabilities: Capability[] = [];
  const rules: Array<{ id: string; statement: string }> = [];

  const mapStart = lines.findIndex((line) => /^##\s+\d+\.\s+Capability Map/.test(line));
  if (mapStart !== -1) {
    let index = mapStart + 1;
    while (index < lines.length && !lines[index].startsWith('```')) index += 1;
    index += 1;
    let counter = 0;
    for (; index < lines.length && !lines[index].startsWith('```'); index += 1) {
      const name = lines[index].trim();
      if (!name) continue;
      counter += 1;
      capabilities.push({
        id: `CAP-${String(counter).padStart(3, '0')}`,
        name,
        description: `Capacidade "${name}" definida na system spec do projeto.`,
        rules: [],
      });
    }
  }

  const depStart = lines.findIndex((line) => /^###\s+[\d.]+\.?\s*Capability dependency/.test(line));
  if (depStart !== -1) {
    let counter = 0;
    for (let index = depStart + 1; index < lines.length; index += 1) {
      const line = lines[index];
      if (line.startsWith('## ') || line.startsWith('### ')) break;
      if (!line.startsWith('- ')) continue;
      counter += 1;
      rules.push({ id: `BR-${String(counter).padStart(3, '0')}`, statement: line.slice(2).trim() });
    }
  }

  return { capabilities, rules };
}

function tokens(value: string): string[] {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((token) => (token.length > 4 && token.endsWith('s') ? token.slice(0, -1) : token))
    .filter((token) => token.length > 3);
}

/**
 * Explicit, reviewable keyword aliases per capability name. Portuguese and English
 * work vocabulary is mapped onto the English capability names of the system spec.
 * Anything not covered here falls back to plain token overlap.
 */
const CAPABILITY_ALIASES: Array<{ capability: RegExp; words: string[] }> = [
  { capability: /identity|access/i, words: ['auth', 'autenticacao', 'authentication', 'login', 'logout', 'session', 'sessao', 'signin', 'signup', 'cadastro', 'registro', 'registro', 'rbac', 'role', 'papel', 'credential', 'credencial', 'senha', 'password', 'cookie', 'principal', 'better'] },
  { capability: /public experience/i, words: ['publico', 'public', 'visitor', 'visitante', 'landing', 'discovery', 'descoberta'] },
  { capability: /customer/i, words: ['cliente', 'customer', 'profile', 'perfil', 'address', 'endereco', 'favorito', 'favorite', 'privacidade', 'privacy', 'lgpd', 'titular', 'exportacao', 'export'] },
  { capability: /seller/i, words: ['lojista', 'seller', 'store', 'loja', 'vendedor'] },
  { capability: /catalog/i, words: ['catalogo', 'catalog', 'produto', 'product'] },
  { capability: /inventory/i, words: ['estoque', 'inventory', 'inventario', 'stock'] },
  { capability: /cart|checkout/i, words: ['carrinho', 'cart', 'checkout', 'cesta', 'basket'] },
  { capability: /order/i, words: ['pedido', 'order', 'status', 'entrega', 'lifecycle', 'ciclo'] },
  { capability: /courier|delivery/i, words: ['entregador', 'courier', 'delivery', 'entrega', 'motoboy', 'coleta', 'pickup'] },
  { capability: /payment/i, words: ['pagamento', 'payment', 'cobranca', 'transacao'] },
  { capability: /fee|invoice/i, words: ['taxa', 'fee', 'fatura', 'invoice', 'comissao'] },
  { capability: /support/i, words: ['suporte', 'support', 'ticket', 'chamado', 'disputa'] },
  { capability: /administration/i, words: ['admin', 'administrador', 'administracao', 'moderacao', 'moderation'] },
  { capability: /audit/i, words: ['auditoria', 'audit', 'historico', 'history', 'append'] },
  { capability: /notification/i, words: ['notificacao', 'notification', 'email', 'push', 'aviso'] },
  { capability: /background work/i, words: ['job', 'worker', 'fila', 'queue', 'background', 'assincrono', 'async'] },
  { capability: /file storage/i, words: ['arquivo', 'file', 'upload', 'storage', 'imagem', 'image'] },
  { capability: /observability/i, words: ['observabilidade', 'observability', 'health', 'healthz', 'readyz', 'metrica', 'metrics', 'log', 'log'] },
];

/**
 * Text used to match a task against the capability map: title, behavior, touched
 * files, and — crucially — the RED + acceptance commands, where the observable
 * outcome (e.g. `/healthz`) usually lives.
 */
function capabilityHaystack(task: PlanTask): string {
  return [
    task.title,
    task.behavior,
    task.components.join(' '),
    task.files.join(' '),
    task.red.command,
    task.red.description,
    ...task.acceptance_criteria.flatMap((entry) => [entry.command, entry.description]),
  ].join(' ');
}

function normalizeText(value: string): string {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

/**
 * Explicit, reviewable risk classification used by `--risk auto`.
 *
 * - L3: security-sensitive surfaces (auth, sessions, credentials, payments,
 *   webhooks, CORS/CSRF/rate limiting, privacy/LGPD, authorization middleware).
 * - L1: documentation/formatting only.
 * - L2: everything else.
 *
 * L4 is NEVER auto-assigned: it suspends the run for human review, which must be
 * a deliberate operator decision, not a heuristic.
 */
const RISK_L3_KEYWORDS = [
  'auth', 'autentica', 'login', 'signin', 'signup', 'password', 'senha', 'credencial',
  'sessao', 'session', 'token', 'cookie', 'rbac', 'permissao', 'autorizacao', 'papel',
  'seguranca', 'security', 'hardening', 'webhook', 'hmac', 'assinatura', 'signature',
  'pagamento', 'payment', 'estorno', 'refund', 'crypto', 'secret', 'csrf', 'cors',
  'rate limit', 'rate-limit', 'privacidade', 'privacy', 'lgpd', 'middleware', 'bcrypt',
  'argon2', 'hash', 'csrf', 'oauth',
];

const RISK_L1_KEYWORDS = [
  'readme', 'documentacao', 'documentation', 'comentario', 'formatacao', 'estilo',
  'tipografia', 'copy', 'changelog', 'licenca', 'license',
];

/** Classify an imported task's risk from its own declarations. */
export function deriveTaskRisk(task: PlanTask): RiskLevel {
  const text = normalizeText(capabilityHaystack(task));
  if (RISK_L3_KEYWORDS.some((keyword) => text.includes(keyword))) return 'L3';
  if (RISK_L1_KEYWORDS.some((keyword) => text.includes(keyword))) return 'L1';
  return 'L2';
}

/** Best-effort mapping of a task to a capability id from the map. */
export function mapTaskToCapability(task: PlanTask, map: CapabilityMap): { id: string; score: number } {
  const haystack = tokens(capabilityHaystack(task));
  let best = { id: map.capabilities[0]?.id ?? 'CAP-001', score: 0 };
  for (const capability of map.capabilities) {
    const needles = tokens(capability.name);
    let score = needles.filter((needle) => haystack.includes(needle)).length;
    const alias = CAPABILITY_ALIASES.find((entry) => entry.capability.test(capability.name));
    if (alias) score += alias.words.filter((word) => haystack.includes(word)).length * 2;
    if (score > best.score) best = { id: capability.id, score };
  }
  return best;
}

// ── the import ─────────────────────────────────────────────────────

export interface V3ImportOptions {
  rootDir: string;
  workId: string;
  /** Overwrite existing `.pwn/work/<id>` artifacts. */
  force?: boolean;
  /** Risk frozen into the derived contracts. `'auto'` classifies per task. Default L2. */
  risk?: RiskLevel | 'auto';
  /** Also derive the documental gate chain (discovery/requirements/prd/spec/traceability). */
  gateChain?: boolean;
}

export interface V3ImportResult {
  workId: string;
  workDir: string;
  generated: string[];
  skipped: Array<{ file: string; reason: string }>;
  warnings: string[];
  capabilityMapping: Array<{ task: string; capability: string; score: number }>;
  riskMapping: Array<{ task: string; risk: RiskLevel }>;
  plan: Plan;
}

function writeJson(filePath: string, value: unknown, generated: string[], skipped: V3ImportResult['skipped'], force: boolean): void {
  if (fs.existsSync(filePath) && !force) {
    skipped.push({ file: path.basename(filePath), reason: 'já existe (use --force para sobrescrever)' });
    return;
  }
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  generated.push(path.basename(filePath));
}

/**
 * Translate a v3 Work into pwn canonical artifacts under
 * `.pwn/work/<id>/`. Reads only; never touches the v3 files.
 */
export function importV3Work(options: V3ImportOptions): V3ImportResult {
  const { rootDir, workId, force = false, risk = 'L2', gateChain = false } = options;
  const files = findV3Work(rootDir, workId);
  if (!files) {
    throw new Error(`Work v3 ${workId} não encontrado: falta .todo/${workId}-tasks.md em ${rootDir}`);
  }

  const plan = parseV3PlanMarkdown(fs.readFileSync(files.planPath, 'utf8'), workId);
  if (plan.tasks.length === 0) {
    throw new Error(`Nenhuma task canônica encontrada em ${files.planPath}`);
  }

  const systemSpec = files.systemSpecPath ? fs.readFileSync(files.systemSpecPath, 'utf8') : '';
  const capabilityMap = parseCapabilityMap(systemSpec);
  const prompt = files.promptPath ? parsePromptDigest(fs.readFileSync(files.promptPath, 'utf8')) : null;
  const source = files.sourcePath ? fs.readFileSync(files.sourcePath, 'utf8') : '';

  const warnings: string[] = [];
  const capabilityMapping: V3ImportResult['capabilityMapping'] = [];
  const riskMapping: V3ImportResult['riskMapping'] = [];
  for (const task of plan.tasks) {
    const mapped = mapTaskToCapability(task, capabilityMap);
    task.spec_reference = mapped.id;
    capabilityMapping.push({ task: task.id, capability: mapped.id, score: mapped.score });
    if (mapped.score === 0) {
      warnings.push(`Task ${task.id}: nenhuma capability casou por palavra-chave; usando ${mapped.id} — revise o spec_reference.`);
    }
    riskMapping.push({ task: task.id, risk: risk === 'auto' ? deriveTaskRisk(task) : risk });
  }

  const workDir = path.join(rootDir, '.pwn', 'work', workId);
  fs.mkdirSync(workDir, { recursive: true });

  const generated: string[] = [];
  const skipped: V3ImportResult['skipped'] = [];
  const now = new Date().toISOString();
  const write = (name: string, value: unknown): void =>
    writeJson(path.join(workDir, name), value, generated, skipped, force);

  // 1. Canonical plan (schema: plan.schema.json).
  write('plan.json', { $schema: '../../../schemas/plan.schema.json', ...plan });

  // 2. Frozen V4 contracts (risk per task when `--risk auto`).
  for (const task of plan.tasks) {
    const taskRisk = riskMapping.find((entry) => entry.task === task.id)!.risk;
    const contract = deriveContract(plan, task, workId, taskRisk);
    write(`${task.contract_id}.json`, contract);
  }

  if (!gateChain) {
    return { workId, workDir, generated, skipped, warnings, capabilityMapping, riskMapping, plan };
  }

  // 3. Documental gate chain, derived from the prompt/plan/system spec.
  const requirements = plan.tasks.map((task) => ({
    id: task.requirement_id,
    title: task.title,
    acceptance_criteria: task.acceptance_criteria.map((entry) => `${entry.command} — ${entry.description}`),
  }));

  const problem = prompt?.problem && prompt.problem.length >= 20
    ? prompt.problem
    : `O Work ${workId} ("${plan.title}") precisa ser executado sob governança determinística do PWN.`;
  const solution = prompt?.solution && prompt.solution.length >= 20
    ? prompt.solution
    : `Executar o plano "${plan.title}" com contratos V4 congelados, sandbox e diff guard.`;

  const accepted = requirements.map((entry) => entry.id);

  write('discovery.json', {
    work_id: workId,
    title: plan.title,
    imported_from: files.planPath.replace(`${rootDir}${path.sep}`, ''),
    problem,
    actors: prompt?.actors.length ? prompt.actors : ['Operador humano'],
    objectives: prompt?.successCriteria.length ? prompt.successCriteria : plan.tasks.map((task) => task.title),
    constraints: prompt?.constraints.length ? prompt.constraints : plan.global_gates,
  });

  write('requirements.json', { work_id: workId, requirements });

  write('prd.json', {
    $schema: '../../../schemas/prd.schema.json',
    id: `PRD-${workId}`,
    meta: { version: '1.0', created_at: now, author: 'pwn-import' },
    title: plan.title.slice(0, 100),
    status: plan.tasks.every((task) => task.status === 'done') ? 'approved' : 'draft',
    scenario: 'brownfield',
    problem: { statement: problem },
    solution: { statement: solution },
    decisions: [
      {
        id: 'DEC-001',
        statement: `Governar o Work ${workId} pelo PWN com contratos V4 congelados derivados do plano v3.`,
        status: 'accepted',
        made_by: 'pwn-import',
      },
    ],
    requirements: requirements.map((entry) => ({
      id: entry.id.match(/^(FR|QR|EC|SC)/) ? entry.id : `FR-${entry.id.replace(/\D/g, '')}`,
      type: 'functional',
      statement: `${entry.id}: ${entry.title}`,
      acceptance_criteria: entry.acceptance_criteria,
    })),
    stakeholders: prompt?.actors.length ? prompt.actors.map((name) => ({ name, role: 'stakeholder' })) : [{ name: 'Operador humano', role: 'operator' }],
    scope: {
      in_scope: prompt?.inScope.length ? prompt.inScope : plan.tasks.map((task) => task.title),
      out_of_scope: prompt?.outOfScope.length ? prompt.outOfScope : ['Itens não declarados no plano importado'],
    },
    accepted_requirements: accepted,
  });

  const usedCapabilities = unique(plan.tasks.map((task) => task.spec_reference));
  const capabilityRows = usedCapabilities.map((id) => {
    const found = capabilityMap.capabilities.find((capability) => capability.id === id);
    return {
      id,
      name: found?.name ?? `Capacidade do Work ${workId}`,
      description: found?.description ?? `Capacidade implementada pelo Work ${workId}: ${plan.title}.`,
      rules: capabilityMap.rules.length > 0 ? capabilityMap.rules.map((rule) => rule.id) : ['BR-001'],
    };
  });
  write('spec.json', {
    work_id: workId,
    title: plan.title,
    capabilities: capabilityRows,
    rules: capabilityMap.rules.length > 0
      ? capabilityMap.rules
      : [{ id: 'BR-001', statement: 'A execução deve permanecer dentro do escopo congelado nos contratos V4.' }],
  });

  write('traceability-matrix.json', {
    work_id: workId,
    matrix: plan.tasks.map((task, index) => ({
      origin: 'DISC-001',
      requirement_id: task.requirement_id,
      decision_id: 'DEC-001',
      spec_section: task.spec_reference,
      task_id: task.id,
      contract_id: task.contract_id,
      evidence_id: `EVD-${String(index + 1).padStart(3, '0')}`,
      status: task.status === 'done' ? 'done' : 'planned',
    })),
  });

  if (source.trim() === '') {
    warnings.push('Nenhum .sources/NNNN-*.md encontrado: discovery.json derivado apenas do prompt/plano.');
  }

  return { workId, workDir, generated, skipped, warnings, capabilityMapping, riskMapping, plan };
}
