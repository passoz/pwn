import { createHash } from 'node:crypto';
import path from 'node:path';

import { normalizeMarkers } from './plan-renderer.js';

// ── Amarração da aceitação ao plano ────────────────────────────────
//
// O audit, os gates, o validador do markdown e o status leem a MESMA definição
// de task: comandos de RED/AC/gates e listas de arquivos saem do plano, nunca do
// operador. O operador continua digitando o comando (o harness não executa nada
// lido de um artefato do repositório), mas o comando digitado precisa coincidir
// com o declarado — é isso que impede `check --name AC-1 -- true`.

/** Comando de RED/AC declarado no plano. */
export interface PlanCommand {
  command: string;
  description: string;
}

/** Definição de uma task extraída do markdown v3 (`.todo/NNNN-tasks.md`). */
export interface PlanTaskDefinition {
  id: string;
  marker: string;
  title: string;
  /** Linhas do bloco da task, heading incluso. */
  lines: string[];
  implementationFiles: string[];
  testFiles: string[];
  components: string[];
  red: PlanCommand | null;
  acs: PlanCommand[];
  visual: { required: boolean; command: string | null };
  documentation: { required: boolean; command: string | null };
}

/** Item de `## Global gates`. */
export interface PlanGlobalGate {
  marker: string;
  command: string | null;
  text: string;
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash']);

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * JSON com chaves ordenadas em todos os níveis: a mesma estrutura sempre produz
 * os mesmos bytes, o que permite assinar e reverificar um objeto relido do disco.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry === undefined ? null : entry)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

// ── Comandos ───────────────────────────────────────────────────────

/**
 * Tokeniza uma linha de comando no subconjunto POSIX usado nos planos: espaço
 * separa argumentos, aspas simples são literais, aspas duplas aceitam escape de
 * `"`, `\`, `$` e crase, e a barra invertida fora de aspas escapa o próximo
 * caractere. Devolve `null` quando as aspas não fecham.
 */
export function splitCommandLine(command: string): string[] | null {
  const tokens: string[] = [];
  let current = '';
  let inToken = false;
  let quote: '"' | "'" | null = null;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index];
    if (quote === "'") {
      if (char === "'") quote = null;
      else current += char;
      continue;
    }
    if (quote === '"') {
      if (char === '"') {
        quote = null;
      } else if (char === '\\' && index + 1 < command.length && '"\\$`'.includes(command[index + 1])) {
        index += 1;
        current += command[index];
      } else {
        current += char;
      }
      continue;
    }
    if (/\s/.test(char)) {
      if (inToken) tokens.push(current);
      current = '';
      inToken = false;
      continue;
    }
    inToken = true;
    if (char === "'" || char === '"') {
      quote = char;
    } else if (char === '\\' && index + 1 < command.length) {
      index += 1;
      current += command[index];
    } else {
      current += char;
    }
  }
  if (quote) return null;
  if (inToken) tokens.push(current);
  return tokens;
}

/** Forma canônica de um comando para comparação (tokens separados por um espaço). */
export function normalizeCommand(command: string): string {
  const tokens = splitCommandLine(command.trim());
  return tokens ? tokens.join(' ') : command.trim().replace(/\s+/g, ' ');
}

function quoteToken(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

/** Representação legível de um argv para mensagens. */
export function displayCommand(argv: readonly string[]): string {
  return argv.map(quoteToken).join(' ');
}

/**
 * O argv do operador corresponde ao comando do plano quando os tokens são iguais
 * ou quando ele roda exatamente o texto do plano via `sh -c`/`bash -c` (forma
 * necessária para comandos com pipe, `&&` ou redirecionamento).
 */
export function commandMatches(planned: string, argv: readonly string[]): boolean {
  const expected = planned.trim();
  const tokens = splitCommandLine(expected);
  if (tokens && tokens.length === argv.length && tokens.every((token, index) => token === argv[index])) return true;
  return argv.length === 3 && SHELLS.has(path.basename(argv[0])) && argv[1] === '-c' && argv[2].trim() === expected;
}

const VACUOUS_PROGRAMS = new Set(['true', ':', 'echo', 'printf', 'exit', 'yes']);

/** Motivo pelo qual o comando não exercita comportamento algum (`true`, `echo ok`...), ou `null`. */
export function vacuousCommandReason(command: string): string | null {
  const tokens = splitCommandLine(command.trim());
  if (!tokens || tokens.length === 0) return 'comando vazio ou com aspas desbalanceadas';
  const program = path.basename(tokens[0]);
  if (VACUOUS_PROGRAMS.has(program)) return `\`${program}\` não exercita comportamento`;
  if (SHELLS.has(program) && tokens[1] === '-c' && tokens.length === 3 && !/[;&|<>]/.test(tokens[2])) {
    return vacuousCommandReason(tokens[2]);
  }
  return null;
}

/** Runners cuja execução sem alvo roda a suíte inteira. */
const SUITE_RUNNERS: string[][] = [
  ['bun', 'test'], ['bun', 'run', 'test'],
  ['npm', 'test'], ['npm', 't'], ['npm', 'run', 'test'],
  ['pnpm', 'test'], ['pnpm', 'run', 'test'],
  ['yarn', 'test'], ['yarn', 'run', 'test'],
  ['npx', 'vitest', 'run'], ['npx', 'vitest'], ['vitest', 'run'], ['vitest'],
  ['npx', 'jest'], ['jest'],
  ['node', '--test'],
  ['deno', 'test'],
  ['go', 'test'],
  ['cargo', 'test'],
  ['python', '-m', 'pytest'], ['python3', '-m', 'pytest'], ['pytest'],
  ['mvn', 'test'], ['gradle', 'test'], ['./gradlew', 'test'],
  ['dotnet', 'test'], ['mix', 'test'], ['bundle', 'exec', 'rspec'], ['rspec'], ['phpunit'], ['vendor/bin/phpunit'],
  ['make', 'test'], ['make', 'check'],
];

/** Flags de runner que recebem valor sem estreitar a seleção de testes. */
const NON_SELECTING_VALUE_FLAGS = new Set([
  '--timeout', '-timeout', '--reporter', '--reporters', '--rerun-each', '--seed', '--bail', '--preload',
  '--coverage-reporter', '--coverage-dir', '--max-concurrency', '--config', '-c', '--project', '-count',
  '-p', '--maxfail', '--workers', '-j', '--jobs', '--parallel', '-parallel',
]);

/** O comando roda a suíte inteira de um runner conhecido, sem arquivo, filtro ou pacote alvo. */
export function isWholeSuiteCommand(command: string): boolean {
  const tokens = splitCommandLine(command.trim());
  if (!tokens || tokens.length === 0) return false;
  const runner = SUITE_RUNNERS.find((prefix) => prefix.every((token, index) => tokens[index] === token));
  if (!runner) return false;
  const rest = tokens.slice(runner.length);
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === '--') continue;
    if (arg.startsWith('-')) {
      if (!arg.includes('=') && NON_SELECTING_VALUE_FLAGS.has(arg)) index += 1;
      continue;
    }
    if (arg === './...' || arg === '.' || arg === '...' || /^\d+$/.test(arg)) continue;
    return false;
  }
  return true;
}

/**
 * Motivo pelo qual o comando não serve como critério de aceite de uma task:
 * vazio/vácuo, repetição de um gate global ou suíte inteira sem alvo.
 */
export function genericCommandReason(command: string, gateCommands: readonly string[] = []): string | null {
  const vacuous = vacuousCommandReason(command);
  if (vacuous) return vacuous;
  const normalized = normalizeCommand(command);
  if (gateCommands.some((gate) => normalizeCommand(gate) === normalized)) {
    return 'repete um gate global/comando de regressão — gate não é critério de aceite da task';
  }
  if (isWholeSuiteCommand(command)) return 'roda a suíte inteira sem alvo — não prova o comportamento da task';
  return null;
}

const GENERIC_EXPECT = new Set([
  '(fail)', 'fail', 'fail:', 'failed', 'failure', 'failing', 'error', 'error:', 'errors', 'assertionerror',
  'assertion', 'assert', 'expected', 'received', 'expect(received)', 'tobe', 'not ok', 'panic', 'traceback',
  'exception', 'fatal', 'false', 'undefined', 'null',
]);

/** Motivo pelo qual o texto de `--expect` é genérico demais para identificar a asserção da task. */
export function genericExpectReason(expect: string): string | null {
  const text = expect.trim();
  if (GENERIC_EXPECT.has(text.toLowerCase())) return `"${text}" é marcador genérico do runner, não a asserção da task`;
  if (text.length < 6) return `"${text}" tem ${text.length} caractere(s); use o identificador da asserção (mínimo 6)`;
  return null;
}

/** Motivo pelo qual um caminho declarado não é um arquivo concreto (diretório, glob, placeholder). */
export function placeholderPathReason(filePath: string): string | null {
  const value = filePath.trim();
  if (!value) return 'caminho vazio';
  if (value === '.' || value === '..' || value.endsWith('/') || value.endsWith(path.sep)) return 'é diretório, não arquivo';
  if (/[*?[\]{}]/.test(value)) return 'é glob, não arquivo';
  if (/<[^>]*>|\b(?:TODO|TBD)\b/.test(value)) return 'é placeholder';
  return null;
}

/** Primeiro trecho em crase de um texto, ou o texto inteiro quando não há crase. */
export function firstInlineCommand(text: string): string | null {
  const match = text.match(/`([^`\n]+)`/);
  if (match) return match[1].trim();
  const plain = text.trim();
  return plain.length > 0 ? plain : null;
}

// ── Leitura do plano (markdown v3) ─────────────────────────────────

const TASK_HEADING = /^### \[([ x!])\] \[(\d+)\.(\d+)\] (.*)$/;
const RED_LINE = /^- `([^`]+)`(?:\s+—\s+(.*))?\s*$/;
const AC_LINE = /^- \[[ xX!]\] `([^`]+)`(?:\s+—\s+(.*))?\s*$/;
const EVIDENCE_LINE = /^- \*\*Evidence:\*\* `([^`]+)`/;

function normalizeTaskId(taskId: string): string {
  const match = taskId.match(/^(\d+)\.(\d+)$/);
  return match ? `${Number(match[1])}.${Number(match[2])}` : taskId;
}

function fieldValue(block: string[], name: string): string | null {
  const prefixes = [`**${name}:**`, `- **${name}:**`];
  for (const line of block) {
    for (const prefix of prefixes) {
      if (line.startsWith(prefix)) return line.slice(prefix.length).trim();
    }
  }
  return null;
}

function fieldSection(block: string[], name: string): string[] {
  const start = block.indexOf(`**${name}:**`);
  if (start === -1) return [];
  let end = block.length;
  for (let index = start + 1; index < block.length; index += 1) {
    if (block[index].startsWith('**')) {
      end = index;
      break;
    }
  }
  return block.slice(start + 1, end);
}

function listValues(value: string | null): string[] {
  if (!value) return [];
  return [...new Set(value.split(',').map((part) => part.trim().replace(/^`|`$/g, '')).filter((part) => part && part !== 'N/A'))];
}

/** Blocos de task do plano, na ordem do arquivo. */
function taskBlocks(lines: string[]): Array<{ id: string; marker: string; title: string; start: number; end: number }> {
  const headings: Array<{ index: number; match: RegExpMatchArray }> = [];
  lines.forEach((line, index) => {
    const match = line.match(TASK_HEADING);
    if (match) headings.push({ index, match });
  });
  return headings.map(({ index, match }, position) => {
    let end = position + 1 < headings.length ? headings[position + 1].index : lines.length;
    for (let cursor = index + 1; cursor < end; cursor += 1) {
      if (lines[cursor].startsWith('## ') || (lines[cursor].startsWith('### ') && !TASK_HEADING.test(lines[cursor]))) {
        end = cursor;
        break;
      }
    }
    return { id: `${Number(match[2])}.${Number(match[3])}`, marker: match[1], title: match[4], start: index, end };
  });
}

function definitionFromBlock(id: string, marker: string, title: string, block: string[]): PlanTaskDefinition {
  const redLine = fieldSection(block, 'RED').map((line) => line.match(RED_LINE)).find(Boolean);
  const acs = fieldSection(block, 'ACs')
    .map((line) => line.match(AC_LINE))
    .filter((match): match is RegExpMatchArray => Boolean(match))
    .map((match) => ({ command: match[1].trim(), description: (match[2] ?? '').trim() }));

  const visualRequired = fieldValue(block, 'Visual') === 'REQUIRED';
  const playwright = fieldValue(block, 'Playwright');
  const documentationRequired = fieldValue(block, 'Documentation') === 'REQUIRED';
  const evidence = block.map((line) => line.match(EVIDENCE_LINE)).find(Boolean);

  return {
    id,
    marker,
    title,
    lines: block,
    implementationFiles: listValues(fieldValue(block, 'Implementation files')),
    testFiles: listValues(fieldValue(block, 'Test files')),
    components: listValues(fieldValue(block, 'Components')),
    red: redLine ? { command: redLine[1].trim(), description: (redLine[2] ?? '').trim() } : null,
    acs,
    visual: { required: visualRequired, command: visualRequired && playwright ? firstInlineCommand(playwright) : null },
    documentation: { required: documentationRequired, command: documentationRequired && evidence ? evidence[1].trim() : null },
  };
}

/** Lê a definição de uma task do plano; `null` quando a task não existe. */
export function parsePlanTask(planText: string, taskId: string): PlanTaskDefinition | null {
  const lines = planText.split(/\r?\n/);
  const wanted = normalizeTaskId(taskId);
  const entry = taskBlocks(lines).find((candidate) => candidate.id === wanted);
  if (!entry) return null;
  return definitionFromBlock(entry.id, entry.marker, entry.title, lines.slice(entry.start, entry.end));
}

/** Todas as tasks do plano, na ordem do arquivo. */
export function parsePlanTasks(planText: string): PlanTaskDefinition[] {
  const lines = planText.split(/\r?\n/);
  return taskBlocks(lines).map((entry) => definitionFromBlock(entry.id, entry.marker, entry.title, lines.slice(entry.start, entry.end)));
}

function sectionLines(lines: string[], heading: string): string[] | null {
  const start = lines.indexOf(heading);
  if (start === -1) return null;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].startsWith('## ') || lines[index].startsWith('### ')) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end);
}

/** Itens de `## Global gates`; `null` quando a seção não existe, `[]` quando é `N/A`. */
export function parseGlobalGates(planText: string): PlanGlobalGate[] | null {
  const section = sectionLines(planText.split(/\r?\n/), '## Global gates');
  if (section === null) return null;
  const gates: PlanGlobalGate[] = [];
  for (const line of section) {
    const match = line.match(/^- \[([ xX!])\]\s*(.*)$/);
    if (!match) continue;
    const text = match[2].trim();
    const inline = text.match(/`([^`\n]+)`/);
    gates.push({ marker: match[1].toLowerCase(), command: inline ? inline[1].trim() : null, text });
  }
  return gates;
}

const ASSURANCE_COLUMNS = ['regression', 'lint', 'build', 'security'];

/** Comandos das colunas de garantia (Regression, Lint, Build, Security) do Execution contract. */
function assuranceTable(planText: string): Array<{ component: string; columns: Record<string, string> }> {
  const section = sectionLines(planText.split(/\r?\n/), '## Execution contract');
  if (!section) return [];
  const rows = section.filter((line) => line.trim().startsWith('|'));
  if (rows.length < 2) return [];
  const cells = (line: string) => line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim().replace(/^`|`$/g, ''));
  const headers = cells(rows[0]).map((header) => header.toLowerCase());
  return rows.slice(1)
    .map(cells)
    .filter((row) => row.length && !/^[-:]+$/.test(row[0]) && row[0].toLowerCase() !== 'component')
    .map((row) => ({
      component: row[0],
      columns: Object.fromEntries(headers.map((header, index) => [header, row[index] ?? ''])),
    }));
}

function tableCommands(planText: string, columns: string[], components?: readonly string[]): string[] {
  const wanted = components && components.length ? new Set(components) : null;
  return assuranceTable(planText)
    .filter((row) => !wanted || wanted.has(row.component))
    .flatMap((row) => columns.map((column) => row.columns[column]))
    .filter((value): value is string => Boolean(value) && value !== 'N/A');
}

function globalGateCommands(planText: string): string[] {
  return (parseGlobalGates(planText) ?? []).map((gate) => gate.command).filter((command): command is string => Boolean(command));
}

function uniqueCommands(commands: string[]): string[] {
  const seen = new Set<string>();
  return commands.filter((command) => {
    const key = normalizeCommand(command);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Comandos aceitos para o check REGRESSION: coluna Regression dos componentes da task + gates globais. */
export function regressionCommands(planText: string, components?: readonly string[]): string[] {
  return uniqueCommands([...tableCommands(planText, ['regression'], components), ...globalGateCommands(planText)]);
}

/** Todos os comandos de gate do plano (colunas de garantia + gates globais): nenhum deles é AC de task. */
export function assuranceCommands(planText: string, components?: readonly string[]): string[] {
  return uniqueCommands([...tableCommands(planText, ASSURANCE_COLUMNS, components), ...globalGateCommands(planText)]);
}

/** Checks que a atestação de aceitação exige para a task. */
export function requiredAuditChecks(task: PlanTaskDefinition): string[] {
  return [
    ...task.acs.map((_, index) => `AC-${index + 1}`),
    ...(task.visual.required ? ['VISUAL'] : []),
    ...(task.documentation.required ? ['DOCUMENTATION'] : []),
    'REGRESSION',
  ];
}

/** Comandos que o plano autoriza para um check do audit, ou o motivo de não haver nenhum. */
export function allowedCheckCommands(planText: string, task: PlanTaskDefinition, name: string): { commands: string[]; error?: string } {
  const ac = name.match(/^AC-([1-9]\d*)$/);
  if (ac) {
    const entry = task.acs[Number(ac[1]) - 1];
    if (!entry) return { commands: [], error: `${name} não existe no plano: a task ${task.id} declara ${task.acs.length} AC(s)` };
    return { commands: [entry.command] };
  }
  if (name === 'VISUAL') {
    if (!task.visual.required) return { commands: [], error: `a task ${task.id} não exige VISUAL` };
    if (!task.visual.command) return { commands: [], error: `a task ${task.id} exige VISUAL mas não declara o comando em **Playwright:**` };
    return { commands: [task.visual.command] };
  }
  if (name === 'DOCUMENTATION') {
    if (!task.documentation.required) return { commands: [], error: `a task ${task.id} não exige DOCUMENTATION` };
    if (!task.documentation.command) return { commands: [], error: `a task ${task.id} exige DOCUMENTATION mas não declara o comando em **Evidence:**` };
    return { commands: [task.documentation.command] };
  }
  if (name === 'REGRESSION') {
    const commands = regressionCommands(planText, task.components);
    return commands.length
      ? { commands }
      : { commands, error: 'o plano não declara comando de regressão (coluna Regression ou itens de ## Global gates)' };
  }
  if (name === 'LOCAL-GATES') {
    const commands = assuranceCommands(planText, task.components);
    return commands.length
      ? { commands }
      : { commands, error: 'o plano não declara gates locais (colunas de garantia ou ## Global gates)' };
  }
  return { commands: [], error: `check desconhecido: ${name}` };
}

/**
 * Impressão digital da definição da task: bloco do plano (sem o estado dos
 * checkboxes) mais os comandos de gate que se aplicam a ela. Congelada no
 * baseline, impede trocar ACs, RED ou arquivos no meio do ciclo.
 */
export function taskDefinitionDigest(planText: string, task: PlanTaskDefinition): string {
  const block = normalizeMarkers(task.lines.join('\n'))
    .split('\n')
    .map((line) => line.trimEnd())
    .join('\n')
    .trim();
  const gates = assuranceCommands(planText, task.components).map(normalizeCommand);
  return sha256(canonicalJson({ block, gates }));
}
