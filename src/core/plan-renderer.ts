import fs from 'node:fs';
import path from 'node:path';

// ── Canonical plan model (single source of truth, rendered to the v3 markdown) ──
// The canonical task id is the v3 dotted form ("1.1"), shared by the gates, the
// pack validators (validate_tasks.js) and the TDD evidence tool (task_evidence.js).

export interface PlanComponent {
  name: string;
  purpose: string;
  // v3 execution-contract assurance columns. When any component declares these,
  // the renderer emits the full v3 table so legacy plans round-trip byte-for-byte.
  root?: string;
  regression?: string;
  lint?: string;
  build?: string;
  security?: string;
  dev?: string;
  health?: string;
}

/** Ordered v3 assurance columns: [model key, markdown header]. */
export const ASSURANCE_COLUMNS: ReadonlyArray<readonly [keyof PlanComponent, string]> = [
  ['root', 'Root'],
  ['regression', 'Regression'],
  ['lint', 'Lint'],
  ['build', 'Build'],
  ['security', 'Security'],
  ['dev', 'Dev'],
  ['health', 'Health'],
];

/** The v3 writer pads separators to `header.length + 2` dashes. */
function separator(headers: string[]): string {
  return `|${headers.map((header) => '-'.repeat(header.length + 2)).join('|')}|`;
}

/** The v3 writer wraps every path in inline code. */
function codeList(values: string[]): string {
  return values.map((value) => `\`${value}\``).join(', ');
}

export interface PlanRed {
  command: string;
  description: string;
}

export interface PlanAC {
  command: string;
  description: string;
}

export interface PlanTask {
  id: string; // "1.1"
  title: string;
  requirement_id: string; // "FR-001"
  depends_on: string[];
  behavior: string;
  components: string[];
  files: string[];
  implementation_files: string[];
  test_files: string[];
  red: PlanRed;
  implementation_steps: string[];
  acceptance_criteria: PlanAC[];
  visual?: 'N/A' | 'REQUIRED';
  documentation?: 'N/A' | 'REQUIRED';
  spec_reference: string;
  contract_id: string;
  complexity: string;
  status?: 'pending' | 'done' | 'blocked';
}

export interface Plan {
  work_id: string;
  title: string;
  components: PlanComponent[];
  global_gates: string[];
  tasks: PlanTask[];
}

function marker(task: PlanTask): string {
  if (task.status === 'done') return 'x';
  if (task.status === 'blocked') return '!';
  return ' ';
}

/**
 * Render the canonical plan into the v3 task-contract markdown consumed by
 * validate_tasks.js, project_status.js and task_evidence.js.
 *
 * Deterministic: same plan → same bytes.
 */
export function renderTasksMarkdown(plan: Plan): string {
  const lines: string[] = [];

  lines.push(`# Tasks: ${plan.title}`);
  lines.push('');
  lines.push('**Contract version:** 3');
  lines.push(`**Work ID:** ${plan.work_id}`);
  lines.push('');
  lines.push('## Execution contract');
  lines.push('');
  const extended = plan.components.some((component) =>
    ASSURANCE_COLUMNS.some(([key]) => component[key] !== undefined),
  );
  if (extended) {
    const headers = ['Component', ...ASSURANCE_COLUMNS.map(([, header]) => header)];
    lines.push(`| ${headers.join(' | ')} |`);
    lines.push(separator(headers));
    for (const component of plan.components) {
      const cells = ASSURANCE_COLUMNS.map(([key]) => `\`${component[key] ?? 'N/A'}\``);
      lines.push(`| ${component.name} | ${cells.join(' | ')} |`);
    }
  } else {
    const headers = ['Component', 'Purpose'];
    lines.push(`| ${headers.join(' | ')} |`);
    lines.push(separator(headers));
    for (const component of plan.components) {
      lines.push(`| \`${component.name}\` | ${component.purpose} |`);
    }
  }
  lines.push('');
  lines.push('## Global gates');
  for (const gate of plan.global_gates) {
    lines.push(`- [ ] ${gate}`);
  }

  for (const task of plan.tasks) {
    lines.push('');
    lines.push(`### [${marker(task)}] [${task.id}] ${task.title}`);
    lines.push('');
    lines.push(`**Requirement:** ${task.requirement_id}`);
    lines.push(`**Depends on:** ${task.depends_on.length ? task.depends_on.join(', ') : 'none'}`);
    lines.push(`**Behavior:** ${task.behavior}`);
    lines.push(`**Components:** ${task.components.join(', ')}`);
    lines.push(`**Files:** ${codeList(task.files)}`);
    lines.push(`**Implementation files:** ${codeList(task.implementation_files)}`);
    lines.push(`**Test files:** ${codeList(task.test_files)}`);
    lines.push('');
    lines.push('**RED:**');
    lines.push(`- \`${task.red.command}\` — ${task.red.description}`);
    lines.push('');
    lines.push('**Implementation:**');
    task.implementation_steps.forEach((step, index) => lines.push(`${index + 1}. ${step}`));
    lines.push('');
    lines.push('**ACs:**');
    for (const ac of task.acceptance_criteria) {
      lines.push(`- [ ] \`${ac.command}\` — ${ac.description}`);
    }
    lines.push('');
    lines.push(`**Visual:** ${task.visual ?? 'N/A'}`);
    lines.push(`**Documentation:** ${task.documentation ?? 'N/A'}`);
  }

  return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}

/**
 * Normalize checkbox markers so that execution state (checked/blocked) does not
 * count as plan drift. Only the structural content of the plan is compared.
 */
export function normalizeMarkers(markdown: string): string {
  return markdown
    .replace(/^### \[[ x!]\]/gm, '### [ ]')
    .replace(/^- \[[ xX!]\]/gm, '- [ ]');
}

/**
 * Load the canonical plan for a work id. Returns null when absent or unreadable.
 */
export function loadPlan(workId: string, rootDir: string = process.cwd()): Plan | null {
  const planPath = path.resolve(rootDir, '.pwn/work', workId, 'plan.json');
  if (!fs.existsSync(planPath)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(planPath, 'utf8'));
    if (!data || !Array.isArray(data.tasks)) return null;
    return data as Plan;
  } catch {
    return null;
  }
}

/**
 * Render the plan and compare it against an existing markdown file, ignoring
 * checkbox state. Returns true when the structural content matches.
 */
export function planMatchesMarkdown(plan: Plan, existingMarkdown: string): boolean {
  return normalizeMarkers(renderTasksMarkdown(plan)) === normalizeMarkers(existingMarkdown);
}

/**
 * Resolve the canonical markdown path for a work id.
 */
export function tasksMarkdownPath(workId: string, rootDir: string = process.cwd()): string {
  return path.resolve(rootDir, '.todo', `${workId}-tasks.md`);
}
