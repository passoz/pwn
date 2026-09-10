import fs from 'node:fs';
import path from 'node:path';

// ── Canonical plan model (single source of truth, rendered to the v3 markdown) ──
// The canonical task id is the v3 dotted form ("1.1"), shared by the gates, the
// pack validators (validate_tasks.js) and the TDD evidence tool (task_evidence.js).

export interface PlanComponent {
  name: string;
  purpose: string;
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
  lines.push('| Component | Purpose |');
  lines.push('|-----------|---------|');
  for (const component of plan.components) {
    lines.push(`| \`${component.name}\` | ${component.purpose} |`);
  }
  lines.push('');
  lines.push('## Global gates');
  lines.push('');
  for (const gate of plan.global_gates) {
    lines.push(`- [ ] ${gate}`);
  }

  for (const task of plan.tasks) {
    lines.push('');
    lines.push(`### [${marker(task)}] [${task.id}] ${task.title}`);
    lines.push(`**Requirement:** ${task.requirement_id}`);
    lines.push(`**Depends on:** ${task.depends_on.length ? task.depends_on.join(', ') : 'none'}`);
    lines.push(`**Behavior:** ${task.behavior}`);
    lines.push(`**Components:** ${task.components.join(', ')}`);
    lines.push(`**Files:** ${task.files.join(', ')}`);
    lines.push(`**Implementation files:** ${task.implementation_files.join(', ')}`);
    lines.push(`**Test files:** ${task.test_files.join(', ')}`);
    lines.push('**RED:**');
    lines.push(`- \`${task.red.command}\` — ${task.red.description}`);
    lines.push('**Implementation:**');
    task.implementation_steps.forEach((step, index) => lines.push(`${index + 1}. ${step}`));
    lines.push('**ACs:**');
    for (const ac of task.acceptance_criteria) {
      lines.push(`- [ ] \`${ac.command}\` — ${ac.description}`);
    }
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
  const planPath = path.resolve(rootDir, '.piwerness/work', workId, 'plan.json');
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
