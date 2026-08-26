---
name: engineering-workflow
description: Create numbered, system-spec-traceable work prompts and atomized task plans; execute, report, audit, and document software changes through the make-* workflow. Use for Work IDs, .todo/NNNN-tasks.md, immutable RED/GREEN evidence, independent acceptance audit, unattended execution, status, or documentation synchronization.
---

# Engineering Workflow

Use the stage requested by the user. Load only that stage's reference file; do not load every reference by default.

| User intent or Pi adapter | Reference |
|---|---|
| Create and validate a change prompt against the system spec; `/make-prompt` | `references/specify-change.md` |
| Create or validate tasks; `/make-todo` | `references/plan-tasks.md` |
| Execute tasks; `/make-task` | `references/execute-task.md` |
| Execute and audit every task unattended; `/make-all` | `references/run-all.md` plus the two references it requires |
| Show task and evidence panorama; `/make-status` | `references/project-status.md` |
| Audit acceptance criteria; `/make-ac` | `references/audit-acceptance.md` |
| Audit or synchronize documentation; `/make-doc` | `references/synchronize-docs.md` |

Resolve paths relative to this skill directory. The deterministic tools are:

- `scripts/validate_prompt.js`
- `scripts/validate_tasks.js`
- `scripts/work_artifacts.js`
- `scripts/validate_work_graph.js`
- `scripts/task_evidence.js`
- `scripts/project_status.js`
- `scripts/unattended_exec.js`

Current work artifacts use a four-digit repository-local Work ID. A canonical work is indexed by `.work/NNNN.json`, stores its source snapshot in `.sources/NNNN-*.md`, its validated prompt in `.prompts/NNNN-change.md`, and its plan in `.todo/NNNN-tasks.md`. Execution and audit stages require an explicit canonical plan target (`NNNN`, `.todo/NNNN-tasks.md`, or `legacy` during compatibility). Evidence, diagnostics, screenshots, and acceptance candidates are namespaced by Work ID.

The selected reference is authoritative for arguments, help behavior, state transitions, evidence, and completion criteria. Repository instructions and safety constraints still take precedence.
