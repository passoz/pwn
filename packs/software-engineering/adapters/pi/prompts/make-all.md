---
description: Execute and audit every planned task sequentially in unattended mode.
argument-hint: "[-h | NNNN | plan path | legacy] [ID | range | all]"
---

Load the installed skill `engineering-workflow` and execute the unattended make-all workflow corresponding to this adapter. Pass `$@` through unchanged as the user's explicit arguments. The skill owns help behavior, task-by-task execution, acceptance audit, autonomous recovery, evidence, timeouts, cleanup, and completion rules; do not duplicate or replace them here.
