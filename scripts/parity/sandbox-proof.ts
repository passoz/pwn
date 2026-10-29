import fs from 'node:fs';
import path from 'node:path';

import { runVerification } from '../../src/core/verification-runner.js';

const approval = {
  version: 1 as const,
  approval_id: 'SANDBOX-PROOF',
  work_id: '0002',
  task_id: '1.5',
  kind: 'task' as const,
  approved_by: 'prova',
  created_at: new Date().toISOString(),
  plan_path: '.todo/0002-tasks.md',
  plan_sha256: '',
  contract_id: null,
  contract_sha256: null,
  baseline_commit: 'HEAD',
  implementation_files: [],
  checks: [
    {
      id: 'AC-1',
      command: ['bun', '-e', 'import("ajv").then(() => console.log("AJV-OK"))'],
      expect_output: null,
      require_baseline_failure: false,
    },
  ],
  approved_files: [],
};

const result = runVerification({ rootDir: process.cwd(), approval, timeoutSeconds: 60 });
const check = result.checks[0];
const proof = {
  node_modules_visible: check.exit_code === 0,
  network: result.sandbox_policy.network,
  check_exit: check.exit_code,
  output_tail: check.output_tail.slice(-200),
};
fs.mkdirSync(path.resolve('testdata/parity'), { recursive: true });
fs.writeFileSync(path.resolve('testdata/parity/sandbox.json'), `${JSON.stringify(proof, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(proof));
process.exit(check.exit_code === 0 ? 0 : 1);
