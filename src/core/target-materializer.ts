export type TargetRuntime = 'pi' | 'opencode' | 'omp' | 'raw';

export interface TargetCapabilities {
  target: TargetRuntime;
  name: string;
  supportsSystemPrompt: boolean;
  supportsSubagents: boolean;
  supportsSkills: boolean;
  supportsToolCalling: boolean;
  supportsContractV4: boolean;
  supportsWorktreeSandbox: boolean;
  promptFileFormat: string; // e.g. 'AGENTS.md', 'SYSTEM.md', 'omp.json'
}

export const TARGET_CAPABILITY_MATRIX: Record<TargetRuntime, TargetCapabilities> = {
  pi: {
    target: 'pi',
    name: 'Pi Agent Harness',
    supportsSystemPrompt: true,
    supportsSubagents: true,
    supportsSkills: true,
    supportsToolCalling: true,
    supportsContractV4: true,
    supportsWorktreeSandbox: true,
    promptFileFormat: 'AGENTS.md',
  },
  opencode: {
    target: 'opencode',
    name: 'OpenCode Interpreter',
    supportsSystemPrompt: true,
    supportsSubagents: true,
    supportsSkills: true,
    supportsToolCalling: true,
    supportsContractV4: true,
    supportsWorktreeSandbox: true,
    promptFileFormat: 'AGENTS.md',
  },
  omp: {
    target: 'omp',
    name: 'omp CLI Assistant',
    supportsSystemPrompt: true,
    supportsSubagents: false,
    supportsSkills: true,
    supportsToolCalling: false,
    supportsContractV4: false,
    supportsWorktreeSandbox: false,
    promptFileFormat: 'omp.json',
  },
  raw: {
    target: 'raw',
    name: 'Raw Model API / LLM Prompt',
    supportsSystemPrompt: true,
    supportsSubagents: false,
    supportsSkills: false,
    supportsToolCalling: false,
    supportsContractV4: false,
    supportsWorktreeSandbox: false,
    promptFileFormat: 'prompt.txt',
  },
};

export interface MaterializationResult {
  target: TargetRuntime;
  success: boolean;
  unsupportedCapabilities: string[];
  generatedFiles: string[];
  notes: string[];
}

export function validateTargetSupport(target: TargetRuntime, requiredCapabilities: Array<keyof TargetCapabilities>): { valid: boolean; missing: string[] } {
  const caps = TARGET_CAPABILITY_MATRIX[target];
  if (!caps) {
    return { valid: false, missing: [`Target desconhecido: ${target}`] };
  }

  const missing: string[] = [];
  for (const req of requiredCapabilities) {
    if (!caps[req]) {
      missing.push(req as string);
    }
  }

  return {
    valid: missing.length === 0,
    missing,
  };
}

// ── Contract-derived materialization ───────────────────────────────

export interface TargetContractContext {
  writeAllow: string[];
  writeDeny: string[];
  acceptanceCommands: string[];
  riskLevel: string;
  taskCount: number;
}

const RISK_ORDER = ['L0', 'L1', 'L2', 'L3', 'L4'];

export function collectContractContext(contracts: Array<{
  scope_contract: { write_allow: string[]; write_deny: string[] };
  acceptance_contract: { commands: string[] };
  risk: { level: string };
}>): TargetContractContext {
  const levels = contracts.map((c) => c.risk.level);
  const highest = levels.reduce((acc, level) => (RISK_ORDER.indexOf(level) > RISK_ORDER.indexOf(acc) ? level : acc), 'L0');
  return {
    writeAllow: [...new Set(contracts.flatMap((c) => c.scope_contract.write_allow))],
    writeDeny: [...new Set(contracts.flatMap((c) => c.scope_contract.write_deny))],
    acceptanceCommands: [...new Set(contracts.flatMap((c) => c.acceptance_contract.commands))],
    riskLevel: highest,
    taskCount: contracts.length,
  };
}

export function renderScopeSection(context: TargetContractContext): string {
  if (context.taskCount === 0) return '';
  const lines = [
    '',
    '## Escopo do contrato (V4 congelado)',
    'WRITE ALLOW:',
    ...context.writeAllow.map((w) => `  + ${w}`),
    'WRITE DENY:',
    ...context.writeDeny.map((d) => `  - ${d}`),
    'VALIDATION COMMANDS:',
    ...context.acceptanceCommands.map((c) => `  $ ${c}`),
    `RISK LEVEL: ${context.riskLevel}`,
  ];
  return lines.join('\n');
}
