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
