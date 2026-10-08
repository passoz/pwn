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
    name: 'omp (oh my pi) Coding Agent',
    supportsSystemPrompt: true,
    supportsSubagents: true,
    supportsSkills: true,
    supportsToolCalling: true,
    supportsContractV4: true,
    supportsWorktreeSandbox: true,
    promptFileFormat: 'AGENTS.md',
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

export const TARGET_CAPABILITY_FLAGS: Array<keyof TargetCapabilities> = [
  'supportsSystemPrompt',
  'supportsSubagents',
  'supportsSkills',
  'supportsToolCalling',
  'supportsContractV4',
  'supportsWorktreeSandbox',
];

export function deriveUnsupportedCapabilities(target: TargetRuntime): string[] {
  const caps = TARGET_CAPABILITY_MATRIX[target];
  if (!caps) return [];
  return TARGET_CAPABILITY_FLAGS.filter((flag) => !caps[flag]);
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

/**
 * Protocolo de aceitação que o agente precisa seguir. Cada passo é conferido pelo
 * harness (comandos e arquivos amarrados ao plano, atestação assinada); o texto
 * existe para o agente não descobrir as regras pelo erro.
 */
export function renderAcceptanceProtocol(): string {
  return [
    '',
    '## Protocolo de aceitação (obrigatório — o harness confere cada passo)',
    'Uma task só está concluída com a atestação assinada de `pwn work audit candidate`.',
    'Marcar `[x]` sem ela deixa o Work em INCONSISTENT STATE; "testes passando" não é conclusão.',
    '',
    '1. Antes de tocar em qualquer arquivo: `pwn work audit baseline --work <W> --task <T>` (os arquivos vêm do plano).',
    '2. Escreva o teste que falha e rode `pwn work audit red --work <W> --task <T> --expect "<ID da asserção>" -- <comando RED do plano>`.',
    '   O texto de `--expect` precisa estar escrito no arquivo de teste e aparecer só na falha (nada de "fail" ou "Error").',
    '3. Implemente e rode `pwn work audit green --work <W> --task <T> -- <comando RED do plano>`.',
    '4. Para cada AC do plano: `pwn work audit check --work <W> --task <T> --name AC-<n> -- <comando do AC-n, idêntico ao plano>`.',
    '   O harness roda o AC também sem a sua implementação: AC que passa assim é recusado como vácuo.',
    '5. `pwn work audit check --work <W> --task <T> --name REGRESSION -- <comando de regressão do plano>`.',
    '6. `pwn work audit candidate --work <W> --task <T> -- <comando RED do plano>` e só então marque `[x]`.',
    '7. Ao fim do Work, para cada gate global: `pwn work audit gate --work <W> --name G-<n> -- <comando do gate>`.',
    '',
    'Proibido: editar plano, contrato ou testes de aceitação congelados para a task passar; trocar os comandos do plano;',
    'alterar testes depois do RED; implementar fora do que os ACs exigem e chamar de pronto.',
  ].join('\n');
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
