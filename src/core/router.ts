import fs from 'node:fs';
import path from 'node:path';

export type AgentRole = 'cheap' | 'strong' | 'review' | 'plan';

export interface ModelRoutingConfig {
  role: AgentRole;
  defaultModel: string;
  maxTokens: number;
  temperature: number;
}

export const DEFAULT_ROUTING_TABLE: Record<AgentRole, ModelRoutingConfig> = {
  cheap: {
    role: 'cheap',
    defaultModel: 'qwen3.5:27b',
    maxTokens: 4000,
    temperature: 0.2,
  },
  strong: {
    role: 'strong',
    defaultModel: 'claude-3-7-sonnet',
    maxTokens: 16000,
    temperature: 0.1,
  },
  review: {
    role: 'review',
    defaultModel: 'claude-3-5-haiku',
    maxTokens: 8000,
    temperature: 0.1,
  },
  plan: {
    role: 'plan',
    defaultModel: 'claude-3-7-sonnet',
    maxTokens: 12000,
    temperature: 0.2,
  },
};

export function getRoutingTable(rootDir: string = process.cwd()): Record<AgentRole, ModelRoutingConfig> {
  const table = JSON.parse(JSON.stringify(DEFAULT_ROUTING_TABLE)) as Record<AgentRole, ModelRoutingConfig>;

  // 1. Ler arquivo .piwerness/routing.json se existir
  const configPath = path.resolve(rootDir, '.piwerness/routing.json');
  if (fs.existsSync(configPath)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      const roles: AgentRole[] = ['cheap', 'strong', 'review', 'plan'];
      for (const role of roles) {
        if (fileData[role]) {
          if (fileData[role].defaultModel) table[role].defaultModel = fileData[role].defaultModel;
          if (fileData[role].maxTokens) table[role].maxTokens = fileData[role].maxTokens;
          if (fileData[role].temperature !== undefined) table[role].temperature = fileData[role].temperature;
        }
      }
    } catch {
      // ignora se JSON corrompido
    }
  }

  // 2. Sobrescrever por Variáveis de Ambiente
  if (process.env.PWN_MODEL_CHEAP) table.cheap.defaultModel = process.env.PWN_MODEL_CHEAP;
  if (process.env.PWN_MODEL_STRONG) table.strong.defaultModel = process.env.PWN_MODEL_STRONG;
  if (process.env.PWN_MODEL_REVIEW) table.review.defaultModel = process.env.PWN_MODEL_REVIEW;
  if (process.env.PWN_MODEL_PLAN) table.plan.defaultModel = process.env.PWN_MODEL_PLAN;

  return table;
}

export function saveRoutingConfig(
  newConfig: Partial<Record<AgentRole, Partial<ModelRoutingConfig>>>,
  rootDir: string = process.cwd()
): void {
  const piwernessDir = path.resolve(rootDir, '.piwerness');
  if (!fs.existsSync(piwernessDir)) {
    fs.mkdirSync(piwernessDir, { recursive: true });
  }

  const configPath = path.join(piwernessDir, 'routing.json');
  const currentTable = getRoutingTable(rootDir);

  const roles: AgentRole[] = ['cheap', 'strong', 'review', 'plan'];
  for (const role of roles) {
    if (newConfig[role]) {
      currentTable[role] = {
        ...currentTable[role],
        ...newConfig[role],
      };
    }
  }

  fs.writeFileSync(configPath, JSON.stringify(currentTable, null, 2), 'utf8');
}

export interface EscalationDecision {
  shouldEscalate: boolean;
  targetRole: AgentRole;
  reason?: string;
}

export function evaluateEscalation(
  currentRole: AgentRole,
  attempts: number,
  maxAttempts: number,
  hasWriteViolation: boolean,
  hasContractViolation: boolean
): EscalationDecision {
  if (hasWriteViolation) {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: 'Violação mecânica de allowlist de escrita detectada',
    };
  }

  if (hasContractViolation) {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: 'Violação de invariante ou contrato arquitetural detectada',
    };
  }

  if (attempts >= maxAttempts && currentRole === 'cheap') {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: `Tentativas esgotadas (${attempts}/${maxAttempts}) para agente 'cheap'`,
    };
  }

  return {
    shouldEscalate: false,
    targetRole: currentRole,
  };
}
