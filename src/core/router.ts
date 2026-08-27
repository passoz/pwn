import fs from 'node:fs';
import path from 'node:path';
import { RiskLevel } from './contract-engine.js';

export type AgentRole = 'cheap' | 'strong' | 'review' | 'plan';
export type ReasoningEffort = 'off' | 'low' | 'medium' | 'high';

export interface ModelRoutingConfig {
  role: AgentRole;
  defaultModel: string;
  maxTokens: number;
  temperature: number;
  reasoningEffort?: ReasoningEffort;
  baseUrl?: string;
  provider?: string;
  apiKeyEnv?: string;
  apiKey?: string;
}

/**
 * Execution policy — separates model selection from permissions.
 *
 * The model chosen does not determine the execution environment alone.
 * A cheap model on a high-risk task still gets restricted permissions.
 */
export interface ExecutionPolicy {
  /** Whether the agent can write files */
  canWrite: boolean;
  /** Whether the agent can execute shell commands */
  canShell: boolean;
  /** Whether the agent can make network requests */
  canNetwork: boolean;
  /** Maximum file writes per run */
  maxFileWrites: number;
  /** Whether human review is required before merging */
  requiresReview: boolean;
}

export const DEFAULT_ROUTING_TABLE: Record<AgentRole, ModelRoutingConfig> = {
  cheap: {
    role: 'cheap',
    defaultModel: 'qwen3.5:27b',
    maxTokens: 4000,
    temperature: 0.2,
    reasoningEffort: 'low',
  },
  strong: {
    role: 'strong',
    defaultModel: 'claude-3-7-sonnet',
    maxTokens: 16000,
    temperature: 0.1,
    reasoningEffort: 'high',
  },
  review: {
    role: 'review',
    defaultModel: 'claude-3-5-haiku',
    maxTokens: 8000,
    temperature: 0.1,
    reasoningEffort: 'low',
  },
  plan: {
    role: 'plan',
    defaultModel: 'claude-3-7-sonnet',
    maxTokens: 12000,
    temperature: 0.2,
    reasoningEffort: 'medium',
  },
};

/**
 * Risk → initial role mapping.
 *
 * L0-L1: cheap execution (low risk, fast, economical)
 * L2: cheap + mandatory review
 * L3: strong (complex reasoning needed)
 * L4: human review required (never fully autonomous)
 */
export const RISK_ROLE_MAP: Record<RiskLevel, { initialRole: AgentRole; requiresReview: boolean }> = {
  L0: { initialRole: 'cheap', requiresReview: false },
  L1: { initialRole: 'cheap', requiresReview: false },
  L2: { initialRole: 'cheap', requiresReview: true },
  L3: { initialRole: 'strong', requiresReview: false },
  L4: { initialRole: 'strong', requiresReview: true },
};

/**
 * Execution policies by risk level.
 *
 * Higher risk = more restrictions, even if the model is powerful.
 * This ensures model selection does not determine permissions.
 */
export const RISK_EXECUTION_POLICY: Record<RiskLevel, ExecutionPolicy> = {
  L0: { canWrite: true, canShell: true, canNetwork: true, maxFileWrites: 50, requiresReview: false },
  L1: { canWrite: true, canShell: true, canNetwork: true, maxFileWrites: 30, requiresReview: false },
  L2: { canWrite: true, canShell: true, canNetwork: false, maxFileWrites: 20, requiresReview: true },
  L3: { canWrite: true, canShell: false, canNetwork: false, maxFileWrites: 10, requiresReview: false },
  L4: { canWrite: false, canShell: false, canNetwork: false, maxFileWrites: 0, requiresReview: true },
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
          if (fileData[role].reasoningEffort !== undefined) table[role].reasoningEffort = fileData[role].reasoningEffort;
          if (fileData[role].baseUrl !== undefined) table[role].baseUrl = fileData[role].baseUrl;
          if (fileData[role].provider !== undefined) table[role].provider = fileData[role].provider;
          if (fileData[role].apiKeyEnv !== undefined) table[role].apiKeyEnv = fileData[role].apiKeyEnv;
          if (fileData[role].apiKey !== undefined) table[role].apiKey = fileData[role].apiKey;
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

  if (process.env.PWN_API_BASE_URL_CHEAP) table.cheap.baseUrl = process.env.PWN_API_BASE_URL_CHEAP;
  if (process.env.PWN_API_BASE_URL_STRONG) table.strong.baseUrl = process.env.PWN_API_BASE_URL_STRONG;
  if (process.env.PWN_API_BASE_URL_REVIEW) table.review.baseUrl = process.env.PWN_API_BASE_URL_REVIEW;
  if (process.env.PWN_API_BASE_URL_PLAN) table.plan.baseUrl = process.env.PWN_API_BASE_URL_PLAN;

  if (process.env.PWN_API_KEY_CHEAP) table.cheap.apiKey = process.env.PWN_API_KEY_CHEAP;
  if (process.env.PWN_API_KEY_STRONG) table.strong.apiKey = process.env.PWN_API_KEY_STRONG;
  if (process.env.PWN_API_KEY_REVIEW) table.review.apiKey = process.env.PWN_API_KEY_REVIEW;
  if (process.env.PWN_API_KEY_PLAN) table.plan.apiKey = process.env.PWN_API_KEY_PLAN;

  if (process.env.PWN_REASONING_CHEAP) table.cheap.reasoningEffort = process.env.PWN_REASONING_CHEAP as ReasoningEffort;
  if (process.env.PWN_REASONING_STRONG) table.strong.reasoningEffort = process.env.PWN_REASONING_STRONG as ReasoningEffort;
  if (process.env.PWN_REASONING_REVIEW) table.review.reasoningEffort = process.env.PWN_REASONING_REVIEW as ReasoningEffort;
  if (process.env.PWN_REASONING_PLAN) table.plan.reasoningEffort = process.env.PWN_REASONING_PLAN as ReasoningEffort;

  return table;
}

export function saveRoutingConfig(
  newConfig: Partial<Record<AgentRole, Partial<ModelRoutingConfig>>>,
  rootDir: string = process.cwd(),
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

// ── Risk-aware routing ─────────────────────────────────────────────

export interface RoutingDecision {
  role: AgentRole;
  model: ModelRoutingConfig;
  executionPolicy: ExecutionPolicy;
  requiresReview: boolean;
  reason: string;
}

/**
 * Select the initial agent role and execution policy based on risk level.
 *
 * This separates model selection from execution policy:
 * - The model is chosen based on the role (cheap/strong/plan/review)
 * - The execution policy is determined by the risk level
 * - A cheap model on L3 still gets restricted shell/network access
 */
export function selectForRisk(
  riskLevel: RiskLevel,
  rootDir: string = process.cwd(),
): RoutingDecision {
  const { initialRole, requiresReview } = RISK_ROLE_MAP[riskLevel];
  const executionPolicy = RISK_EXECUTION_POLICY[riskLevel];
  const table = getRoutingTable(rootDir);
  const model = table[initialRole];

  return {
    role: initialRole,
    model,
    executionPolicy,
    requiresReview,
    reason: `Risk ${riskLevel} → role "${initialRole}" (review: ${requiresReview})`,
  };
}

export interface EscalationDecision {
  shouldEscalate: boolean;
  targetRole: AgentRole;
  reason?: string;
}

/**
 * Evaluate whether escalation is needed.
 *
 * Enhanced to consider risk level:
 * - L4 always escalates to human review
 * - L3 escalates to strong agent on any failure
 * - L0-L2 use standard escalation logic
 */
export function evaluateEscalation(
  currentRole: AgentRole,
  attempts: number,
  maxAttempts: number,
  hasWriteViolation: boolean,
  hasContractViolation: boolean,
  riskLevel?: RiskLevel,
): EscalationDecision {
  // L4 always requires human review — never fully autonomous
  if (riskLevel === 'L4') {
    return {
      shouldEscalate: true,
      targetRole: 'review',
      reason: 'Risk L4: requer revisão humana — nunca totalmente autônomo',
    };
  }

  // Write violation → always escalate
  if (hasWriteViolation) {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: 'Violação mecânica de allowlist de escrita detectada',
    };
  }

  // Contract violation → escalate
  if (hasContractViolation) {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: 'Violação de invariante ou contrato arquitetural detectada',
    };
  }

  // Attempts exhausted → escalate from cheap to strong
  if (attempts >= maxAttempts && currentRole === 'cheap') {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: `Tentativas esgotadas (${attempts}/${maxAttempts}) para agente 'cheap'`,
    };
  }

  // L3: escalate on first failure (strict)
  if (riskLevel === 'L3' && attempts >= 1 && currentRole === 'cheap') {
    return {
      shouldEscalate: true,
      targetRole: 'strong',
      reason: 'Risk L3: primeira falha já aciona modelo forte',
    };
  }

  return {
    shouldEscalate: false,
    targetRole: currentRole,
  };
}
