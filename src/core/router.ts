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
