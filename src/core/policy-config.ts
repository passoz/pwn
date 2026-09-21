/**
 * Policy Config — política declarativa OPCIONAL em `.piwerness/policy.json`.
 *
 * O arquivo nunca é obrigatório: ausente, malformado ou fora do schema ⇒ os
 * defaults do harness valem (aviso em `console.warn`, jamais lança). Quando
 * existe, cada seção é mesclada SOBRE os defaults — nunca os substitui por
 * inteiro — e o resultado é exposto por `resolvePolicy`.
 *
 * Formato no disco (snake_case, ver `schemas/policy.schema.json`):
 *   {
 *     "risk_keywords": { "l3": [...], "l1": [...] },
 *     "gate_thresholds": { "max_findings_before_block": 0, "max_acs_per_task": 0 },
 *     "shell": { "allowed_commands": [{ "command": "bun", "args": ["test"] }], "denied_commands": [...], "allow_all_shell": false },
 *     "network": { "allowed_domains": [...], "denied_domains": [...], "allow_all_network": false }
 *   }
 */

import fs from 'node:fs';
import path from 'node:path';
import { Ajv, type ValidateFunction } from 'ajv';
import policySchema from '../../schemas/policy.schema.json' with { type: 'json' };
import {
  DEFAULT_NETWORK_POLICY,
  DEFAULT_SHELL_POLICY,
  type CommandRule,
  type NetworkPolicy,
  type ShellPolicy,
} from './policy-engine.js';

const POLICY_RELATIVE_PATH = path.join('.piwerness', 'policy.json');

export interface PolicyConfigFile {
  risk_keywords?: { l3?: string[]; l1?: string[] };
  gate_thresholds?: { max_findings_before_block?: number; max_acs_per_task?: number };
  shell?: ShellPolicy;
  network?: NetworkPolicy;
}

/**
 * Defaults de `risk_keywords`. FONTE DE VERDADE ESPELHADA: as listas canônicas
 * vivem em `src/core/v3-import.ts` (`RISK_L3_KEYWORDS` / `RISK_L1_KEYWORDS`) e
 * são copiadas aqui LITERALMENTE — importá-las criaria ciclo de módulos.
 * Mantenha as duas cópias em sincronia.
 */
export const DEFAULT_RISK_KEYWORDS: { l3: string[]; l1: string[] } = {
  l3: [
    'auth', 'autentica', 'login', 'signin', 'signup', 'password', 'senha', 'credencial',
    'sessao', 'session', 'token', 'cookie', 'rbac', 'permissao', 'autorizacao', 'papel',
    'seguranca', 'security', 'hardening', 'webhook', 'hmac', 'assinatura', 'signature',
    'pagamento', 'payment', 'estorno', 'refund', 'crypto', 'secret', 'csrf', 'cors',
    'rate limit', 'rate-limit', 'privacidade', 'privacy', 'lgpd', 'middleware', 'bcrypt',
    'argon2', 'hash', 'csrf', 'oauth',
  ],
  l1: [
    'readme', 'documentacao', 'documentation', 'comentario', 'formatacao', 'estilo',
    'tipografia', 'copy', 'changelog', 'licenca', 'license',
  ],
};

/** Defaults dos limiares de gate. `0` = nenhum achado tolerado / sem limite explícito. */
export const DEFAULT_GATE_THRESHOLDS: { max_findings_before_block: number; max_acs_per_task: number } = {
  max_findings_before_block: 0,
  max_acs_per_task: 0,
};

/** Caminho canônico do arquivo de política. */
export function policyFilePath(rootDir: string = process.cwd()): string {
  return path.join(rootDir, POLICY_RELATIVE_PATH);
}

// ── Validação ──────────────────────────────────────────────────────

let compiledValidator: ValidateFunction | null = null;

/**
 * Compila (uma vez) o schema de política, **embutido no bundle**. Não depende do
 * disco: o binário movido para outro diretório valida `.piwerness/policy.json`
 * contra a mesma lei.
 */
function policyValidator(): ValidateFunction {
  if (!compiledValidator) {
    compiledValidator = new Ajv({ allErrors: true, strict: false }).compile(structuredClone(policySchema));
  }
  return compiledValidator;
}

// ── Normalização (snake_case do arquivo → tipos do PolicyEngine) ────

function copyStringArray(value: unknown, fallback: readonly string[]): string[] {
  if (!Array.isArray(value)) return [...fallback];
  return value.filter((entry): entry is string => typeof entry === 'string');
}

function copyCommandRules(value: unknown, fallback: readonly CommandRule[]): CommandRule[] {
  if (!Array.isArray(value)) return fallback.map((rule) => (rule.args ? { command: rule.command, args: [...rule.args] } : { command: rule.command }));
  return value.map((entry) => {
    const rule = entry as CommandRule;
    return rule.args ? { command: rule.command, args: [...rule.args] } : { command: rule.command };
  });
}

/**
 * Converte um documento já validado para a forma tipada.
 * Subcampos ausentes caem nos defaults (ex.: `shell` só com `allow_all_shell`
 * preserva a denylist padrão).
 */
function normalizePolicyFile(raw: Record<string, unknown>): PolicyConfigFile {
  const out: PolicyConfigFile = {};

  const risks = raw.risk_keywords as { l3?: unknown; l1?: unknown } | undefined;
  if (risks) {
    out.risk_keywords = {};
    if (risks.l3 !== undefined) out.risk_keywords.l3 = copyStringArray(risks.l3, DEFAULT_RISK_KEYWORDS.l3);
    if (risks.l1 !== undefined) out.risk_keywords.l1 = copyStringArray(risks.l1, DEFAULT_RISK_KEYWORDS.l1);
  }

  const thresholds = raw.gate_thresholds as { max_findings_before_block?: unknown; max_acs_per_task?: unknown } | undefined;
  if (thresholds) {
    out.gate_thresholds = {};
    if (typeof thresholds.max_findings_before_block === 'number') {
      out.gate_thresholds.max_findings_before_block = thresholds.max_findings_before_block;
    }
    if (typeof thresholds.max_acs_per_task === 'number') {
      out.gate_thresholds.max_acs_per_task = thresholds.max_acs_per_task;
    }
  }

  const shell = raw.shell as Record<string, unknown> | undefined;
  if (shell) {
    out.shell = {
      allowedCommands: copyCommandRules(shell.allowed_commands, DEFAULT_SHELL_POLICY.allowedCommands),
      deniedCommands: copyCommandRules(shell.denied_commands, DEFAULT_SHELL_POLICY.deniedCommands),
      allowAllShell:
        typeof shell.allow_all_shell === 'boolean' ? shell.allow_all_shell : DEFAULT_SHELL_POLICY.allowAllShell ?? false,
    };
  }

  const network = raw.network as Record<string, unknown> | undefined;
  if (network) {
    out.network = {
      allowedDomains: copyStringArray(network.allowed_domains, DEFAULT_NETWORK_POLICY.allowedDomains),
      deniedDomains: copyStringArray(network.denied_domains, DEFAULT_NETWORK_POLICY.deniedDomains),
      allowAllNetwork:
        typeof network.allow_all_network === 'boolean' ? network.allow_all_network : DEFAULT_NETWORK_POLICY.allowAllNetwork ?? false,
    };
  }

  return out;
}

/** Lê e valida `.piwerness/policy.json`. Retorna null se ausente/inválido (nunca lança). */
export function loadPolicyFile(rootDir: string = process.cwd()): PolicyConfigFile | null {
  const filePath = policyFilePath(rootDir);
  if (!fs.existsSync(filePath)) return null;

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.warn(`[policy] ${filePath} não é JSON válido (${(err as Error).message}) — usando defaults`);
    return null;
  }

  const validate = policyValidator();
  if (!validate(raw)) {
    const detail = (validate.errors ?? [])
      .map((err) => `${err.instancePath || '/'} ${err.message ?? 'inválido'}`)
      .join('; ');
    console.warn(`[policy] ${filePath} fora do schema: ${detail} — usando defaults`);
    return null;
  }

  return normalizePolicyFile(raw as Record<string, unknown>);
}

// ── Resolução efetiva ──────────────────────────────────────────────

/** Resolve a política efetiva: arquivo (se existir) mesclado sobre os defaults. */
export function resolvePolicy(rootDir: string = process.cwd()): {
  risk_keywords: { l3: string[]; l1: string[] };
  gate_thresholds: { max_findings_before_block: number; max_acs_per_task: number };
  shell: ShellPolicy;
  network: NetworkPolicy;
  source: 'file' | 'defaults';
} {
  const file = loadPolicyFile(rootDir);

  const risk_keywords = {
    l3: file?.risk_keywords?.l3 ? [...file.risk_keywords.l3] : [...DEFAULT_RISK_KEYWORDS.l3],
    l1: file?.risk_keywords?.l1 ? [...file.risk_keywords.l1] : [...DEFAULT_RISK_KEYWORDS.l1],
  };
  const gate_thresholds = {
    max_findings_before_block:
      file?.gate_thresholds?.max_findings_before_block ?? DEFAULT_GATE_THRESHOLDS.max_findings_before_block,
    max_acs_per_task: file?.gate_thresholds?.max_acs_per_task ?? DEFAULT_GATE_THRESHOLDS.max_acs_per_task,
  };

  // Cópia defensiva: a política resolvida nunca compartilha arrays com os defaults.
  const baseShell = file?.shell ?? DEFAULT_SHELL_POLICY;
  const shell: ShellPolicy = {
    allowedCommands: copyCommandRules(baseShell.allowedCommands, []),
    deniedCommands: copyCommandRules(baseShell.deniedCommands, []),
    allowAllShell: baseShell.allowAllShell ?? false,
  };
  const baseNetwork = file?.network ?? DEFAULT_NETWORK_POLICY;
  const network: NetworkPolicy = {
    allowedDomains: [...baseNetwork.allowedDomains],
    deniedDomains: [...baseNetwork.deniedDomains],
    allowAllNetwork: baseNetwork.allowAllNetwork ?? false,
  };

  return { risk_keywords, gate_thresholds, shell, network, source: file ? 'file' : 'defaults' };
}
