import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, rmSync } from "node:fs";
import path from "node:path";

import { assertProtectedOutsideRepository, initializeVerifierHome, verifierRoot, writeFileAtomic } from "../verifier-home.js";

/**
 * Configuração do operador-decisor de UM projeto (docs/future/operador-decisor.md).
 *
 * Vive na raiz do verificador, fora do repositório: o agente que escreve plano, testes
 * e código não pode escolher quem o aprova. Presença de configuração habilitada liga o
 * decisor por padrão no projeto; ausência significa que não há decisor.
 * A credencial nunca é gravada: guarda-se o NOME da variável de ambiente que a contém.
 */

/** Provedores com adaptador conhecido. */
export const DECIDER_PROVIDERS: Record<string, true> = { jev: true };
export const RISK_LEVELS = ["L0", "L1", "L2", "L3", "L4"] as const;
export type RiskCeiling = (typeof RISK_LEVELS)[number];

export const DEFAULT_DECIDER = "jev:jev-latest";
export const DEFAULT_KEY_ENV = "TYPESAFE_API_KEY";
export const DEFAULT_MAX_RISK: RiskCeiling = "L3";
/** Anúncio do agente hospedeiro: vira a sugestão padrão no `pwn init`, nunca autorização. */
export const HOST_DECIDER_ENV = "PWN_DECIDER";

/**
 * Pontos de decisão do operador que o decisor pode assumir (ver `engine.ts`):
 * aprovação dos critérios, fila L4, tasks retidas no lote e elevação de `--risk auto`.
 */
export const DECIDER_SCOPES = ["approve", "queue", "batch", "risk"] as const;
export type DecisionPoint = (typeof DECIDER_SCOPES)[number];

export interface EnabledDeciderConfig {
  version: 1;
  enabled: true;
  project: string;
  /** `<provedor>:<modelo>`, ex.: `jev:jev-latest`. */
  decider: string;
  key_env: string;
  max_risk: RiskCeiling;
  scope: DecisionPoint[];
  /** Endpoint alternativo do provedor (ex.: proxy próprio); `null` = endpoint oficial do adaptador. */
  endpoint: string | null;
  configured_at: string;
}

export interface DisabledDeciderConfig {
  version: 1;
  enabled: false;
  project: string;
  configured_at: string;
}

export type DeciderConfig = EnabledDeciderConfig | DisabledDeciderConfig;

export interface DeciderInput {
  decider: string;
  keyEnv: string;
  maxRisk: string;
  endpoint?: string | null;
}

export interface ValidDeciderInput {
  decider: string;
  keyEnv: string;
  maxRisk: RiskCeiling;
  endpoint: string | null;
}

/** Valida os valores informados pelo operador; lança com mensagem acionável. */
export function validateDeciderInput(input: DeciderInput): ValidDeciderInput {
  const decider = input.decider.trim();
  const separator = decider.indexOf(":");
  const provider = separator === -1 ? "" : decider.slice(0, separator);
  const model = separator === -1 ? "" : decider.slice(separator + 1);
  if (!provider || !model) throw new Error(`decisor inválido: '${decider}' (formato <provedor>:<modelo>, ex.: ${DEFAULT_DECIDER})`);
  if (!DECIDER_PROVIDERS[provider]) {
    throw new Error(`provedor de decisor sem adaptador: '${provider}' (disponíveis: ${Object.keys(DECIDER_PROVIDERS).join(", ")})`);
  }
  const keyEnv = input.keyEnv.trim();
  if (!/^[A-Z_][A-Z0-9_]*$/.test(keyEnv)) throw new Error(`nome de variável de ambiente inválido para a chave: '${keyEnv}'`);
  const maxRisk = input.maxRisk.trim().toUpperCase();
  if (!(RISK_LEVELS as readonly string[]).includes(maxRisk)) {
    throw new Error(`teto de risco inválido: '${input.maxRisk}' (use ${RISK_LEVELS.join(", ")})`);
  }
  const endpoint = input.endpoint?.trim() || null;
  if (endpoint && !/^https?:\/\/[^\s]+$/.test(endpoint)) throw new Error(`endpoint do decisor inválido: '${endpoint}' (use http(s)://…)`);
  return { decider, keyEnv, maxRisk: maxRisk as RiskCeiling, endpoint };
}

/** Raiz canônica do projeto: a mesma configuração vale de qualquer subdiretório ou symlink. */
export function projectIdentity(repositoryRoot: string): string {
  return realpathSync(repositoryRoot);
}

function configPath(repositoryRoot: string, root: string): string {
  const id = createHash("sha256").update(projectIdentity(repositoryRoot)).digest("hex").slice(0, 16);
  return path.join(root, "deciders", `${id}.json`);
}

export function readDeciderConfig(repositoryRoot: string, root: string = verifierRoot()): DeciderConfig | null {
  const file = configPath(repositoryRoot, root);
  if (!existsSync(file)) return null;
  const parsed = JSON.parse(readFileSync(file, "utf8")) as DeciderConfig;
  if (parsed?.version !== 1 || parsed.project !== projectIdentity(repositoryRoot)) {
    throw new Error(`configuração do decisor inválida ou de outro projeto: ${file}`);
  }
  return parsed;
}

/** Grava a escolha do operador (habilitada ou explicitamente sem decisor). */
export function writeDeciderConfig(
  repositoryRoot: string,
  input: DeciderInput | null,
  root: string = verifierRoot(),
): DeciderConfig {
  initializeVerifierHome(root);
  assertProtectedOutsideRepository(root, repositoryRoot);
  const project = projectIdentity(repositoryRoot);
  const configuredAt = new Date().toISOString();
  const config: DeciderConfig = input
    ? (() => {
        const valid = validateDeciderInput(input);
        return {
          version: 1,
          enabled: true,
          project,
          decider: valid.decider,
          key_env: valid.keyEnv,
          max_risk: valid.maxRisk,
          scope: [...DECIDER_SCOPES],
          endpoint: valid.endpoint,
          configured_at: configuredAt,
        };
      })()
    : { version: 1, enabled: false, project, configured_at: configuredAt };
  writeFileAtomic(configPath(repositoryRoot, root), `${JSON.stringify(config, null, 2)}\n`, 0o600);
  return config;
}

/** Remove a configuração do projeto: sem ela, não há decisor. Devolve se havia algo a remover. */
export function removeDeciderConfig(repositoryRoot: string, root: string = verifierRoot()): boolean {
  const file = configPath(repositoryRoot, root);
  if (!existsSync(file)) return false;
  rmSync(file);
  return true;
}
