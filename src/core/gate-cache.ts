import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { GateOutput } from './gates.js';
import { lawsDigest } from './validator.js';
import harnessManifest from '../../package.json' with { type: 'json' };

/** Versão do formato de cache. Um cache gravado por outra versão nunca é servido. */
export const GATE_CACHE_VERSION = '2';

/**
 * Versão do harness que gravou o cache, lida do `package.json` embutido — nunca
 * de uma cópia literal neste arquivo, que sairia de sincronia no próximo bump e
 * faria cache velho passar por atual.
 */
export const HARNESS_VERSION: string = harnessManifest.version;

/** Envelope persistido em disco: metadados de versão + o GateOutput completo + assinatura HMAC. */
export interface GateCacheEnvelope {
  gate_version: string;
  harness_version: string;
  laws_sha256: string;
  computed_at: string;
  output: GateOutput;
  signature?: string;
}
let sessionKey: string | null = null;

/** Chave de verificação para HMAC-SHA256 dos vereditos de gate. */
export function getVerifierKey(workDir: string): string {
  if (process.env.PWN_VERIFIER_KEY && process.env.PWN_VERIFIER_KEY.trim()) {
    return process.env.PWN_VERIFIER_KEY.trim();
  }
  const keyPath = path.join(workDir, '.piwerness', '.verifier_key');
  if (fs.existsSync(keyPath)) {
    try {
      const stats = fs.statSync(keyPath);
      // Assegurar permissão 0600 (não legível por outros usuários)
      if (process.platform !== 'win32' && (stats.mode & 0o077) !== 0) {
        try { fs.chmodSync(keyPath, 0o600); } catch { /* ignore */ }
      }
      const existing = fs.readFileSync(keyPath, 'utf8').trim();
      if (existing) return existing;
    } catch {
      // ignore
    }
  }
  if (sessionKey) return sessionKey;
  const generated = crypto.randomBytes(32).toString('hex');
  try {
    const dir = path.dirname(keyPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(keyPath, generated, { encoding: 'utf8', mode: 0o600 });
  } catch {
    // se não puder gravar em disco (ex: fs somente-leitura), retém chave em memória para a sessão
    sessionKey = generated;
  }
  return generated;
}
function canonicalGatePayload(
  gate: string,
  workId: string,
  inputVersions: Record<string, string>,
  result: string,
  findings: unknown[],
  summary: unknown,
  lawsSha256: string,
  gateVersion: string,
  harnessVersion: string,
): string {
  const sortedInputs = Object.keys(inputVersions)
    .sort()
    .map((k) => [k, inputVersions[k]]);
  return JSON.stringify([
    gate,
    workId,
    sortedInputs,
    result,
    findings,
    summary,
    lawsSha256,
    gateVersion,
    harnessVersion,
  ]);
}

export function signVerdict(output: GateOutput, workDir: string, lawsSha256: string): string {
  const secret = getVerifierKey(workDir);
  const payload = canonicalGatePayload(
    output.gate,
    output.work_id,
    output.input_versions ?? {},
    output.result,
    output.findings,
    output.summary,
    lawsSha256,
    GATE_CACHE_VERSION,
    HARNESS_VERSION,
  );
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export function verifyVerdict(
  output: GateOutput,
  workDir: string,
  lawsSha256: string,
  signature: string,
  gateVersion: string,
  harnessVersion: string,
): boolean {
  const secret = getVerifierKey(workDir);
  const payload = canonicalGatePayload(
    output.gate,
    output.work_id,
    output.input_versions ?? {},
    output.result,
    output.findings,
    output.summary,
    lawsSha256,
    gateVersion,
    harnessVersion,
  );
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature, 'utf8'), Buffer.from(expected, 'utf8'));
}

/**
 * Diretório do cache de gates: `.piwerness/gate-cache/` sob o `workDir` informado.
 * O `workDir` é a raiz que contém `.piwerness/` (o mesmo `rootDir` dos demais comandos).
 */
function cacheDir(workDir: string): string {
  return path.join(workDir, '.piwerness', 'gate-cache');
}

/** Caminho determinístico do arquivo de cache para um par gate + hashes de input. */
function cacheFilePath(gate: string, workDir: string, inputVersions: Record<string, string>): string {
  return path.join(cacheDir(workDir), `${gate}-${gateCacheKey(gate, inputVersions)}.json`);
}

/**
 * Chave estável para o par gate + hashes de input.
 * Independente da ordem das chaves: as entradas são ordenadas antes do hash.
 * `sha256(JSON.stringify(sortedEntries))` truncado em 12 chars hex.
 */
export function gateCacheKey(gate: string, inputVersions: Record<string, string>): string {
  const sortedEntries = Object.keys(inputVersions)
    .sort()
    .map((key) => [key, inputVersions[key]] as const);
  const payload = JSON.stringify([gate, sortedEntries]);
  return crypto.createHash('sha256').update(payload).digest('hex').slice(0, 12);
}

/**
 * Lê o cache; retorna `null` se ausente, corrompido, ou se `gate_version`/
 * `harness_version` não batem com as versões correntes. Nunca lança.
 */
export function readGateCache(gate: string, workDir: string, inputVersions: Record<string, string>): GateOutput | null {
  try {
    const file = cacheFilePath(gate, workDir, inputVersions);
    if (!fs.existsSync(file)) return null;

    const envelope = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<GateCacheEnvelope> | null;
    if (!envelope || typeof envelope !== 'object') return null;
    if (envelope.gate_version !== GATE_CACHE_VERSION) return null;
    if (envelope.harness_version !== HARNESS_VERSION) return null;

    // Se laws_sha256 divergir das leis embutidas correntes, invalida o cache
    if (envelope.laws_sha256 && envelope.laws_sha256 !== lawsDigest()) return null;

    const output = envelope.output;
    if (!output || typeof output !== 'object') return null;
    if (output.gate !== gate) return null;

    // Defensivo: os hashes gravados devem bater com os solicitados.
    const cachedVersions = output.input_versions ?? {};
    const requestedKeys = Object.keys(inputVersions);
    if (requestedKeys.length !== Object.keys(cachedVersions).length) return null;
    for (const key of requestedKeys) {
      if (cachedVersions[key] !== inputVersions[key]) return null;
    }

    // Assinatura HMAC é estritamente obrigatória na versão 2
    if (!envelope.signature) {
      return null;
    }
    const valid = verifyVerdict(
      output,
      workDir,
      envelope.laws_sha256 ?? lawsDigest(),
      envelope.signature,
      envelope.gate_version,
      envelope.harness_version,
    );
    if (!valid) {
      // Assinatura inválida: arquivo forjado ou adulterado -> rejeita
      return null;
    }

    return output;
  } catch {
    return null;
  }
}

/** Grava o output do gate no cache. Qualquer erro de IO é silenciado (no-op). */
export function writeGateCache(output: GateOutput, workDir: string): void {
  try {
    const dir = cacheDir(workDir);
    fs.mkdirSync(dir, { recursive: true });
    const currentLaws = lawsDigest();
    const signature = signVerdict(output, workDir, currentLaws);
    const envelope: GateCacheEnvelope = {
      gate_version: GATE_CACHE_VERSION,
      harness_version: HARNESS_VERSION,
      laws_sha256: currentLaws,
      computed_at: new Date().toISOString(),
      output,
      signature,
    };
    const file = cacheFilePath(output.gate, workDir, output.input_versions ?? {});
    fs.writeFileSync(file, JSON.stringify(envelope, null, 2), 'utf8');
  } catch {
    // Cache é uma otimização: falha de escrita nunca interrompe o gate.
  }
}

/** Remove os arquivos de cache de um diretório e devolve quantos removeu. */
function removeCacheDir(dir: string): number {
  let removed = 0;
  try {
    if (!fs.existsSync(dir)) return 0;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      try {
        fs.unlinkSync(path.join(dir, entry.name));
        removed += 1;
      } catch {
        // Ignora arquivos que não puderam ser removidos.
      }
    }
    if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
  } catch {
    return removed;
  }
  return removed;
}

/**
 * Remove o cache de gates. Com `workDir`, remove o cache daquele diretório; sem
 * argumento, remove o cache do diretório atual e de todos os Works sob
 * `.piwerness/work/*`. Devolve quantos arquivos removeu.
 */
export function clearGateCache(workDir?: string): number {
  if (workDir) return removeCacheDir(cacheDir(workDir));

  const root = process.cwd();
  let removed = removeCacheDir(cacheDir(root));
  const workRoot = path.join(root, '.piwerness', 'work');
  try {
    if (fs.existsSync(workRoot)) {
      for (const entry of fs.readdirSync(workRoot, { withFileTypes: true })) {
        if (entry.isDirectory()) removed += removeCacheDir(cacheDir(path.join(workRoot, entry.name)));
      }
    }
  } catch {
    // Ignora falhas ao enumerar Works.
  }
  return removed;
}
