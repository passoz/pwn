import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  GATE_CACHE_VERSION,
  HARNESS_VERSION,
  gateCacheKey,
  readGateCache,
  writeGateCache,
  clearGateCache,
  signVerdict,
} from '../src/core/gate-cache.js';
import { lawsDigest } from '../src/core/validator.js';
import type { GateOutput } from '../src/core/gates.js';
function fixtureDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-gate-cache-'));
}

function sampleOutput(gate: string, inputVersions: Record<string, string>): GateOutput {
  return {
    gate,
    work_id: '0001',
    input_versions: inputVersions,
    result: 'pass_with_notes',
    summary: { covered: 2, gaps: 1, conflicts: 0, ambiguities: 0, traceability_gaps: 0 },
    findings: [
      {
        id: 'FIND-01',
        severity: 'medium',
        type: 'coverage_gap',
        source_refs: ['discovery.json'],
        target_refs: ['requirements.json'],
        description: 'Lacuna de exemplo',
        required_resolution: 'Cobrir o requisito',
        resolution_owner: 'product-owner',
        status: 'open',
      },
    ],
  };
}

function cacheFilePath(workDir: string, gate: string, inputVersions: Record<string, string>): string {
  return path.join(workDir, '.pwn', 'gate-cache', `${gate}-${gateCacheKey(gate, inputVersions)}.json`);
}

describe('gate-cache', () => {
  test('(a) writeGateCache seguido de readGateCache devolve output idêntico', () => {
    const workDir = fixtureDir();
    try {
      const output = sampleOutput('GATE-DISC-REQ', { discovery: 'aaa', requirements: 'bbb' });
      writeGateCache(output, workDir);

      const cached = readGateCache('GATE-DISC-REQ', workDir, output.input_versions);
      expect(cached).toEqual(output);
      // round-trip JSON preserva todos os campos relevantes
      expect(cached?.findings[0].required_resolution).toBe('Cobrir o requisito');
      expect(cached?.summary.gaps).toBe(1);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(b) readGateCache devolve null quando os input_versions mudam', () => {
    const workDir = fixtureDir();
    try {
      writeGateCache(sampleOutput('GATE-REQ-PRD', { requirements: 'aaa', prd: 'bbb' }), workDir);

      expect(readGateCache('GATE-REQ-PRD', workDir, { requirements: 'aaa', prd: 'bbb' })).not.toBeNull();
      expect(readGateCache('GATE-REQ-PRD', workDir, { requirements: 'aaa', prd: 'CCC' })).toBeNull();
      expect(readGateCache('GATE-REQ-PRD', workDir, { requirements: 'aaa' })).toBeNull();
      expect(readGateCache('GATE-REQ-PRD', workDir, { requirements: 'aaa', prd: 'bbb', extra: 'x' })).toBeNull();
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(c) readGateCache devolve null com gate_version ou harness_version divergentes', () => {
    const workDir = fixtureDir();
    try {
      const inputVersions = { spec: 'aaa', plan: 'bbb' };
      const file = cacheFilePath(workDir, 'GATE-SPEC-PLAN', inputVersions);
      fs.mkdirSync(path.dirname(file), { recursive: true });

      fs.writeFileSync(file, JSON.stringify({
        gate_version: '999',
        harness_version: HARNESS_VERSION,
        computed_at: new Date().toISOString(),
        output: sampleOutput('GATE-SPEC-PLAN', inputVersions),
      }), 'utf8');
      expect(readGateCache('GATE-SPEC-PLAN', workDir, inputVersions)).toBeNull();

      fs.writeFileSync(file, JSON.stringify({
        gate_version: GATE_CACHE_VERSION,
        harness_version: '0.0.0',
        computed_at: new Date().toISOString(),
        output: sampleOutput('GATE-SPEC-PLAN', inputVersions),
      }), 'utf8');
      expect(readGateCache('GATE-SPEC-PLAN', workDir, inputVersions)).toBeNull();

      // sanity: com as versões corretas e assinatura válida o arquivo é servido
      const validOut = sampleOutput('GATE-SPEC-PLAN', inputVersions);
      const currentLaws = lawsDigest();
      fs.writeFileSync(file, JSON.stringify({
        gate_version: GATE_CACHE_VERSION,
        harness_version: HARNESS_VERSION,
        laws_sha256: currentLaws,
        computed_at: new Date().toISOString(),
        output: validOut,
        signature: signVerdict(validOut, workDir, currentLaws),
      }), 'utf8');
      expect(readGateCache('GATE-SPEC-PLAN', workDir, inputVersions)).not.toBeNull();
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(c2) readGateCache devolve null para arquivo ausente ou corrompido', () => {
    const workDir = fixtureDir();
    try {
      expect(readGateCache('GATE-DISC-REQ', workDir, { discovery: 'aaa' })).toBeNull();

      const inputVersions = { discovery: 'aaa' };
      const file = cacheFilePath(workDir, 'GATE-DISC-REQ', inputVersions);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, '{ isto não é json', 'utf8');
      expect(readGateCache('GATE-DISC-REQ', workDir, inputVersions)).toBeNull();
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(d) clearGateCache remove os arquivos e devolve a contagem', () => {
    const workDir = fixtureDir();
    try {
      writeGateCache(sampleOutput('GATE-DISC-REQ', { discovery: 'aaa', requirements: 'bbb' }), workDir);
      writeGateCache(sampleOutput('GATE-REQ-PRD', { requirements: 'bbb', prd: 'ccc' }), workDir);

      expect(clearGateCache(workDir)).toBe(2);
      expect(readGateCache('GATE-DISC-REQ', workDir, { discovery: 'aaa', requirements: 'bbb' })).toBeNull();
      expect(readGateCache('GATE-REQ-PRD', workDir, { requirements: 'bbb', prd: 'ccc' })).toBeNull();
      // segunda limpeza não tem o que remover
      expect(clearGateCache(workDir)).toBe(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(e) gateCacheKey é determinístico e independente da ordem das chaves', () => {
    const first = gateCacheKey('GATE-DISC-REQ', { discovery: 'aaa', requirements: 'bbb' });
    const second = gateCacheKey('GATE-DISC-REQ', { discovery: 'aaa', requirements: 'bbb' });
    const reordered = gateCacheKey('GATE-DISC-REQ', { requirements: 'bbb', discovery: 'aaa' });

    expect(first).toBe(second);
    expect(reordered).toBe(first);
    expect(first).toMatch(/^[0-9a-f]{12}$/);
    expect(gateCacheKey('GATE-REQ-PRD', { discovery: 'aaa', requirements: 'bbb' })).not.toBe(first);
    expect(gateCacheKey('GATE-DISC-REQ', { discovery: 'aaa', requirements: 'CCC' })).not.toBe(first);
  });

  test('(f) readGateCache rejeita envelope adulterado (HMAC inválido)', () => {
    const workDir = fixtureDir();
    try {
      const inputVersions = { prd: '111', spec: '222' };
      const out = sampleOutput('GATE-PRD-SPEC', inputVersions);
      out.result = 'blocked';
      writeGateCache(out, workDir);

      // Leitura legítima passa
      const cached = readGateCache('GATE-PRD-SPEC', workDir, inputVersions);
      expect(cached).not.toBeNull();
      expect(cached?.result).toBe('blocked');

      // Agora adulteramos o arquivo em disco: alteramos 'blocked' para 'pass'
      const file = cacheFilePath(workDir, 'GATE-PRD-SPEC', inputVersions);
      const content = JSON.parse(fs.readFileSync(file, 'utf8'));
      content.output.result = 'pass';
      content.output.findings = [];
      fs.writeFileSync(file, JSON.stringify(content, null, 2), 'utf8');

      // Leitura DEVE rejeitar o arquivo forjado
      const forged = readGateCache('GATE-PRD-SPEC', workDir, inputVersions);
      expect(forged).toBeNull();
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  test('(g) readGateCache rejeita envelope com laws_sha256 divergente', () => {
    const workDir = fixtureDir();
    try {
      const inputVersions = { prd: '111', spec: '222' };
      const out = sampleOutput('GATE-PRD-SPEC', inputVersions);
      writeGateCache(out, workDir);

      const file = cacheFilePath(workDir, 'GATE-PRD-SPEC', inputVersions);
      const content = JSON.parse(fs.readFileSync(file, 'utf8'));
      content.laws_sha256 = '0000000000000000';
      fs.writeFileSync(file, JSON.stringify(content, null, 2), 'utf8');

      expect(readGateCache('GATE-PRD-SPEC', workDir, inputVersions)).toBeNull();
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});
