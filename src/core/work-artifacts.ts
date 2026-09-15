import fs from 'node:fs';
import path from 'node:path';
import { listWorkIds } from './work-manifest.js';

export interface WorkArtifactsPaths {
  workDir: string;
  intake: string;
  discovery: string;
  requirements: string;
  prd: string;
  technicalDecisions: string;
  spec: string;
  enrichment: string;
  workGovernance: string;
  plan: string;
  progress: string;
  traceabilityMatrix: string;
}

export function getExistingWorkIds(rootDir: string = process.cwd()): string[] {
  const baseDir = path.resolve(rootDir, '.piwerness/work');
  if (!fs.existsSync(baseDir)) {
    return [];
  }
  return fs.readdirSync(baseDir).filter(name => {
    try {
      const full = path.join(baseDir, name);
      if (!fs.statSync(full).isDirectory()) return false;
      // Diretório vazio não é um Work existente: não deve deslocar a numeração.
      return fs.readdirSync(full).length > 0;
    } catch {
      return false;
    }
  });
}

/**
 * Todos os Work IDs conhecidos, em qualquer trilha de artefatos.
 * A numeração (`getNextWorkId`/`getLatestWorkId`) usa este espaço de IDs
 * compartilhado com o manifest v3 (`.work/*.json`, `.todo/NNNN-tasks.md`, ...),
 * evitando colisão entre `pwn work init` e as reservas do manifest.
 */
function allWorkIds(rootDir: string): string[] {
  return listWorkIds(rootDir);
}

export function getLatestWorkId(rootDir: string = process.cwd()): string {
  const ids = allWorkIds(rootDir);
  if (ids.length === 0) {
    return '0001';
  }
  let maxNum = 0;
  for (const id of ids) {
    const num = parseInt(id, 10);
    if (!isNaN(num) && num > maxNum) {
      maxNum = num;
    }
  }
  if (maxNum === 0) {
    return ids[ids.length - 1];
  }
  return String(maxNum).padStart(4, '0');
}

export function getNextWorkId(rootDir: string = process.cwd()): string {
  const ids = allWorkIds(rootDir);
  if (ids.length === 0) {
    return '0001';
  }
  let maxNum = 0;
  for (const id of ids) {
    const num = parseInt(id, 10);
    if (!isNaN(num) && num > maxNum) {
      maxNum = num;
    }
  }
  const nextNum = maxNum + 1;
  return String(nextNum).padStart(4, '0');
}

export function getWorkArtifactsPaths(workId: string, rootDir: string = process.cwd()): WorkArtifactsPaths {
  const workDir = path.resolve(rootDir, '.piwerness/work', workId);

  return {
    workDir,
    intake: path.join(workDir, 'intake.json'),
    discovery: path.join(workDir, 'discovery.json'),
    requirements: path.join(workDir, 'requirements.json'),
    prd: path.join(workDir, 'prd.json'),
    technicalDecisions: path.join(workDir, 'technical-decisions.json'),
    spec: path.join(workDir, 'spec.json'),
    enrichment: path.join(workDir, 'enrichment.json'),
    workGovernance: path.join(workDir, 'work-governance.json'),
    plan: path.join(workDir, 'plan.json'),
    progress: path.join(workDir, 'progress.json'),
    traceabilityMatrix: path.join(workDir, 'traceability-matrix.json'),
  };
}

export function initWorkDirectory(workId?: string, rootDir: string = process.cwd()): WorkArtifactsPaths {
  const resolvedWorkId = (!workId || workId === 'auto') ? getNextWorkId(rootDir) : workId;
  const paths = getWorkArtifactsPaths(resolvedWorkId, rootDir);

  if (!fs.existsSync(paths.workDir)) {
    fs.mkdirSync(paths.workDir, { recursive: true });
  }

  // Create template files if they don't exist
  if (!fs.existsSync(paths.intake)) {
    fs.writeFileSync(paths.intake, JSON.stringify({
      work_id: resolvedWorkId,
      created_at: new Date().toISOString(),
      objective: "Objetivo do pedido bruto",
      requester: "operator",
      status: "draft"
    }, null, 2));
  }

  if (!fs.existsSync(paths.discovery)) {
    fs.writeFileSync(paths.discovery, JSON.stringify({
      work_id: resolvedWorkId,
      problem: "Descrição do problema",
      actors: ["ACT-001"],
      objectives: ["Objetivo principal"],
      constraints: ["Restrição de tecnologia/tempo"]
    }, null, 2));
  }

  if (!fs.existsSync(paths.requirements)) {
    fs.writeFileSync(paths.requirements, JSON.stringify({
      work_id: resolvedWorkId,
      requirements: [
        {
          id: "FR-001",
          title: "Primeiro Requisito Funcional",
          user_story: "Como operador, quero funcionalidade X para beneficio Y",
          acceptance_criteria: ["Critério 1 observável"]
        }
      ]
    }, null, 2));
  }

  if (!fs.existsSync(paths.prd)) {
    fs.writeFileSync(paths.prd, JSON.stringify({
      $schema: "https://piwerness.dev/schemas/prd.schema.json",
      id: `PRD-${resolvedWorkId}`,
      meta: { version: "1.0", created_at: new Date().toISOString(), author: "operator" },
      title: `PRD do Work ${resolvedWorkId}`,
      status: "draft",
      scenario: "greenfield",
      problem: { statement: "Problema resolvido pelo PRD — descreva o problema em detalhe" },
      solution: { statement: "Solucao proposta — descreva a abordagem" },
      decisions: [{ id: "DEC-001", statement: "Decisao inicial do produto", status: "proposed" }],
      requirements: [
        { id: "FR-001", type: "functional", statement: "Primeiro requisito funcional" }
      ],
      stakeholders: [{ name: "operator", role: "ACT-001" }],
      scope: { in_scope: ["Escopo incluido"], out_of_scope: ["Nao-objetivos"] },
      accepted_requirements: ["FR-001"]
    }, null, 2));
  }

  if (!fs.existsSync(paths.traceabilityMatrix)) {
    fs.writeFileSync(paths.traceabilityMatrix, JSON.stringify({
      work_id: resolvedWorkId,
      matrix: [
        {
          origin: "DISC-001",
          requirement_id: "FR-001",
          decision_id: "TD-001",
          spec_section: "SPEC-001",
          task_id: "T-001",
          contract_id: "CTR-001",
          evidence_id: "EVD-001",
          status: "planned"
        }
      ]
    }, null, 2));
  }

  return paths;
}
