import fs from 'node:fs';
import path from 'node:path';

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

export function initWorkDirectory(workId: string, rootDir: string = process.cwd()): WorkArtifactsPaths {
  const paths = getWorkArtifactsPaths(workId, rootDir);

  if (!fs.existsSync(paths.workDir)) {
    fs.mkdirSync(paths.workDir, { recursive: true });
  }

  // Create template files if they don't exist
  if (!fs.existsSync(paths.intake)) {
    fs.writeFileSync(paths.intake, JSON.stringify({
      work_id: workId,
      created_at: new Date().toISOString(),
      objective: "Objetivo do pedido bruto",
      requester: "operator",
      status: "draft"
    }, null, 2));
  }

  if (!fs.existsSync(paths.discovery)) {
    fs.writeFileSync(paths.discovery, JSON.stringify({
      work_id: workId,
      problem: "Descrição do problema",
      actors: ["ACT-001"],
      objectives: ["Objetivo principal"],
      constraints: ["Restrição de tecnologia/tempo"]
    }, null, 2));
  }

  if (!fs.existsSync(paths.requirements)) {
    fs.writeFileSync(paths.requirements, JSON.stringify({
      work_id: workId,
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
      $schema: "../../schemas/prd.schema.json",
      work_id: workId,
      meta: { version: "1.0", created_at: new Date().toISOString() },
      title: `PRD do Work ${workId}`,
      status: "draft",
      problem: "Problema resolvido pelo PRD",
      actors: ["ACT-001"],
      scope: { inside: ["Escopo incluído"], outside: ["Não-objetivos"] },
      accepted_requirements: ["FR-001"]
    }, null, 2));
  }

  if (!fs.existsSync(paths.traceabilityMatrix)) {
    fs.writeFileSync(paths.traceabilityMatrix, JSON.stringify({
      work_id: workId,
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
