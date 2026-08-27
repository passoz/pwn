import fs from 'node:fs';
import path from 'node:path';
import { MaterializationResult, TARGET_CAPABILITY_MATRIX } from '../core/target-materializer.js';

export function materializeOmpTarget(outDir: string): MaterializationResult {
  const caps = TARGET_CAPABILITY_MATRIX.omp;
  const generatedFiles: string[] = [];
  const notes: string[] = [];
  const unsupportedCapabilities: string[] = ['supportsToolCalling', 'supportsContractV4', 'supportsWorktreeSandbox'];

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // 1. Generate omp.json
  const ompConfig = {
    version: "1.0",
    name: "piwerness-omp",
    systemPrompt: "Você é um assistente omp operando sob contratos de engenharia do Piwerness.",
    capabilities: {
      toolCalling: false,
      contractV4: false
    }
  };

  const configPath = path.join(outDir, 'omp.json');
  fs.writeFileSync(configPath, JSON.stringify(ompConfig, null, 2), 'utf8');
  generatedFiles.push(configPath);
  notes.push('omp não possui suporte nativo a chamadas de ferramentas ou Sandboxes Worktree. Funcionalidades foram degradadas para prompt simples.');

  return {
    target: 'omp',
    success: true,
    unsupportedCapabilities,
    generatedFiles,
    notes,
  };
}
