import fs from 'node:fs';
import path from 'node:path';
import { MaterializationResult, TargetContractContext, deriveUnsupportedCapabilities, renderScopeSection } from '../core/target-materializer.js';

export function materializeOpenCodeTarget(outDir: string, context?: TargetContractContext): MaterializationResult {
  const generatedFiles: string[] = [];
  const notes: string[] = [];

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // 1. Generate AGENTS.md
  const agentsMdContent = `# OpenCode Agents Rulebook

> Materializado via \`pwn target materialize --target opencode\`

## Regras Globais
- Respeitar contratos contratuais V4 de tarefas.
- Modificações Restritas à allowlist declarada.
- Executar scripts de validação antes de sinalizar conclusão.
${context ? renderScopeSection(context) : ''}
`;

  const agentsPath = path.join(outDir, 'AGENTS.md');
  fs.writeFileSync(agentsPath, agentsMdContent, 'utf8');
  generatedFiles.push(agentsPath);

  // 2. Generate opencode.jsonc
  const openCodeConfig = {
    $schema: 'https://opencode.ai/config.json',
    permission: {
      edit: 'allow',
      bash: 'allow',
    },
  };

  const configPath = path.join(outDir, 'opencode.jsonc');
  fs.writeFileSync(configPath, JSON.stringify(openCodeConfig, null, 2), 'utf8');
  generatedFiles.push(configPath);
  notes.push('Gerado opencode.jsonc e AGENTS.md para OpenCode');
  notes.push('Instale copiando AGENTS.md e opencode.jsonc para a raiz do projeto (ou exporte OPENCODE_CONFIG apontando para o opencode.jsonc)');
  notes.push('permission explícita: sessões headless não respondem prompts; o gate de escrita é o Diff Guard do PWN (write_allow/write_deny)');

  return {
    target: 'opencode',
    success: true,
    unsupportedCapabilities: deriveUnsupportedCapabilities('opencode'),
    generatedFiles,
    notes,
  };
}
