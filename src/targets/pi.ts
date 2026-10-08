import fs from 'node:fs';
import path from 'node:path';
import { MaterializationResult, TargetContractContext, deriveUnsupportedCapabilities, renderAcceptanceProtocol, renderScopeSection } from '../core/target-materializer.js';

export function materializePiTarget(outDir: string, context?: TargetContractContext): MaterializationResult {
  const generatedFiles: string[] = [];
  const notes: string[] = [];

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // 1. Generate AGENTS.md
  const agentsMdContent = `# Regras do Pi Harness (Pi Target)

> Configuração materializada via \`pwn target materialize --target pi\`

## Invariantes Globais
- **Precedência**: Seguir AGENTS.md e especificações normativas JSON.
- **Segurança**: Respeitar allowlist de escrita de arquivos.
- **Validação**: Conclusão só com a atestação do audit — siga o protocolo abaixo.
${renderAcceptanceProtocol()}
${context ? renderScopeSection(context) : ''}
`;

  const agentsPath = path.join(outDir, 'AGENTS.md');
  fs.writeFileSync(agentsPath, agentsMdContent, 'utf8');
  generatedFiles.push(agentsPath);
  notes.push('Gerado AGENTS.md para Pi');
  notes.push('Instale copiando AGENTS.md para a raiz do projeto (pi descobre AGENTS.md e CLAUDE.md na inicialização)');

  return {
    target: 'pi',
    success: true,
    unsupportedCapabilities: deriveUnsupportedCapabilities('pi'),
    generatedFiles,
    notes,
  };
}
