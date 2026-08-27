import fs from 'node:fs';
import path from 'node:path';
import { MaterializationResult, TARGET_CAPABILITY_MATRIX } from '../core/target-materializer.js';

export function materializePiTarget(outDir: string): MaterializationResult {
  const caps = TARGET_CAPABILITY_MATRIX.pi;
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
- **Validação**: Executar testes automatizados via \`bun test\`.
`;

  const agentsPath = path.join(outDir, 'AGENTS.md');
  fs.writeFileSync(agentsPath, agentsMdContent, 'utf8');
  generatedFiles.push(agentsPath);
  notes.push('Gerado AGENTS.md para Pi');

  return {
    target: 'pi',
    success: true,
    unsupportedCapabilities: [],
    generatedFiles,
    notes,
  };
}
