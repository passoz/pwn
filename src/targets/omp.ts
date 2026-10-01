import fs from 'node:fs';
import path from 'node:path';
import { MaterializationResult, TargetContractContext, deriveUnsupportedCapabilities, renderScopeSection } from '../core/target-materializer.js';

export function materializeOmpTarget(outDir: string, context?: TargetContractContext): MaterializationResult {
  const generatedFiles: string[] = [];
  const notes: string[] = [];

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // 1. Generate AGENTS.md (context file descoberto nativamente pelo omp)
  const agentsMdContent = `# Regras do omp (oh my pi)

> Configuração materializada via \`pwn target materialize --target omp\`

## Invariantes Globais
- **Precedência**: Seguir AGENTS.md e especificações normativas JSON.
- **Segurança**: Respeitar allowlist de escrita de arquivos.
- **Validação**: Executar os comandos de aceitação do contrato antes de concluir.
${context ? renderScopeSection(context) : ''}
`;

  const agentsPath = path.join(outDir, 'AGENTS.md');
  fs.writeFileSync(agentsPath, agentsMdContent, 'utf8');
  generatedFiles.push(agentsPath);

  // 2. Generate .omp/config.yml (configuração de projeto nativa do omp, YAML)
  const ompConfigContent = `# Materializado via \`pwn target materialize --target omp\`
# Instale copiando este arquivo para <raiz-do-repo>/.omp/config.yml
#   (ou carregue só nesta execução: omp --config <caminho>)
# Chaves validadas contra \`omp config list\` (omp v18.x).

# Sessões headless (\`omp --print\`) não têm UI para responder prompts: qualquer
# policy "prompt" falha fechado. O gate de escrita do PWN é o Diff Guard
# (write_allow/write_deny), então o approvalMode do projeto fica explícito.
tools:
  approvalMode: yolo
`;

  const configDir = path.join(outDir, '.omp');
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  const configPath = path.join(configDir, 'config.yml');
  fs.writeFileSync(configPath, ompConfigContent, 'utf8');
  generatedFiles.push(configPath);

  notes.push('Gerado AGENTS.md e .omp/config.yml para omp (oh my pi)');
  notes.push('Instale copiando AGENTS.md para a raiz do projeto e .omp/config.yml para <raiz>/.omp/config.yml');
  notes.push('tools.approvalMode: yolo no config de projeto sobrepõe a policy global do operador; use --approval-mode write para sessões interativas');

  return {
    target: 'omp',
    success: true,
    unsupportedCapabilities: deriveUnsupportedCapabilities('omp'),
    generatedFiles,
    notes,
  };
}
