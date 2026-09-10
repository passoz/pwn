import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// `validate_system_spec.js` termina em `_spec.js`, que o Bun interpreta como
// arquivo de teste e executa como spec (exit code 2). O harness vendored o
// renomeia para um nome sem o sufixo colidido.
const SCRIPTS_TO_RENAME: Record<string, string> = {
  'validate_system_spec.js': 'validate-system-spec.js',
};

function frameworkScriptsDir(): string {
  const cliRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return path.resolve(cliRoot, 'packs/software-engineering/scripts');
}

/**
 * pwn init — instala o harness (scripts do pack) no projeto-alvo sob
 * .piwerness/harness/scripts, fora do alcance da descoberta de testes do Bun.
 */
export function handleInitCommand(args: string[]): void {
  console.log('=== [pwn init] Instalando harness no projeto-alvo ===\n');

  const dirIdx = args.indexOf('--dir');
  const targetDir = dirIdx !== -1 && args[dirIdx + 1] ? path.resolve(args[dirIdx + 1]) : process.cwd();

  const src = frameworkScriptsDir();
  const dest = path.join(targetDir, '.piwerness', 'harness', 'scripts');

  if (!fs.existsSync(src)) {
    console.error(`Diretório de scripts do framework não encontrado: ${src}`);
    process.exit(1);
  }

  fs.mkdirSync(dest, { recursive: true });

  let copied = 0;
  let renamed = 0;
  for (const entry of fs.readdirSync(src)) {
    if (!entry.endsWith('.js')) continue;
    const destName = SCRIPTS_TO_RENAME[entry] ?? entry;
    fs.copyFileSync(path.join(src, entry), path.join(dest, destName));
    copied++;
    if (destName !== entry) renamed++;
  }

  console.log(`✓ ${copied} scripts copiados para ${dest}`);
  if (renamed > 0) {
    console.log(`  ${renamed} script(s) renomeado(s) para evitar colisão com o padrão *_spec.js do Bun.`);
  }

  // Escopa a descoberta de testes quando o projeto usa tests/ e ainda não tem bunfig.
  const bunfigPath = path.join(targetDir, 'bunfig.toml');
  if (!fs.existsSync(bunfigPath) && fs.existsSync(path.join(targetDir, 'tests'))) {
    fs.writeFileSync(bunfigPath, '[test]\nroot = "tests"\n', 'utf8');
    console.log('✓ bunfig.toml criado com [test] root = "tests"');
  }

  console.log('\nHarness instalado. Os comandos pwn work/plan/status/audit resolvem os scripts do pack localmente.');
  process.exit(0);
}
