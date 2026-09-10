import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_RENAMES: Record<string, string> = {
  'validate_system_spec.js': 'validate-system-spec.js',
};

export function handlePackCommand(subcommand: string, args: string[]): void {
  const packsDir = path.resolve(process.cwd(), 'packs');

  switch (subcommand) {
    case 'list':
      console.log('=== [pwn pack list] Packs Instalados ===\n');
      if (fs.existsSync(packsDir)) {
        const packs = fs.readdirSync(packsDir, { withFileTypes: true })
          .filter(d => d.isDirectory())
          .map(d => d.name);

        packs.forEach(p => console.log(`  - ${p}`));
      }
      process.exit(0);
      break;

    case 'diff':
      console.log('=== [pwn pack diff] Divergências entre o harness instalado e o framework ===\n');
      {
        const cliRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
        const frameworkDir = path.resolve(cliRoot, 'packs/software-engineering/scripts');
        const harnessDir = path.resolve(process.cwd(), '.piwerness/harness/scripts');

        if (!fs.existsSync(harnessDir)) {
          console.log('Harness não instalado neste projeto. Rode "pwn init" para instalá-lo.');
          process.exit(0);
        }

        let drift = 0;
        for (const entry of fs.readdirSync(frameworkDir)) {
          if (!entry.endsWith('.js')) continue;
          const harnessName = SCRIPT_RENAMES[entry] ?? entry;
          const harnessPath = path.join(harnessDir, harnessName);
          if (!fs.existsSync(harnessPath)) {
            console.log(`- ausente no harness: ${harnessName}`);
            drift++;
            continue;
          }
          if (fs.readFileSync(harnessPath, 'utf8') !== fs.readFileSync(path.join(frameworkDir, entry), 'utf8')) {
            console.log(`- divergente: ${harnessName}`);
            drift++;
          }
        }

        if (drift === 0) {
          console.log('Harness sincronizado com o framework — nenhuma divergência.');
          process.exit(0);
        }
        console.log(`\n${drift} divergência(s). Reinstale com "pwn init".`);
        process.exit(1);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn pack': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn pack list  Lista todos os packs instalados');
      console.log('  pwn pack diff  Verifica divergências de linhagem com a origem');
      process.exit(1);
  }
}
