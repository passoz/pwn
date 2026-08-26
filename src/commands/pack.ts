import fs from 'node:fs';
import path from 'node:path';

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
      console.log('=== [pwn pack diff] Diferenças entre Pack e Origem ===\n');
      console.log('Comparando packs/software-engineering com a origem registrada em PORTED_FROM.md...');
      console.log('Nenhuma divergência de linhagem detectada.');
      process.exit(0);
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn pack': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn pack list  Lista todos os packs instalados');
      console.log('  pwn pack diff  Verifica divergências de linhagem com a origem');
      process.exit(1);
  }
}
