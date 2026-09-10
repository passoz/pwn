import fs from 'node:fs';
import path from 'node:path';

export function handleSkillCommand(subcommand: string, args: string[]): void {
  const packSkillsDir = path.resolve(process.cwd(), 'packs/software-engineering/skills');

  switch (subcommand) {
    case 'list':
      console.log('=== [pwn skill list] Skills Disponíveis no Pack ===\n');
      if (fs.existsSync(packSkillsDir)) {
        const skills = fs.readdirSync(packSkillsDir, { withFileTypes: true })
          .filter(d => d.isDirectory())
          .map(d => d.name);

        skills.forEach(s => console.log(`  - ${s}`));
        console.log(`\nTotal: ${skills.length} skills encontradas.`);
      } else {
        console.log('Nenhum diretório de skills encontrado no pack.');
      }
      process.exit(0);
      break;

    case 'discover':
      console.log('=== [pwn skill discover] Descobrindo Skills Externas ===\n');
      console.log('Buscando em ~/.agents/skills/ ...');
      const homeSkills = path.resolve(process.env.HOME || '', '.agents/skills');
      if (fs.existsSync(homeSkills)) {
        const skills = fs.readdirSync(homeSkills, { withFileTypes: true })
          .filter(d => d.isDirectory())
          .map(d => d.name);
        skills.forEach(s => console.log(`  - ${s} (${path.join(homeSkills, s)})`));
      } else {
        console.log('Nenhuma skill externa encontrada em ~/.agents/skills/.');
      }
      process.exit(0);
      break;

    case 'link':
      console.log('=== [pwn skill link] Vinculando Skill ===');
      {
        const name = args[0];
        if (!name) {
          console.error('Uso: pwn skill link <nome-da-skill> [caminho]');
          process.exit(1);
        }

        const packSkillsDir = path.resolve(process.cwd(), 'packs/software-engineering/skills');
        const source = args[1] ? path.resolve(args[1]) : path.join(packSkillsDir, name);
        if (!fs.existsSync(source)) {
          console.error(`Skill '${name}' não encontrada em ${source}`);
          process.exit(1);
        }

        const destDir = path.resolve(process.env.HOME ?? '', '.agents/skills');
        fs.mkdirSync(destDir, { recursive: true });
        const dest = path.join(destDir, name);

        let exists = false;
        try {
          fs.lstatSync(dest);
          exists = true;
        } catch {
          exists = false;
        }
        if (exists) {
          console.error(`Destino já existe: ${dest} (remova para religar)`);
          process.exit(1);
        }

        fs.symlinkSync(source, dest, 'dir');
        console.log(`✓ Skill '${name}' vinculada em ${dest} -> ${source}`);
        process.exit(0);
      }
      break;

    default:
      console.error(`Subcomando desconhecido para 'pwn skill': ${subcommand}`);
      console.log('\nUso:');
      console.log('  pwn skill list       Lista todas as skills do pack oficial');
      console.log('  pwn skill discover   Descobre skills instaladas no ambiente');
      console.log('  pwn skill link       Vincula uma skill externa ao harness');
      process.exit(1);
  }
}
