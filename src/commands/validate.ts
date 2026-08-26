import { validateNormativeDocument, validateAllCoreNormatives } from '../core/validator.js';

export function handleValidateCommand(args: string[]): void {
  console.log('=== [pwn validate] Validador de Documentos Normativos JSON ===\n');

  if (args.length > 0) {
    const filePath = args[0];
    const res = validateNormativeDocument(filePath);
    if (res.valid) {
      console.log(`✓ ${res.file} — VÁLIDO (JSON sintaticamente correto, campos ok)`);
      process.exit(0);
    } else {
      console.log(`✗ ${res.file} — ERRO:`);
      res.errors.forEach(e => console.log(`  - ${e}`));
      process.exit(1);
    }
  }

  const results = validateAllCoreNormatives();
  let errorsCount = 0;

  for (const res of results) {
    if (res.valid) {
      console.log(`✓ ${res.file} — VÁLIDO (JSON sintaticamente correto, campos ok)`);
    } else {
      console.log(`✗ ${res.file} — ERRO:`);
      res.errors.forEach(e => console.log(`  - ${e}`));
      errorsCount++;
    }
  }

  console.log(`\n=== RESUMO: ${results.length - errorsCount}/${results.length} arquivos válidos, ${errorsCount} erros ===`);
  process.exit(errorsCount > 0 ? 1 : 0);
}
