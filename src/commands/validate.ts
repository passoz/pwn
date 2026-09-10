import { validateNormativeDocument, validateAllCoreNormatives, validateWorkDocuments } from '../core/validator.js';
import { getExistingWorkIds } from '../core/work-artifacts.js';

function printResults(results: Array<{ valid: boolean; file: string; errors: string[] }>): number {
  let errorsCount = 0;
  for (const res of results) {
    if (res.valid) {
      console.log(`✓ ${res.file} — VÁLIDO (conforme schema)`);
    } else {
      console.log(`✗ ${res.file} — ERRO:`);
      res.errors.forEach((e) => console.log(`  - ${e}`));
      errorsCount++;
    }
  }
  return errorsCount;
}

/**
 * pwn validate — valida os documentos normativos do projeto (Works).
 * `--work NNNN` valida um Work específico; sem argumento, valida todos os Works
 * e, na ausência deles (repo do framework), valida os documentos core.
 */
export function handleValidateCommand(args: string[]): void {
  const workIdx = args.indexOf('--work');
  const workId = workIdx !== -1 && args[workIdx + 1] && !args[workIdx + 1].startsWith('--') ? args[workIdx + 1] : null;

  if (workId) {
    console.log(`=== [pwn validate] Validador de Documentos do Work ${workId} ===\n`);
    const results = validateWorkDocuments(workId);
    if (results.length === 0) {
      console.log(`Nenhum documento com schema encontrado em .piwerness/work/${workId}/.`);
      process.exit(0);
    }
    const errorsCount = printResults(results);
    console.log(`\n=== RESUMO: ${results.length - errorsCount}/${results.length} arquivos válidos, ${errorsCount} erros ===`);
    process.exit(errorsCount > 0 ? 1 : 0);
  }

  const ids = getExistingWorkIds();
  if (ids.length > 0) {
    console.log('=== [pwn validate] Validador de Documentos dos Works do projeto ===\n');
    let total = 0;
    let errorsCount = 0;
    for (const id of ids) {
      const results = validateWorkDocuments(id);
      total += results.length;
      errorsCount += printResults(results);
    }
    console.log(`\n=== RESUMO: ${total - errorsCount}/${total} arquivos válidos, ${errorsCount} erros ===`);
    process.exit(errorsCount > 0 ? 1 : 0);
  }

  // Fallback: repo do framework (sem Works) valida os documentos core.
  console.log('=== [pwn validate] Validador de Documentos Normativos JSON ===\n');
  const results = validateAllCoreNormatives();
  const errorsCount = printResults(results);
  console.log(`\n=== RESUMO: ${results.length - errorsCount}/${results.length} arquivos válidos, ${errorsCount} erros ===`);
  process.exit(errorsCount > 0 ? 1 : 0);
}

/**
 * pwn self-check — valida os documentos normativos do próprio framework.
 */
export function handleSelfCheckCommand(): void {
  console.log('=== [pwn self-check] Validador dos documentos normativos do framework ===\n');
  const results = validateAllCoreNormatives();
  const errorsCount = printResults(results);
  console.log(`\n=== RESUMO: ${results.length - errorsCount}/${results.length} arquivos válidos, ${errorsCount} erros ===`);
  process.exit(errorsCount > 0 ? 1 : 0);
}
