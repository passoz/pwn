import { validateNormativeDocument, validateAllCoreNormatives, validateWorkDocuments } from '../core/validator.js';
import { getExistingWorkIds, getLatestWorkId } from '../core/work-artifacts.js';
import { describeBaseline, mutationCases, runMutations } from '../core/self_check_mutate.js';

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
      console.log(`Nenhum documento com schema encontrado em .pwn/work/${workId}/.`);
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
 * Com `--mutate`, roda o mutation testing dos gates sobre um Work (ver
 * `--mutate [--work NNNN]`).
 */
// INTEGRADOR: passar args do cli.ts
export function handleSelfCheckCommand(args: string[] = []): void {
  if (args.includes('--mutate')) {
    handleMutationCheck(args);
    return;
  }

  console.log('=== [pwn self-check] Validador dos documentos normativos do framework ===\n');
  const results = validateAllCoreNormatives();
  const errorsCount = printResults(results);
  console.log(`\n=== RESUMO: ${results.length - errorsCount}/${results.length} arquivos válidos, ${errorsCount} erros ===`);
  process.exit(errorsCount > 0 ? 1 : 0);
}

/**
 * pwn self-check --mutate [--work NNNN] — mutation testing determinístico dos
 * gates: cada mutação viola um artefato numa cópia temporária do Work e o
 * relatório mostra quais gates realmente bloqueiam a violação (e quais são
 * decorativos).
 */
function handleMutationCheck(args: string[]): void {
  const workIdx = args.indexOf('--work');
  const explicitWork =
    workIdx !== -1 && args[workIdx + 1] && !args[workIdx + 1].startsWith('--') ? args[workIdx + 1] : null;
  const workId = explicitWork ?? getLatestWorkId();

  console.log('=== [pwn self-check --mutate] Mutation testing dos gates do harness ===\n');

  if (explicitWork && !getExistingWorkIds().includes(workId)) {
    console.error(`Work ${workId} não encontrado em .pwn/work/.`);
    process.exit(1);
  }

  console.log(`Baseline: ${describeBaseline({ workId })}\n`);

  const cases = mutationCases();
  const results = runMutations({ workId });
  const expectedDetected = results.filter((r) => cases.find((c) => c.id === r.id)?.expect_blocked);

  for (const result of results) {
    const expectation = cases.find((c) => c.id === result.id);
    const advisory = expectation?.expect_blocked === false ? ' (advisory)' : '';
    const mark = result.detected ? '✓' : '✗';
    const outcome = result.detected ? 'detectado' : 'NÃO DETECTADO';
    console.log(`${mark} ${result.id} — ${result.gate} — ${outcome}${advisory} — ${result.detail}`);
  }

  const detected = results.filter((r) => r.detected).length;
  console.log(`\n=== RESUMO: ${detected}/${results.length} mutações detectadas ===`);
  const advisoryGates = results
    .filter((r) => !r.detected && cases.find((c) => c.id === r.id)?.expect_blocked === false)
    .map((r) => r.gate);
  if (advisoryGates.length > 0) {
    console.log(`Gates decorativos (mutação aceita como advisory): ${advisoryGates.join(', ')}`);
  }

  const allExpectedDetected =
    expectedDetected.length > 0 && expectedDetected.every((r) => r.detected);
  if (!allExpectedDetected) {
    const missed = expectedDetected.filter((r) => !r.detected).map((r) => r.id);
    console.error(`Esperava detecção nas mutações bloqueantes: ${missed.join(', ') || '(nenhuma declarada)'}`);
  }
  process.exit(allExpectedDetected ? 0 : 1);
}
