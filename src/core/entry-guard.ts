import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * `true` quando o módulo identificado por `moduleUrl` é o ponto de entrada do
 * processo — isto é, foi invocado como script (`bun src/core/<módulo>.ts ...`)
 * em vez de importado.
 *
 * Num bundle compilado (`bun build --compile`) o entrypoint vive em
 * `/$bunfs/root/...`, um VFS em que `realpathSync` lança ENOENT; daí o `catch`
 * devolvendo `false`: nenhum bundler invoca submódulos por caminho de arquivo,
 * então "não é o entrypoint" é a resposta correta nesse contexto.
 */
export function isDirectEntry(moduleUrl: string): boolean {
  const invoked = process.argv[1];
  if (!invoked) return false;
  try {
    return realpathSync(invoked) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}
