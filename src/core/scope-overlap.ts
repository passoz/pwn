import { minimatch } from './glob-utils.js';

const GLOB_CHARS = /[*?[\]{}]/;

function globPrefix(pattern: string): { prefix: string[]; literal: boolean } {
  const segments = pattern.replace(/\\/g, '/').replace(/^\.\//, '').split('/').filter(Boolean);
  const firstGlob = segments.findIndex((segment) => GLOB_CHARS.test(segment));
  return firstGlob === -1
    ? { prefix: segments, literal: true }
    : { prefix: segments.slice(0, firstGlob), literal: false };
}

/**
 * Heurística conservadora: dois globs "podem sobrepor" quando os prefixos literais
 * (segmentos antes do primeiro metacaractere) são um prefixo do outro. Caminho literal
 * é testado exatamente contra o outro glob. `false` significa disjunção garantida;
 * `true` pode ser falso positivo — quem decide paralelismo trata como conflito.
 */
export function globsMayOverlap(a: string, b: string): boolean {
  const pa = globPrefix(a);
  const pb = globPrefix(b);
  const common = Math.min(pa.prefix.length, pb.prefix.length);
  for (let i = 0; i < common; i++) {
    if (pa.prefix[i] !== pb.prefix[i]) return false;
  }
  if (pa.literal && pb.literal) return pa.prefix.length === pb.prefix.length;
  if (pa.literal) return minimatch(pa.prefix.join('/'), b);
  if (pb.literal) return minimatch(pb.prefix.join('/'), a);
  return true;
}
