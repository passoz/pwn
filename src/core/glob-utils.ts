/**
 * Minimal glob matching implementation supporting:
 * - `*` matches any characters except path separator
 * - `**` matches any characters including path separators
 * - `?` matches exactly one character except path separator
 * - `{a,b}` alternation groups, nestable, com `*`/`?` dentro de cada alternativa
 * - `[abc]` character classes
 *
 * `\` NÃO escapa: `minimatch` normaliza `\` para `/` antes de compilar (aceita
 * padrões escritos em estilo Windows), então não existe escape por barra invertida.
 *
 * Um padrão malformado (chave `{` sem `}` correspondente, ou alternativa vazia)
 * lança erro em vez de degradar silenciosamente: um `write_deny` que não casa nada
 * é uma proteção inexistente, e falhar alto é o único desfecho seguro.
 */

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Índice do `]` que fecha a classe aberta em `openIdx`; `-1` se não houver. */
function findClosingBracket(pattern: string, openIdx: number): number {
  return pattern.indexOf(']', openIdx + 1);
}

/**
 * Índice do `}` que fecha o `{` de `openIdx`, respeitando aninhamento e ignorando
 * o conteúdo de classes `[...]` (onde `{`, `}` e `,` são literais); `-1` se não houver.
 */
function findClosingBrace(pattern: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '[') {
      const close = findClosingBracket(pattern, i);
      if (close !== -1) i = close;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Divide o corpo de um grupo nas vírgulas de primeiro nível (vírgulas aninhadas não separam). */
function splitAlternatives(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === '[') {
      const close = findClosingBracket(inner, i);
      if (close !== -1) {
        current += inner.slice(i, close + 1);
        i = close;
        continue;
      }
    }
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}

/** Profundidade máxima de aninhamento de grupos; além disso o padrão é recusado (compilação O(L²)). */
const MAX_BRACE_DEPTH = 32;

/** Compila um padrão (sem âncoras) para a fonte da regex correspondente. */
function buildRegexSource(pattern: string, depth = 0): string {
  let regexStr = '';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i];

    if (ch === '*' && i + 1 < pattern.length && pattern[i + 1] === '*') {
      // ** — matches everything including /
      // Handle /** or **/ patterns
      if (i + 2 < pattern.length && pattern[i + 2] === '/') {
        // ** followed by / — e.g. src/**/foo or **/foo
        regexStr += '(?:.+/)?';
        i += 3;
      } else if (i === 0 || pattern[i - 1] === '/') {
        // ** at start or after / with nothing after — e.g. **, src/**
        // If ** is at the END of the pattern, match everything (including files)
        if (i + 2 >= pattern.length) {
          // src/** → match src/anything (files and dirs)
          regexStr += '.*';
        } else {
          // ** in the middle without trailing / — treat as .*
          regexStr += '.*';
        }
        i += 2;
      } else {
        regexStr += '.*';
        i += 2;
      }
      continue;
    }

    if (ch === '*') {
      // Single * — matches everything except /
      regexStr += '[^/]*';
      i++;
      continue;
    }

    if (ch === '?') {
      regexStr += '[^/]';
      i++;
      continue;
    }

    if (ch === '{') {
      // Alternation: {a,b,c} — cada alternativa é compilada recursivamente, então
      // `*.{ts,js}` e `{a,{b,c}}` funcionam como se espera.
      if (depth >= MAX_BRACE_DEPTH) {
        throw new Error(`glob inválido: aninhamento de grupos acima de ${MAX_BRACE_DEPTH} em ${JSON.stringify(pattern)}`);
      }
      const closeIdx = findClosingBrace(pattern, i);
      if (closeIdx === -1) {
        throw new Error(`glob inválido: "{" sem "}" correspondente em ${JSON.stringify(pattern)}`);
      }
      const alternatives = splitAlternatives(pattern.slice(i + 1, closeIdx));
      if (alternatives.some((alternative) => alternative === '')) {
        throw new Error(`glob inválido: alternativa vazia em ${JSON.stringify(pattern)}`);
      }
      regexStr += '(?:' + alternatives.map((alternative) => buildRegexSource(alternative, depth + 1)).join('|') + ')';
      i = closeIdx + 1;
      continue;
    }

    if (ch === '[') {
      // Character class — copy verbatim
      const closeIdx = pattern.indexOf(']', i + 1);
      if (closeIdx !== -1) {
        regexStr += pattern.slice(i, closeIdx + 1);
        i = closeIdx + 1;
      } else {
        regexStr += escapeRegExp(ch);
        i++;
      }
      continue;
    }

    // Literal character
    regexStr += escapeRegExp(ch);
    i++;
  }

  return regexStr;
}

/**
 * Match a file path against a glob pattern.
 * Patterns use .gitignore-style semantics:
 *   `src/**`       → matches everything under `src/` (not `src` itself)
 *   `src/*.ts`     → matches .ts files directly inside src/
 *   `src/foo/**`   → matches everything under src/foo/
 *   `*.{ts,js}`    → alternation; alternatives may contain `*`/`?`
 * `*.ts` does NOT match nested paths (`a/b.ts`); use a `**` prefix for any depth.
 * Matching is anchored: a pattern matches the whole path, not a prefix.
 */
export function minimatch(filePath: string, pattern: string): boolean {
  // Normalize separators
  const normalizedFile = filePath.replace(/\\/g, '/');
  const normalizedPattern = pattern.replace(/\\/g, '/');

  const regex = new RegExp('^' + buildRegexSource(normalizedPattern) + '$');
  return regex.test(normalizedFile);
}
