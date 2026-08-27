/**
 * Minimal glob matching implementation supporting:
 * - `*` matches any characters except path separator
 * - `**` matches any characters including path separators
 * - `?` matches exactly one character except path separator
 * - `{a,b}` alternation groups
 * - Literal escaping with backslash
 */

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parsePattern(pattern: string): RegExp {
  let regexStr = '';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i];

    if (ch === '\\' && i + 1 < pattern.length) {
      // Escaped character — treat literally
      regexStr += escapeRegExp(pattern[i + 1]);
      i += 2;
      continue;
    }

    if (ch === '*' && i + 1 < pattern.length && pattern[i + 1] === '*') {
      // ** — matches everything including /
      // Handle /** or **/ patterns
      if (i + 2 < pattern.length && pattern[i + 2] === '/') {
        regexStr += '(?:.+/)?';
        i += 3;
      } else if (i === 0 || pattern[i - 1] === '/') {
        regexStr += '(?:.+/)?';
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
      // Alternation: {a,b,c}
      const closeIdx = pattern.indexOf('', i);
      if (closeIdx !== -1) {
        const alternatives = pattern.slice(i + 1, closeIdx).split(',');
        regexStr += '(?:' + alternatives.map(a => escapeRegExp(a)).join('|') + ')';
        i = closeIdx + 1;
      } else {
        regexStr += escapeRegExp(ch);
        i++;
      }
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

  return new RegExp('^' + regexStr + '$');
}

/**
 * Match a file path against a glob pattern.
 * Patterns use .gitignore-style semantics:
 *   `src/**`       → matches src and everything under it
 *   `*.ts`         → matches any .ts file at any depth
 *   `src/*.ts`     → matches .ts files directly inside src/
 *   `src/foo/**`   → matches everything under src/foo/
 */
export function minimatch(filePath: string, pattern: string): boolean {
  // Normalize separators
  const normalizedFile = filePath.replace(/\\/g, '/');
  const normalizedPattern = pattern.replace(/\\/g, '/');

  const regex = parsePattern(normalizedPattern);
  return regex.test(normalizedFile);
}
