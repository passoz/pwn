import { minimatch } from './glob-utils.js';

export interface FileDiffCheckResult {
  allowed: boolean;
  violationType?: 'write_deny' | 'not_in_write_allow';
  file: string;
  reason?: string;
}

export interface ContractDiffCheckReport {
  passed: boolean;
  totalFiles: number;
  violations: FileDiffCheckResult[];
}

export function checkFileAgainstScope(filePath: string, writeAllow: string[], writeDeny: string[]): FileDiffCheckResult {
  // Normalize: remove ./ prefix AND collapse ../ to prevent glob bypass
  // e.g. "src/../secret.txt" → "secret.txt" (which won't match "src/**")
  let normalizedPath = filePath.replace(/^\.\//, '');
  // Collapse path segments — path.normalize but keep forward slashes
  const parts = normalizedPath.split('/');
  const resolved: string[] = [];
  for (const part of parts) {
    if (part === '..') {
      resolved.pop();
    } else if (part !== '.' && part !== '') {
      resolved.push(part);
    }
  }
  normalizedPath = resolved.join('/');

  // 1. Check write_deny first (deny list always overrides allow)
  for (const denyPattern of writeDeny) {
    if (minimatch(normalizedPath, denyPattern)) {
      return {
        allowed: false,
        violationType: 'write_deny',
        file: normalizedPath,
        reason: `Arquivo ${normalizedPath} está explicitamente na lista write_deny: ${denyPattern}`,
      };
    }
  }

  // 2. Check write_allow
  let allowedByAllowlist = false;
  for (const allowPattern of writeAllow) {
    if (minimatch(normalizedPath, allowPattern)) {
      allowedByAllowlist = true;
      break;
    }
  }

  if (!allowedByAllowlist) {
    return {
      allowed: false,
      violationType: 'not_in_write_allow',
      file: normalizedPath,
      reason: `Arquivo ${normalizedPath} não consta na allowlist de escrita: [${writeAllow.join(', ')}]`,
    };
  }

  return {
    allowed: true,
    file: normalizedPath,
  };
}

export function checkDiffAgainstContract(modifiedFiles: string[], writeAllow: string[], writeDeny: string[]): ContractDiffCheckReport {
  const violations: FileDiffCheckResult[] = [];

  for (const file of modifiedFiles) {
    const result = checkFileAgainstScope(file, writeAllow, writeDeny);
    if (!result.allowed) {
      violations.push(result);
    }
  }

  return {
    passed: violations.length === 0,
    totalFiles: modifiedFiles.length,
    violations,
  };
}
