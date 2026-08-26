import fs from 'node:fs';
import path from 'node:path';

export interface ValidationResult {
  valid: boolean;
  file: string;
  errors: string[];
}

export function validateNormativeDocument(filePath: string, rootDir: string = process.cwd()): ValidationResult {
  const absolutePath = path.resolve(rootDir, filePath);
  const relativePath = path.relative(rootDir, absolutePath);
  const errors: string[] = [];

  if (!fs.existsSync(absolutePath)) {
    return { valid: false, file: relativePath, errors: [`File not found: ${relativePath}`] };
  }

  try {
    const raw = fs.readFileSync(absolutePath, 'utf8');
    const data = JSON.parse(raw);

    // Basic schema checking based on file type / schema field
    if (data.$schema) {
      const schemaName = path.basename(data.$schema);
      if (schemaName.includes('system.schema')) {
        const required = ['meta', 'status', 'actors', 'capabilities', 'rules', 'contracts', 'entities', 'coverage', 'traceability'];
        for (const req of required) {
          if (!data[req]) errors.push(`Missing required field in system spec: '${req}'`);
        }
      } else if (schemaName.includes('tasks.schema')) {
        const required = ['meta', 'work_id', 'status', 'tasks'];
        for (const req of required) {
          if (!data[req]) errors.push(`Missing required field in tasks document: '${req}'`);
        }
      } else if (schemaName.includes('pipeline.schema')) {
        const required = ['meta', 'parameters', 'contract', 'stages'];
        for (const req of required) {
          if (!data[req]) errors.push(`Missing required field in pipeline document: '${req}'`);
        }
      } else if (schemaName.includes('prd.schema')) {
        const required = ['meta', 'work_id', 'title', 'status', 'problem', 'actors', 'scope', 'accepted_requirements'];
        for (const req of required) {
          if (!data[req]) errors.push(`Missing required field in PRD document: '${req}'`);
        }
      } else if (schemaName.includes('evidence.schema')) {
        const required = ['meta', 'work_id', 'task_id', 'status', 'evidence'];
        for (const req of required) {
          if (!data[req]) errors.push(`Missing required field in evidence document: '${req}'`);
        }
      }
    }
  } catch (err: any) {
    errors.push(`JSON Syntax Error: ${err.message}`);
  }

  return {
    valid: errors.length === 0,
    file: relativePath,
    errors,
  };
}

export function validateAllCoreNormatives(rootDir: string = process.cwd()): ValidationResult[] {
  const normatives = [
    '.specs/system.json',
    'spec.json',
    'todo.json',
    'packs/core/pipeline-core.json'
  ];

  return normatives.map(file => validateNormativeDocument(file, rootDir));
}
