#!/usr/bin/env node

/**
 * Validador básico de documentos JSON normativos do Piwerness
 * Verifica sintaxe JSON e presença de campos obrigatórios conforme schemas
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname);

console.log('=== VALIDADOR DE DOCUMENTOS NORMATIVOS DO PIWERNESS ===\n');

let totalFiles = 0;
let validFiles = 0;
let errors = 0;

function validateJsonFile(filePath, requiredFields = []) {
  totalFiles++;
  const relativePath = path.relative(ROOT, filePath);
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    
    // Check required top-level fields
    const missingFields = [];
    for (const field of requiredFields) {
      if (data[field] === undefined) {
        missingFields.push(field);
      }
    }
    
    if (missingFields.length > 0) {
      console.log(`✗ ${relativePath} — Faltam campos obrigatórios: ${missingFields.join(', ')}`);
      errors++;
      return false;
    }
    
    console.log(`✓ ${relativePath} — VÁLIDO (JSON sintaticamente correto, campos ok)`);
    validFiles++;
    return true;
  } catch (err) {
    console.log(`✗ ${relativePath} — ERRO: ${err.message}`);
    errors++;
    return false;
  }
}

// 1. Schemas
console.log('--- Schemas ---');
validateJsonFile('schemas/pipeline.schema.json', ['$schema', 'title', 'properties']);
validateJsonFile('schemas/prd.schema.json', ['$schema', 'title', 'properties']);
validateJsonFile('schemas/system.schema.json', ['$schema', 'title', 'properties']);
validateJsonFile('schemas/tasks.schema.json', ['$schema', 'title', 'properties']);
validateJsonFile('schemas/evidence.schema.json', ['$schema', 'title', 'properties']);

// 2. Documentos normativos
console.log('\n--- Documentos Normativos ---');
validateJsonFile('.specs/system.json', ['$schema', 'meta', 'status', 'actors', 'capabilities', 'rules', 'contracts', 'entities', 'coverage', 'traceability']);
validateJsonFile('spec.json', ['$schema', 'meta', 'status', 'actors', 'capabilities', 'rules', 'contracts', 'entities', 'coverage', 'traceability']);
validateJsonFile('todo.json', ['$schema', 'work_id', 'meta', 'status', 'tasks']);
validateJsonFile('packs/core/pipeline-core.json', ['$schema', 'meta', 'parameters', 'contract', 'stages']);

console.log(`\n=== RESUMO: ${validFiles}/${totalFiles} arquivos válidos, ${errors} erros ===`);

if (errors > 0) {
  process.exit(1);
}
