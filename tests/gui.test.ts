import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

test('Editor de pipeline estático tools/pipeline-editor/index.html existe e possui a estrutura autocontida', () => {
  const htmlPath = path.resolve(process.cwd(), 'tools/pipeline-editor/index.html');
  assert.ok(fs.existsSync(htmlPath), 'Arquivo tools/pipeline-editor/index.html não foi encontrado');

  const content = fs.readFileSync(htmlPath, 'utf8');
  assert.match(content, /<!DOCTYPE html>/i);
  assert.match(content, /Piwerness Pipeline/);
  assert.match(content, /Roteamento de Modelos/);
  assert.match(content, /pipeline\.schema\.json/);
  assert.match(content, /json-input/);
  assert.match(content, /stages-container/);
  assert.match(content, /models-grid/);
});
