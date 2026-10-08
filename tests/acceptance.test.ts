import { describe, expect, test } from 'bun:test';
import {
  allowedCheckCommands,
  commandMatches,
  genericCommandReason,
  genericExpectReason,
  isWholeSuiteCommand,
  normalizeCommand,
  parseGlobalGates,
  parsePlanTask,
  parsePlanTasks,
  placeholderPathReason,
  requiredAuditChecks,
  splitCommandLine,
  taskDefinitionDigest,
  vacuousCommandReason,
} from '../src/core/acceptance.js';

/** Plano v3 completo: contrato de execução, gates globais e duas tasks. */
const PLAN = [
  '## Execution contract',
  '',
  '| Component | Regression | Lint | Build | Security |',
  '| --- | --- | --- | --- | --- |',
  '| core | `bun test tests/core.test.ts` | `bun run lint` | `bun run build` | N/A |',
  '',
  '## Global gates',
  '',
  '- [ ] `bun run typecheck` — verificação de tipos',
  '',
  '## Tasks',
  '',
  '### [ ] [1.1] Tokenizar linha de comando',
  '',
  '**Implementation files:** `src/core/acceptance.ts`, `src/core/cli.ts`',
  '',
  '**Test files:** `tests/acceptance.test.ts`',
  '',
  '**Components:** `core`',
  '',
  '**RED:**',
  '- `bun test tests/acceptance.test.ts` — falha porque a tokenização ainda não existe',
  '',
  '**ACs:**',
  '- [ ] `bun test tests/acceptance-split.test.ts` — tokeniza aspas simples',
  '- [ ] `bun test tests/acceptance-quote.test.ts` — tokeniza aspas duplas',
  '',
  '**Visual:** N/A',
  '**Documentation:** N/A',
  '',
  '### [ ] [1.2] Interface visual do relatório',
  '',
  '**Implementation files:** `src/core/report.ts`',
  '',
  '**Test files:** `tests/report.test.ts`',
  '',
  '**Components:** `core`',
  '',
  '**RED:**',
  '- `bun test tests/report.test.ts` — o relatório ainda não existe',
  '',
  '**ACs:**',
  '- [ ] `bun test tests/report-render.test.ts` — renderiza o card',
  '',
  '**Visual:** REQUIRED',
  '**Playwright:** `bun run e2e`',
  '**Documentation:** REQUIRED',
  '- **Evidence:** `bun run docs`',
  '',
].join('\n');

describe('splitCommandLine', () => {
  test('mantém argumento entre aspas simples como um único token', () => {
    expect(splitCommandLine("bun test 'a b.test.mjs'")).toEqual(['bun', 'test', 'a b.test.mjs']);
  });

  test('aspas duplas aceitam escape de aspas internas', () => {
    expect(splitCommandLine('"valor com \\"aspas\\""')).toEqual(['valor com "aspas"']);
  });

  test('barra invertida fora de aspas escapa o próximo caractere', () => {
    expect(splitCommandLine('echo a\\ b')).toEqual(['echo', 'a b']);
  });

  test('aspas não fechadas devolvem null em vez de um token truncado', () => {
    expect(splitCommandLine('echo "aspas')).toBeNull();
    expect(splitCommandLine("echo 'aspas")).toBeNull();
  });

  test('string vazia produz lista vazia', () => {
    expect(splitCommandLine('')).toEqual([]);
  });
});

describe('commandMatches', () => {
  const planned = 'bun test tests/x.test.ts';

  test('aceita o argv com os mesmos tokens do plano', () => {
    expect(commandMatches(planned, ['bun', 'test', 'tests/x.test.ts'])).toBe(true);
  });

  test('aceita a execução do texto exato do plano via bash -c', () => {
    expect(commandMatches(planned, ['bash', '-c', planned])).toBe(true);
  });

  test('rejeita sh -c quando o texto diverge do plano', () => {
    expect(commandMatches(planned, ['sh', '-c', 'bun test tests/outro.test.ts'])).toBe(false);
  });

  test('rejeita um programa diferente mesmo com os demais tokens iguais', () => {
    expect(commandMatches(planned, ['node', 'test', 'tests/x.test.ts'])).toBe(false);
  });
});

describe('vacuousCommandReason', () => {
  test('sinaliza comandos que não exercitam comportamento', () => {
    for (const command of ['true', ':', 'echo ok', "sh -c 'true'"]) {
      expect(vacuousCommandReason(command)).not.toBeNull();
    }
  });

  test('aceita um comando que roda uma asserção real', () => {
    expect(vacuousCommandReason('bun test tests/x.test.ts')).toBeNull();
  });
});

describe('isWholeSuiteCommand', () => {
  test('reconhece runners sem alvo como suíte inteira', () => {
    for (const command of [
      'bun test',
      'bun run test',
      'npm test',
      'npx vitest run',
      'pytest',
      'go test ./...',
      'node --test',
      'bun test --timeout 5000',
    ]) {
      expect(isWholeSuiteCommand(command)).toBe(true);
    }
  });

  test('com arquivo, filtro ou pacote alvo deixa de ser suíte inteira', () => {
    for (const command of [
      'bun test tests/x.test.ts',
      "bun test -t 'nome do caso'",
      'pytest tests/test_x.py',
      'go test ./internal/auth',
    ]) {
      expect(isWholeSuiteCommand(command)).toBe(false);
    }
  });
});

describe('genericCommandReason', () => {
  test('comando vácuo é recusado antes de qualquer outra checagem', () => {
    expect(genericCommandReason('true')).not.toBeNull();
  });

  test('comando igual a um gate global é recusado como repetição de gate', () => {
    const reason = genericCommandReason('bun test', ['bun test']);
    expect(reason).toContain('repete um gate');
  });

  test('suíte inteira sem gates é recusada por não ter alvo', () => {
    const reason = genericCommandReason('bun test');
    expect(reason).toContain('suíte inteira');
  });

  test('comando focado em uma task não gera motivo algum', () => {
    expect(genericCommandReason('bun test tests/x.test.ts')).toBeNull();
  });
});

describe('genericExpectReason', () => {
  test('marcadores do runner são genéricos demais', () => {
    for (const marker of ['fail', '(fail)', 'Error', 'expected']) {
      expect(genericExpectReason(marker)).not.toBeNull();
    }
  });

  test('texto curto demais não identifica a asserção', () => {
    expect(genericExpectReason('abc')).not.toBeNull();
  });

  test('identificador específico da asserção é aceito', () => {
    expect(genericExpectReason('VALUE-NEW-001')).toBeNull();
  });
});

describe('placeholderPathReason', () => {
  test('diretórios são recusados como caminho de arquivo', () => {
    expect(placeholderPathReason('src/')).not.toBeNull();
    expect(placeholderPathReason('.')).not.toBeNull();
  });

  test('globs são recusados', () => {
    expect(placeholderPathReason('src/**')).not.toBeNull();
    expect(placeholderPathReason('*.ts')).not.toBeNull();
  });

  test('placeholders são recusados', () => {
    expect(placeholderPathReason('<arquivo>.ts')).not.toBeNull();
    expect(placeholderPathReason('TODO.ts')).not.toBeNull();
  });

  test('arquivo concreto é aceito', () => {
    expect(placeholderPathReason('src/app.ts')).toBeNull();
  });
});

describe('parsePlanTask', () => {
  test('extrai todos os campos da task declarada no plano', () => {
    const task = parsePlanTask(PLAN, '1.1');
    expect(task).not.toBeNull();
    if (!task) return;

    expect(task.id).toBe('1.1');
    expect(task.marker).toBe(' ');
    expect(task.title).toBe('Tokenizar linha de comando');
    expect(task.lines[0]).toBe('### [ ] [1.1] Tokenizar linha de comando');
    expect(task.implementationFiles).toEqual(['src/core/acceptance.ts', 'src/core/cli.ts']);
    expect(task.testFiles).toEqual(['tests/acceptance.test.ts']);
    expect(task.components).toEqual(['core']);
    expect(task.red).toEqual({
      command: 'bun test tests/acceptance.test.ts',
      description: 'falha porque a tokenização ainda não existe',
    });
    expect(task.acs).toEqual([
      { command: 'bun test tests/acceptance-split.test.ts', description: 'tokeniza aspas simples' },
      { command: 'bun test tests/acceptance-quote.test.ts', description: 'tokeniza aspas duplas' },
    ]);
    expect(task.visual).toEqual({ required: false, command: null });
    expect(task.documentation).toEqual({ required: false, command: null });
  });

  test('devolve null para um id inexistente', () => {
    expect(parsePlanTask(PLAN, '9.9')).toBeNull();
  });

  test('o id "1.1" casa com o heading "[1.1]"', () => {
    expect(parsePlanTask(PLAN, '1.1')?.id).toBe('1.1');
  });
});

describe('parsePlanTasks', () => {
  test('lê as duas tasks na ordem do arquivo', () => {
    const tasks = parsePlanTasks(PLAN);
    expect(tasks.map((task) => task.id)).toEqual(['1.1', '1.2']);
    expect(tasks[1].title).toBe('Interface visual do relatório');
  });
});

describe('parseGlobalGates', () => {
  test('devolve null quando a seção não existe', () => {
    expect(parseGlobalGates('# Plano\n\n### [ ] [1.1] X\n')).toBeNull();
  });

  test('devolve lista vazia quando a seção é N/A', () => {
    expect(parseGlobalGates('# Plano\n\n## Global gates\n\nN/A\n')).toEqual([]);
  });

  test('lê itens com e sem comando entre crases preservando o marcador', () => {
    const gates = parseGlobalGates(['## Global gates', '- [ ] `bun test` — roda tudo', '- [!] revisar lint manualmente', ''].join('\n'));
    expect(gates).toEqual([
      { marker: ' ', command: 'bun test', text: '`bun test` — roda tudo' },
      { marker: '!', command: null, text: 'revisar lint manualmente' },
    ]);
  });
});

describe('requiredAuditChecks', () => {
  test('lista os ACs e REGRESSION quando visual e documentação não são exigidos', () => {
    const task = parsePlanTask(PLAN, '1.1');
    if (!task) throw new Error('task 1.1 ausente no fixture');
    expect(requiredAuditChecks(task)).toEqual(['AC-1', 'AC-2', 'REGRESSION']);
  });

  test('inclui VISUAL e DOCUMENTATION quando o plano os exige', () => {
    const task = parsePlanTask(PLAN, '1.2');
    if (!task) throw new Error('task 1.2 ausente no fixture');
    expect(requiredAuditChecks(task)).toEqual(['AC-1', 'VISUAL', 'DOCUMENTATION', 'REGRESSION']);
  });
});

describe('allowedCheckCommands', () => {
  const taskOne = parsePlanTask(PLAN, '1.1')!;
  const taskTwo = parsePlanTask(PLAN, '1.2')!;

  test('AC fora do range declarado devolve erro', () => {
    const result = allowedCheckCommands(PLAN, taskOne, 'AC-3');
    expect(result.error).toBeDefined();
    expect(result.commands).toEqual([]);
  });

  test('AC válido devolve o comando declarado no plano', () => {
    expect(allowedCheckCommands(PLAN, taskOne, 'AC-1')).toEqual({ commands: ['bun test tests/acceptance-split.test.ts'] });
  });

  test('VISUAL sem exigência no plano devolve erro', () => {
    expect(allowedCheckCommands(PLAN, taskOne, 'VISUAL').error).toBeDefined();
  });

  test('VISUAL exigido devolve o comando de **Playwright:**', () => {
    expect(allowedCheckCommands(PLAN, taskTwo, 'VISUAL')).toEqual({ commands: ['bun run e2e'] });
  });

  test('DOCUMENTATION exigido devolve o comando de **Evidence:**', () => {
    expect(allowedCheckCommands(PLAN, taskTwo, 'DOCUMENTATION')).toEqual({ commands: ['bun run docs'] });
  });

  test('REGRESSION soma a coluna Regression do componente aos gates globais', () => {
    expect(allowedCheckCommands(PLAN, taskOne, 'REGRESSION')).toEqual({
      commands: ['bun test tests/core.test.ts', 'bun run typecheck'],
    });
  });

  test('check desconhecido devolve erro', () => {
    expect(allowedCheckCommands(PLAN, taskOne, 'BOGUS').error).toBe('check desconhecido: BOGUS');
  });
});

describe('taskDefinitionDigest', () => {
  const digestFor = (planText: string): string => {
    const task = parsePlanTask(planText, '1.1');
    if (!task) throw new Error('task 1.1 ausente no fixture');
    return taskDefinitionDigest(planText, task);
  };

  test('não muda quando só o estado dos checkboxes muda', () => {
    const toggled = PLAN.replaceAll('[ ]', '[x]');
    expect(digestFor(toggled)).toBe(digestFor(PLAN));
  });

  test('muda quando o comando de um AC muda', () => {
    const changed = PLAN.replace('bun test tests/acceptance-split.test.ts', 'bun test tests/acceptance-split-v2.test.ts');
    expect(digestFor(changed)).not.toBe(digestFor(PLAN));
  });

  test('muda quando o comando de RED muda', () => {
    const changed = PLAN.replace('bun test tests/acceptance.test.ts', 'bun test tests/acceptance-red-v2.test.ts');
    expect(digestFor(changed)).not.toBe(digestFor(PLAN));
  });
});

describe('normalizeCommand', () => {
  test('canoniza espaços em excesso entre tokens', () => {
    expect(normalizeCommand('bun    test   tests/x.test.ts')).toBe('bun test tests/x.test.ts');
  });
});
