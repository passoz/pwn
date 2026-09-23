import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync, readFileSync, lstatSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { runOrchestrated, prepareSandbox, modifiedFiles, EXIT_SUSPENDED } from '../src/core/run-orchestrator.js';
import { resolveGitDir, createGitWorktreeSandbox } from '../src/core/sandbox.js';

function git(cwd: string, ...args: string[]) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
}

function fixture(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-orch-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'Test');
  // Arquivo commitado que escreve FORA do escopo quando executado.
  writeFileSync(path.join(root, 'out-of-scope.js'), "require('fs').writeFileSync('forbidden.txt','x');\n", 'utf8');
  git(root, 'add', '.');
  git(root, 'commit', '-qm', 'seed');
  return root;
}

function writeWork(root: string, acceptanceCommand: string) {
  const workDir = path.join(root, '.pwn', 'work', '0001');
  mkdirSync(workDir, { recursive: true });
  writeFileSync(path.join(workDir, 'plan.json'), JSON.stringify({
    work_id: '0001',
    title: 't',
    components: [{ name: 'core', purpose: 'nucleo' }],
    global_gates: ['suite'],
    tasks: [
      {
        id: '1.1',
        title: 'Task',
        requirement_id: 'FR-001',
        spec_reference: 'CAP-001',
        contract_id: 'CTR-001',
        depends_on: [],
        components: ['core'],
        files: ['out-of-scope.js'],
        implementation_files: ['out-of-scope.js'],
        test_files: ['out-of-scope.js'],
        red: { command: 'node out-of-scope.js', description: 'falha esperada' },
        implementation_steps: ['step'],
        acceptance_criteria: [{ command: 'node out-of-scope.js', description: 'passa' }],
      },
    ],
  }), 'utf8');
  writeFileSync(path.join(workDir, 'CTR-001.json'), JSON.stringify({
    contract_version: '4.0',
    task_id: '1.1',
    work_id: '0001',
    title: 'Task',
    risk: { level: 'L2', reasons: ['teste'] },
    validation_strategy: 'tdd-strict',
    behavioral_contract: { scenarios: [] },
    change_contract: { target_files: [], affected_components: [] },
    architecture_contract: { invariants: [] },
    acceptance_contract: { commands: [acceptanceCommand], required_evidence: [] },
    scope_contract: { write_allow: ['allowed.txt'], write_deny: [] },
    budget_contract: { max_agent_attempts: 3, max_shell_executions: 10 },
    escalation_contract: { on_write_violation: 'block_and_escalate', on_budget_exceeded: 'escalate_to_strong_agent', on_attempt_failed: 'retry_with_strong' },
  }), 'utf8');
}

test('runOrchestrated detecta escrita fora do escopo e limpa o sandbox', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'out-of-scope.js'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.diffViolations.length > 0, true, 'deve reportar violação de diff');
    assert.match(result.diffViolations[0], /forbidden\.txt/);
    assert.equal(result.status, 1);

    // Sandbox removido após a execução.
    const sandboxes = path.join(root, '.pwn', 'sandboxes');
    const leftovers = existsSync(sandboxes) ? spawnSync('bash', ['-c', `ls -A '${sandboxes}'`], { encoding: 'utf8' }).stdout.trim() : '';
    assert.equal(leftovers, '', 'sandbox deve ser removido após a run');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('runOrchestrated nega comando fora da allowlist da política', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['echo', 'hi'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /allowlist|negado|policy/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('prepareSandbox linka node_modules e copia bunfig.toml', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-prep-'));
  const sandbox = mkdtempSync(path.join(tmpdir(), 'pwn-prep-sb-'));
  try {
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'bunfig.toml'), '[test]\nroot = "tests"\n', 'utf8');

    prepareSandbox(sandbox, root);

    assert.equal(lstatSync(path.join(sandbox, 'node_modules')).isSymbolicLink(), true, 'node_modules deve ser symlink');
    assert.equal(existsSync(path.join(sandbox, 'bunfig.toml')), true, 'bunfig.toml deve ser copiado');
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(sandbox, { recursive: true, force: true });
  }
});

test('runOrchestrated suspende e enfileira tarefas L4 sem executar', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    // Sobrescreve o contrato para risco L4.
    const ctrPath = path.join(root, '.pwn', 'work', '0001', 'CTR-001.json');
    const ctr = JSON.parse(readFileSync(ctrPath, 'utf8'));
    ctr.risk = { level: 'L4', reasons: ['teste'] };
    writeFileSync(ctrPath, JSON.stringify(ctr), 'utf8');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'out-of-scope.js'],
      timeoutSeconds: 5,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.suspended, true);
    assert.equal(result.status, EXIT_SUSPENDED);
    assert.equal(existsSync(path.join(root, 'queue', 'review', `${result.runId}.json`)), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('runOrchestrated não reporta node_modules injetado pelo harness como violação de escopo', () => {
  const root = fixture();
  try {
    // Formato canônico de .gitignore (com barra): não cobre o symlink que o harness cria.
    writeFileSync(path.join(root, '.gitignore'), 'node_modules/\n', 'utf8');
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'ok.js'), "require('fs').writeFileSync('allowed.txt','x');\n", 'utf8');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'ignore + in-scope script');
    writeWork(root, 'node ok.js');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'ok.js'],
      timeoutSeconds: 10,
      isolated: true,
      rootDir: root,
    });

    assert.deepEqual(result.diffViolations, [], 'artefato do próprio harness não é escrita do agente');
    assert.equal(result.status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('modifiedFiles resolve renames, ignora artefatos do harness por assinatura e falha alto sem repositório', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-diff-parse-'));
  try {
    git(root, 'init', '-q');
    git(root, 'config', 'user.email', 'test@example.invalid');
    git(root, 'config', 'user.name', 'Test');
    writeFileSync(path.join(root, 'old.txt'), 'x\n', 'utf8');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'seed');

    // Artefatos que o harness injeta no sandbox: node_modules linkado + bunfig.toml copiado.
    // Same size as old.txt so the rename below keeps the artifact's signature intact.
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'bunfig.toml'), 'x\n', 'utf8');

    const session = createGitWorktreeSandbox('RUN-parse', root);
    const injected = prepareSandbox(session.worktreePath, root);
    assert.deepEqual(Object.keys(injected).sort(), ['bunfig.toml', 'node_modules']);

    git(session.worktreePath, 'mv', 'old.txt', 'new.txt');
    writeFileSync(path.join(session.worktreePath, 'forbidden.txt'), 'x\n', 'utf8');

    const inventory = modifiedFiles(session.worktreePath, session.gitDir, injected);
    assert.equal(inventory.ok, true, 'inventário de um worktree válido deve ser obtido');
    const files = inventory.ok ? inventory.files : [];
    assert.ok(files.includes('new.txt'), 'rename deve ser reportado pelo destino');
    assert.ok(files.includes('old.txt'), 'rename também deve ser reportado pela origem (a remoção é uma mudança)');
    assert.ok(files.includes('forbidden.txt'), 'escrita real fora do escopo continua detectada');
    assert.ok(!files.includes('node_modules'), 'artefato injetado pelo harness é ignorado');
    assert.ok(!files.includes('bunfig.toml'), 'artefato injetado pelo harness é ignorado');

    // Mover um arquivo PARA DENTRO do artefato injetado: o destino é filtrado
    // (a assinatura do artefato continua intacta), mas a remoção da origem é uma
    // mudança real e não pode sumir do inventário. O Git reporta a origem no nível
    // do índice — `old.txt`, já que o rename intermediário estava staged.
    git(session.worktreePath, 'mv', '-f', 'new.txt', 'bunfig.toml');
    const intoArtifact = modifiedFiles(session.worktreePath, session.gitDir, injected);
    assert.equal(intoArtifact.ok, true);
    assert.ok(
      intoArtifact.ok && intoArtifact.files.includes('old.txt'),
      `rename para dentro do artefato deve reportar a origem; veio ${JSON.stringify(intoArtifact.ok ? intoArtifact.files : intoArtifact)}`,
    );
    assert.ok(intoArtifact.ok && !intoArtifact.files.includes('bunfig.toml'), 'destino continua sendo artefato do harness');

    // Substituir o artefato injetado não pode virar passe livre permanente.
    rmSync(path.join(session.worktreePath, 'node_modules'), { force: true });
    writeFileSync(path.join(session.worktreePath, 'node_modules'), 'payload\n', 'utf8');
    const tampered = modifiedFiles(session.worktreePath, session.gitDir, injected);
    assert.equal(tampered.ok, true);
    assert.ok(
      tampered.ok && tampered.files.includes('node_modules'),
      'artefato do harness substituído deve voltar ao inventário',
    );

    // Um nome contendo ' -> ' (ou aspas/espaços) não pode ser truncado para um sufixo.
    mkdirSync(path.join(session.worktreePath, 'evil -> src'), { recursive: true });
    writeFileSync(path.join(session.worktreePath, 'evil -> src', 'x.ts'), 'x\n', 'utf8');
    const arrow = modifiedFiles(session.worktreePath, session.gitDir, injected);
    assert.equal(arrow.ok, true);
    assert.ok(
      arrow.ok && arrow.files.includes('evil -> src/x.ts'),
      `nome com ' -> ' deve ser reportado inteiro; veio ${JSON.stringify(arrow.ok ? arrow.files : arrow)}`,
    );

    // Fail-closed: sem repositório não existe inventário.
    rmSync(path.join(session.worktreePath, '.git'), { force: true });
    const broken = modifiedFiles(session.worktreePath, session.gitDir, injected);
    assert.equal(broken.ok, false, 'worktree sem repositório deve devolver ok:false, nunca lista vazia');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('apagar o .git do sandbox não transfere o diff guard para o repositório-pai', () => {
  const root = fixture();
  try {
    // Sem a âncora do repositório, `git status` passaria a descrever o repositório-pai
    // — cujo .gitignore cobre .pwn/ — e a escrita fora de escopo sumiria.
    writeFileSync(path.join(root, '.gitignore'), '.pwn/\n', 'utf8');
    writeFileSync(
      path.join(root, 'kill-git.js'),
      "require('fs').rmSync('.git', { recursive: true, force: true });\nrequire('fs').writeFileSync('forbidden.txt','x');\n",
      'utf8',
    );
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'kill git then write');
    writeWork(root, 'node kill-git.js');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'kill-git.js'],
      timeoutSeconds: 10,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.status, 1, 'destruir o repositório do sandbox não pode resultar em sucesso');
    assert.match(result.diffViolations.join('\n'), /aponta para|não resolve para um repositório/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('diff guard roda mesmo quando o comando aceito falha (exit != 0)', () => {
  const root = fixture();
  try {
    // Escreve fora do escopo e só então falha: antes, o guard era pulado por inteiro
    // nesse caminho e o run terminava sem qualquer auditoria da árvore.
    writeFileSync(
      path.join(root, 'write-then-fail.js'),
      "require('fs').writeFileSync('forbidden.txt','x');\nprocess.exit(7);\n",
      'utf8',
    );
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'write then fail');
    writeWork(root, 'node write-then-fail.js');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'write-then-fail.js'],
      timeoutSeconds: 10,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.status, 1);
    assert.equal(result.diffViolations.length, 1, 'escrita fora do escopo não pode passar despercebida só porque o comando falhou');
    assert.match(result.diffViolations[0], /forbidden\.txt/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('contrato com padrão de escopo malformado falha antes de criar o sandbox', () => {
  const root = fixture();
  try {
    writeWork(root, 'node out-of-scope.js');
    const ctrPath = path.join(root, '.pwn', 'work', '0001', 'CTR-001.json');
    const ctr = JSON.parse(readFileSync(ctrPath, 'utf8'));
    ctr.scope_contract.write_deny = ['*.{pem'];
    writeFileSync(ctrPath, JSON.stringify(ctr), 'utf8');

    const result = runOrchestrated({
      workId: '0001',
      taskId: '1.1',
      command: ['node', 'out-of-scope.js'],
      timeoutSeconds: 10,
      isolated: true,
      rootDir: root,
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /CONTRACT ERROR.*padrão de escopo inválido/);
    const sandboxes = path.join(root, '.pwn', 'sandboxes');
    assert.equal(existsSync(sandboxes), false, 'nenhum sandbox pode ser criado com contrato inválido');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('artefato do harness apagado, trocado ou reescrito volta ao inventário', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'pwn-artifact-sig-'));
  try {
    git(root, 'init', '-q');
    git(root, 'config', 'user.email', 'test@example.invalid');
    git(root, 'config', 'user.name', 'Test');
    writeFileSync(path.join(root, 'seed.txt'), 'x\n', 'utf8');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'seed');
    mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(path.join(root, 'bunfig.toml'), 'x\n', 'utf8');

    const session = createGitWorktreeSandbox('RUN-sig', root);
    const injected = prepareSandbox(session.worktreePath, root);
    const nm = path.join(session.worktreePath, 'node_modules');
    const bunfig = path.join(session.worktreePath, 'bunfig.toml');
    const report = (): string[] => {
      const result = modifiedFiles(session.worktreePath, session.gitDir, injected);
      assert.equal(result.ok, true);
      return result.ok ? result.files : [];
    };

    // Intactos: nada a reportar (é o que evita falso positivo em run legítimo).
    assert.deepEqual(report(), []);

    // Apagar o link: o `git status` não reporta a remoção de uma entrada não rastreada.
    rmSync(nm, { force: true });
    assert.ok(report().includes('node_modules'), 'link apagado deve ser reportado');

    // Recriar como diretório vazio: `git status` ignora diretório vazio.
    symlinkSync(path.join(root, 'node_modules'), nm, 'dir');
    assert.deepEqual(report(), []);
    rmSync(nm, { force: true });
    mkdirSync(nm, { recursive: true });
    assert.ok(report().includes('node_modules'), 'link trocado por diretório deve ser reportado');

    // Reapontar o link para outro alvo.
    rmSync(nm, { recursive: true, force: true });
    symlinkSync(path.join(root, 'seed.txt'), nm, 'file');
    assert.ok(report().includes('node_modules'), 'link reapontado deve ser reportado');

    // Reescrever o arquivo injetado mantendo o tamanho.
    writeFileSync(bunfig, 'y\n', 'utf8');
    assert.ok(report().includes('bunfig.toml'), 'conteúdo reescrito com o mesmo tamanho deve ser reportado');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
