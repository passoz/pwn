import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canonicalJson } from '../../src/core/acceptance.js';
import { captureDependencyDigest, captureSnapshot } from '../../src/core/candidate-snapshot.js';
import { buildReceipt, signatureIsValid } from '../../src/core/verification-receipt.js';

/**
 * Gera testdata/parity/verify/fixture.json a partir da referência TypeScript.
 *
 * O arquivo fixa approval_id, recibo assinado, digest do snapshot e digest das
 * dependências. Os testes Go recalculam tudo com o port e comparam: a assinatura
 * Ed25519 é determinística, então qualquer divergência de bytes canônicos
 * aparece como falha.
 */
const root = process.cwd();
const directory = path.join(root, 'testdata/parity/verify');
const key = JSON.parse(
  fs.readFileSync(path.join(root, 'testdata/parity/golden/ed25519-key.json'), 'utf8'),
) as { private: string; public: string };

const privateKey = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', d: key.private, x: key.public },
  format: 'jwk',
});
const publicKey = createPublicKey(privateKey);
const privatePEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicPEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const fingerprint = createHash('sha256')
  .update(publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex');

const verifierRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-parity-verifier-'));
fs.mkdirSync(path.join(verifierRoot, 'keys'), { recursive: true });
fs.writeFileSync(path.join(verifierRoot, 'keys', 'verifier-private.pem'), privatePEM);
fs.writeFileSync(path.join(verifierRoot, 'keys', 'verifier-public.pem'), publicPEM);
const config = {
  version: 1,
  verifier_id: 'parity-verifier',
  created_at: '2026-01-01T00:00:00.000Z',
  runtime: { bun: '/nonexistent/bun' },
  isolation: { mode: 'bwrap', bwrap: null, network: false },
};
fs.writeFileSync(path.join(verifierRoot, 'config.json'), `${JSON.stringify(config, null, 2)}\n`);

const approvalContent = {
  version: 1,
  work_id: '0002',
  task_id: '1.3',
  kind: 'task',
  approved_by: 'operator',
  created_at: '2026-01-02T03:04:05.678Z',
  plan_path: '.todo/0002-tasks.md',
  plan_sha256: '1111111111111111111111111111111111111111111111111111111111111111',
  contract_id: 'CTR-001',
  contract_sha256: '2222222222222222222222222222222222222222222222222222222222222222',
  baseline_commit: '0123456789abcdef0123456789abcdef01234567',
  implementation_files: ['src/lib.ts'],
  checks: [
    {
      id: 'AC-1',
      command: ['/usr/bin/bun', 'test', 'tests/acceptance.test.ts'],
      expect_output: null,
      require_baseline_failure: true,
    },
    {
      id: 'REGRESSION',
      command: ['/usr/bin/bun', 'test'],
      expect_output: 'ok',
      require_baseline_failure: false,
    },
  ],
  approved_files: [
    {
      path: 'tests/acceptance.test.ts',
      sha256: '3333333333333333333333333333333333333333333333333333333333333333',
    },
  ],
};
const approvalId = createHash('sha256').update(canonicalJson(approvalContent)).digest('hex');
const approval = { approval_id: approvalId, ...approvalContent };

const result = {
  checks: [
    {
      id: 'AC-1',
      command: ['/usr/bin/bun', 'test', 'tests/acceptance.test.ts'],
      outcome: 'pass',
      exit_code: 0,
      output_digest: '4444444444444444444444444444444444444444444444444444444444444444',
      output_tail: '1 pass',
      baseline: {
        exit_code: 1,
        output_digest: '5555555555555555555555555555555555555555555555555555555555555555',
        output_tail: '1 fail',
        suspect_environmental: false,
      },
    },
    {
      id: 'REGRESSION',
      command: ['/usr/bin/bun', 'test'],
      outcome: 'pass',
      exit_code: 0,
      output_digest: '6666666666666666666666666666666666666666666666666666666666666666',
      output_tail: 'ok',
    },
  ],
  snapshot_digest: '7777777777777777777777777777777777777777777777777777777777777777',
  dependency_digest: '8888888888888888888888888888888888888888888888888888888888888888',
  sandbox_digest: '9999999999999999999999999999999999999999999999999999999999999999',
  sandbox_policy: {
    engine: 'bwrap',
    network: false,
    user_namespace: true,
    pid_namespace: true,
    mounts_ro: ['/bin', '/etc', '/lib', '/lib64', '/usr'],
    mounts: [],
    home: '/nonexistent',
    env_allowlist: ['PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM'],
    path_prepend: [],
    env: {},
  },
};
const receipt = buildReceipt({ approval, result, verifierRootDir: verifierRoot });
if (!signatureIsValid(receipt, verifierRoot)) {
  throw new Error('o recibo de referência não verifica');
}

// Árvore fixa do snapshot: os caminhos de estado do harness e de dependências
// ficam de fora.
const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-parity-tree-'));
fs.mkdirSync(path.join(tree, 'sub'), { recursive: true });
fs.writeFileSync(path.join(tree, 'a.txt'), 'alpha\n');
fs.writeFileSync(path.join(tree, 'sub', 'b.txt'), 'beta\n');
fs.symlinkSync('a.txt', path.join(tree, 'link.txt'));
fs.mkdirSync(path.join(tree, '.git'), { recursive: true });
fs.writeFileSync(path.join(tree, '.git', 'HEAD'), 'ref: refs/heads/main\n');
fs.mkdirSync(path.join(tree, 'node_modules', 'pkg'), { recursive: true });
fs.writeFileSync(path.join(tree, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;\n');
fs.mkdirSync(path.join(tree, '.todo'), { recursive: true });
fs.writeFileSync(path.join(tree, '.todo', 'x.md'), 'x\n');
const snapshot = captureSnapshot(tree);

const deps = fs.mkdtempSync(path.join(os.tmpdir(), 'pwn-parity-deps-'));
const manifests = {
  'package.json': '{"name":"x"}\n',
  'bun.lock': 'lock\n',
  'bunfig.toml': 'logLevel = "error"\n',
};
for (const [name, content] of Object.entries(manifests)) {
  fs.writeFileSync(path.join(deps, name), content);
}
const dependency = captureDependencyDigest(deps);

const fixture = {
  note: 'gerado por bun a partir da referência TypeScript; não edite à mão',
  verifier: { config, private_key_pem: privatePEM, public_key_pem: publicPEM, fingerprint },
  approval_content: approvalContent,
  approval_id: approvalId,
  receipt,
  snapshot: {
    tree: [
      { path: 'a.txt', content: 'alpha\n' },
      { path: 'sub/b.txt', content: 'beta\n' },
      { path: 'link.txt', symlink: 'a.txt' },
      { path: '.git/HEAD', content: 'ref: refs/heads/main\n' },
      { path: 'node_modules/pkg/index.js', content: 'module.exports = 1;\n' },
      { path: '.todo/x.md', content: 'x\n' },
    ],
    files: snapshot.files,
    digest: snapshot.digest,
  },
  dependency: { manifests, files: dependency.files, digest: dependency.digest },
};

fs.mkdirSync(directory, { recursive: true });
fs.writeFileSync(path.join(directory, 'fixture.json'), `${JSON.stringify(fixture, null, 2)}\n`);

fs.rmSync(verifierRoot, { recursive: true, force: true });
fs.rmSync(tree, { recursive: true, force: true });
fs.rmSync(deps, { recursive: true, force: true });
console.log(
  JSON.stringify({
    approval_id: approvalId,
    receipt_id: receipt.receipt_id,
    snapshot: snapshot.digest,
    dependency: dependency.digest,
  }),
);
