import fs from 'node:fs';
import path from 'node:path';

const proof = { node_modules_visible: false, network: false, check_exit: 1, source: 'stub' };
fs.mkdirSync(path.resolve('testdata/parity'), { recursive: true });
fs.writeFileSync(path.resolve('testdata/parity/sandbox.json'), `${JSON.stringify(proof, null, 2)}\n`, 'utf8');
console.error('SANDBOX-PROOF-FAILED: stub ainda não executa o sandbox');
process.exit(1);
