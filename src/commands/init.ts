import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';

import {
  DEFAULT_DECIDER,
  DEFAULT_KEY_ENV,
  DEFAULT_MAX_RISK,
  HOST_DECIDER_ENV,
  projectIdentity,
  readDeciderConfig,
  removeDeciderConfig,
  validateDeciderInput,
  writeDeciderConfig,
  type DeciderConfig,
  type DeciderInput,
} from '../core/decider/config.js';
import { decisionSignatureIsValid, listDecisions } from '../core/decider/ledger.js';
import { verifierRoot } from '../core/verifier-home.js';

const USAGE = [
  'pwn init                                   Inicializa o PWN no projeto e pergunta pela configuração do decisor',
  'pwn init --decider <provedor:modelo> [--decider-key-env VAR] [--decider-max-risk L0..L4] [--decider-endpoint URL]',
  '                                           Configura o decisor sem perguntar (CI, terminal sem TTY)',
  'pwn init --no-decider                      Registra que o projeto não usa decisor',
].join('\n');

function flagValue(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

function describe(config: DeciderConfig): string {
  return config.enabled
    ? `decisor ${config.decider} (chave em $${config.key_env}, teto de risco ${config.max_risk}${config.endpoint ? `, endpoint ${config.endpoint}` : ''})`
    : 'sem decisor: as decisões do operador continuam com você';
}

async function ask(previous: DeciderConfig | null): Promise<DeciderInput | null> {
  const prompt = createInterface({ input: process.stdin });
  // Iterador de linhas: guarda o que chega antes de cada pergunta (colagem, pipe);
  // `question()` descartaria essas linhas. Fim de entrada = aceitar o padrão.
  const lines = prompt[Symbol.asyncIterator]();
  const question = async (text: string, fallback: string): Promise<string> => {
    process.stdout.write(`${text} [${fallback}]: `);
    const next = await lines.next();
    const value = next.done ? '' : String(next.value).trim();
    if (next.done) process.stdout.write('\n');
    return value || fallback;
  };
  try {
    const current = previous?.enabled ? previous : null;
    const answer = (await question('Usar um modelo decisor no lugar do operador? (s/n)', previous?.enabled ? 's' : 'n')).toLowerCase();
    if (!['s', 'sim', 'y', 'yes'].includes(answer)) return null;
    const decider = await question('Decisor (<provedor>:<modelo>)', current?.decider ?? process.env[HOST_DECIDER_ENV]?.trim() ?? DEFAULT_DECIDER);
    const keyEnv = await question('Variável de ambiente com a chave da API', current?.key_env ?? DEFAULT_KEY_ENV);
    const maxRisk = await question('Teto de risco decidido pelo modelo; acima dele a decisão volta para você', current?.max_risk ?? DEFAULT_MAX_RISK);
    return validateDeciderInput({ decider, keyEnv, maxRisk, endpoint: current?.endpoint ?? null });
  } finally {
    prompt.close();
  }
}

function repositoryRootOrNull(): string | null {
  const top = spawnSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' });
  return top.status === 0 ? top.stdout.trim() : null;
}

export async function initCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);
    return 0;
  }
  const repositoryRoot = repositoryRootOrNull();
  if (!repositoryRoot) {
    console.error('✗ pwn init precisa rodar dentro de um repositório Git (worktrees, diff guard e recibos dependem dele).');
    return 1;
  }
  const decider = flagValue(args, '--decider');
  if (args.includes('--decider') && decider === null) {
    console.error('✗ --decider exige <provedor>:<modelo>');
    return 1;
  }
  if (decider && args.includes('--no-decider')) {
    console.error('✗ use --decider ou --no-decider, não os dois');
    return 1;
  }

  console.log(`=== [pwn init] ${repositoryRoot} ===`);
  const previous = readDeciderConfig(repositoryRoot);
  if (previous) console.log(`Configuração atual: ${describe(previous)}`);

  let input: DeciderInput | null;
  if (decider) {
    input = {
      decider,
      keyEnv: flagValue(args, '--decider-key-env') ?? DEFAULT_KEY_ENV,
      maxRisk: flagValue(args, '--decider-max-risk') ?? DEFAULT_MAX_RISK,
      endpoint: flagValue(args, '--decider-endpoint'),
    };
  } else if (args.includes('--no-decider')) {
    input = null;
  } else if (process.stdin.isTTY) {
    input = await ask(previous);
  } else {
    // Sem terminal não há a quem perguntar: nunca trava esperando entrada.
    if (previous) {
      console.log('Sem terminal e sem flags: configuração do decisor mantida.');
      return 0;
    }
    console.warn(`⚠  Sem terminal para perguntar pelo decisor: projeto registrado sem decisor. Para configurar: pwn init --decider ${DEFAULT_DECIDER}`);
    input = null;
  }

  const config = writeDeciderConfig(repositoryRoot, input);
  console.log(`✓ ${describe(config)}`);
  console.log(`  gravado fora do repositório, em ${verifierRoot()}/deciders/`);
  if (config.enabled && !process.env[config.key_env]) {
    console.warn(`⚠  $${config.key_env} não está definida nesta sessão: sem ela, cada decisão vai para a fila humana.`);
  }
  return 0;
}

const DECIDER_USAGE = [
  'pwn decider show                           Mostra a configuração do decisor deste projeto',
  'pwn decider set [--decider <provedor:modelo>] [--decider-key-env VAR] [--decider-max-risk L0..L4] [--decider-endpoint URL|default]',
  '                                           Cria ou altera a configuração; campos omitidos mantêm o valor atual',
  'pwn decider remove                         Remove a configuração: o projeto passa a não usar decisor',
  'pwn decider log [--work NNNN]              Decisões tomadas pelo decisor, com motivos e assinatura conferida',
].join('\n');

export function deciderCommand(action: string, args: string[]): number {
  const repositoryRoot = repositoryRootOrNull();
  if (!repositoryRoot) {
    console.error('✗ pwn decider precisa rodar dentro de um repositório Git.');
    return 1;
  }
  try {
    switch (action) {
      case 'show': {
        const config = readDeciderConfig(repositoryRoot);
        console.log(config ? describe(config) : "nenhuma configuração: rode 'pwn decider set' ou 'pwn init'");
        return 0;
      }
      case 'set': {
        const previous = readDeciderConfig(repositoryRoot);
        const current = previous?.enabled ? previous : null;
        const decider = flagValue(args, '--decider') ?? current?.decider ?? null;
        if (!decider) {
          console.error('✗ não há decisor configurado: informe --decider <provedor:modelo>');
          return 1;
        }
        const endpoint = flagValue(args, '--decider-endpoint');
        const config = writeDeciderConfig(repositoryRoot, {
          decider,
          keyEnv: flagValue(args, '--decider-key-env') ?? current?.key_env ?? DEFAULT_KEY_ENV,
          maxRisk: flagValue(args, '--decider-max-risk') ?? current?.max_risk ?? DEFAULT_MAX_RISK,
          endpoint: endpoint === 'default' ? null : (endpoint ?? current?.endpoint ?? null),
        });
        console.log(`✓ ${describe(config)}`);
        if (config.enabled && !process.env[config.key_env]) {
          console.warn(`⚠  $${config.key_env} não está definida nesta sessão: sem ela, cada decisão vai para a fila humana.`);
        }
        return 0;
      }
      case 'remove':
        console.log(removeDeciderConfig(repositoryRoot)
          ? '✓ configuração removida: o projeto não usa decisor'
          : 'nenhuma configuração para remover');
        return 0;
      case 'log': {
        const workId = flagValue(args, '--work');
        const records = listDecisions(projectIdentity(repositoryRoot)).filter((record) => !workId || record.work_id === workId);
        if (!records.length) {
          console.log('nenhuma decisão registrada');
          return 0;
        }
        for (const record of records) {
          const tokens = record.usage ? `, ${record.usage.input_tokens}+${record.usage.output_tokens} tokens` : '';
          const signature = decisionSignatureIsValid(record) ? 'assinatura ok' : 'ASSINATURA INVÁLIDA';
          console.log(`${record.created_at}  ${record.point.padEnd(7)} ${record.work_id}/${record.task_id}  ${record.outcome}${record.action ? ` (${record.action})` : ''}`);
          console.log(`  ${record.decision_id} — ${record.model ?? record.decider}${tokens}, ${signature}`);
          for (const reason of record.reasons) console.log(`  · ${reason}`);
        }
        return 0;
      }
      default:
        console.error(`Ação desconhecida para 'pwn decider': ${action || '(vazia)'}\n\nUso:\n${DECIDER_USAGE}`);
        return 1;
    }
  } catch (error) {
    console.error(`✗ ${(error as Error).message}`);
    return 1;
  }
}
