/**
 * POST JSON síncrono para os adaptadores do decisor.
 *
 * Os pontos de decisão do PWN (aprovação, fila L4, lote, import) são síncronos; o
 * `fetch` do Bun não é. O adaptador roda este script com `spawnSync`: entrada
 * `{ url, body, timeout_ms }` no stdin, chave em `PWN_DECIDER_AUTH` (nunca em argv),
 * saída `{ status, body }` ou `{ error }` no stdout. 429/529 têm backoff exponencial.
 */

const RETRYABLE: Record<number, true> = { 429: true, 529: true };
const ATTEMPTS = 3;

interface WorkerInput {
  url: string;
  body: unknown;
  timeout_ms: number;
}

async function main(): Promise<void> {
  const input = JSON.parse(await Bun.stdin.text()) as WorkerInput;
  const key = process.env.PWN_DECIDER_AUTH ?? "";
  let last: { status: number; body: string } | null = null;
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    if (attempt > 0) await Bun.sleep(1000 * 2 ** (attempt - 1));
    const response = await fetch(input.url, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify(input.body),
      signal: AbortSignal.timeout(input.timeout_ms),
    });
    last = { status: response.status, body: await response.text() };
    if (!RETRYABLE[response.status]) break;
  }
  process.stdout.write(JSON.stringify(last));
}

main().catch((error: unknown) => {
  process.stdout.write(JSON.stringify({ error: (error as Error).message }));
});
