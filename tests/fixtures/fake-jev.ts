/**
 * Servidor Jev falso para testes: processo separado (o adaptador usa `spawnSync`, que
 * bloquearia um servidor no mesmo processo). Responde com o conteúdo de
 * `FAKE_JEV_REPLY` (JSON `{ status?, body }`, relido a cada pedido) e anexa cada pedido
 * em `FAKE_JEV_LOG` (JSONL com headers e corpo). Imprime a porta na primeira linha.
 */
import { appendFileSync, readFileSync } from "node:fs";

const server = Bun.serve({
  port: 0,
  async fetch(request) {
    const body = await request.json();
    appendFileSync(process.env.FAKE_JEV_LOG!, `${JSON.stringify({ authorization: request.headers.get("authorization"), body })}\n`);
    const reply = JSON.parse(readFileSync(process.env.FAKE_JEV_REPLY!, "utf8")) as { status?: number; body: unknown };
    return new Response(JSON.stringify(reply.body), { status: reply.status ?? 200, headers: { "content-type": "application/json" } });
  },
});
console.log(server.port);
