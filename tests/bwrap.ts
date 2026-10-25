import { spawnSync } from "node:child_process";

/**
 * `true` quando o bwrap do host cria namespaces de verdade.
 *
 * O binário pode existir e o kernel recusar `--unshare-user` (por exemplo,
 * runners com AppArmor restringindo user namespaces). Nesse caso os testes de
 * isolamento não provam nada e devem pular, nunca passar com o sandbox inativo.
 */
let cached: boolean | null = null;

export function bwrapUsable(): boolean {
  if (cached !== null) return cached;
  const probe = spawnSync(
    "bwrap",
    ["--unshare-user", "--unshare-pid", "--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true"],
    { timeout: 5000 },
  );
  cached = probe.status === 0;
  return cached;
}
