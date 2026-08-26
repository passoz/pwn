import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { validateSystemSpec } from "../scripts/validate_system_spec.js";

const VALID = `# SYSTEM SPEC: Gestão de pedidos

**Status:** Baseline parcial
**Versão:** 1
**Última reconciliação:** 2026-08-14
**Escopo da baseline:** criação, consulta e cancelamento de pedidos pelos clientes cadastrados.

## Propósito e resultados sistêmicos

**Problema sistêmico:** Clientes precisam registrar e acompanhar solicitações de compra sem depender de atendimento manual.

**Resultado sistêmico:** Clientes criam e acompanham pedidos enquanto o sistema preserva o estado válido de cada solicitação.

## Fronteira do sistema

### Dentro da fronteira

- Registro, consulta e cancelamento de pedidos.

### Fora da fronteira

- Processamento financeiro realizado pelo provedor externo.

## Atores e sistemas externos

- **ACT-001 — Cliente:** cria e acompanha os próprios pedidos. **Evidência:** \`README.md\`.
- **ACT-002 — Provedor de pagamento:** confirma ou rejeita pagamentos. **Evidência:** decisão explícita do usuário.

## Capacidades sistêmicas

### CAP-001 — Gerenciar pedido

**Valor:** Permite ao cliente registrar e acompanhar uma solicitação de compra.

**Atores:** \`ACT-001\`.

**Comportamento:** O cliente cria um pedido e consulta seu estado atual.

**Falhas e limites:** Um cliente não consulta nem cancela pedidos de outro cliente.

**Regras relacionadas:** \`BR-001\`.

**Contratos relacionados:** \`CON-001\`.

**Evidência:** \`README.md\`, \`tests/orders.test.js\`.

## Regras e invariantes globais

- **BR-001:** Um pedido pertence a exatamente um cliente e somente esse cliente pode consultá-lo ou cancelá-lo. **Cobertura:** \`CAP-001\`. **Evidência:** \`tests/orders.test.js\`.

## Contratos observáveis

### CON-001 — Pedidos

**Consumidores:** \`ACT-001\`.

**Entradas:** dados válidos para criação, identidade do cliente e identificador do pedido.

**Saídas e efeitos:** pedido registrado, estado atual consultável ou cancelamento confirmado.

**Erros:** pedido inexistente ou pertencente a outro cliente não expõe seus dados nem altera seu estado.

**Compatibilidade:** Nenhuma política pública de versionamento foi confirmada nas fontes inspecionadas.

**Evidência:** \`README.md\`, \`tests/orders.test.js\`.

## Modelo conceitual do domínio

- **ENT-001 — Pedido:** solicitação de compra pertencente a um cliente e acompanhada por estado. **Evidência:** \`CONTEXT.md\`, \`tests/orders.test.js\`.

## Dados e ciclo de vida

- O pedido é registrado, consultado e pode ser cancelado enquanto a regra de ownership permanece válida. (\`ENT-001\`, \`BR-001\`) **Evidência:** \`tests/orders.test.js\`.

## Segurança, privacidade e autorização

- A identidade do cliente limita consulta e cancelamento aos pedidos próprios. (\`BR-001\`, \`CON-001\`) **Evidência:** \`tests/orders.test.js\`.

## Qualidades sistêmicas

- **SQR-001:** A consulta de pedido não deve revelar dados de um pedido pertencente a outro cliente. **Cobertura:** \`CAP-001\`, \`CON-001\`. **Evidência:** \`tests/orders.test.js\`.

## Integrações externas

- **INT-001 — Provedor de pagamento:** recebe a solicitação de cobrança e devolve confirmação ou rejeição sob ownership externo. **Cobertura:** \`CAP-001\`. **Evidência:** decisão explícita do usuário.

## Restrições e decisões vigentes

- O processamento financeiro permanece fora da fronteira e sob responsabilidade do provedor externo, conforme decisão explícita do usuário.

## Registro de cobertura e drift

| ID | Estado | Evidência | Observação |
|----|--------|-----------|------------|
| \`CAP-001\` | Confirmado | \`README.md\`, \`tests/orders.test.js\` | Capacidade e limites coerentes nas fontes. |
| \`GAP-001\` | Lacuna | \`README.md\` | Política pública de compatibilidade ainda não possui fonte normativa. |

## Rastreabilidade sistêmica

| Capacidade | Atores | Regras | Contratos | Entidades | Qualidades | Integrações |
|------------|--------|--------|-----------|-----------|-----------|------------|
| \`CAP-001\` | \`ACT-001\` | \`BR-001\` | \`CON-001\` | \`ENT-001\` | \`SQR-001\` | \`INT-001\` |

## Política de evolução

- Mudanças de comportamento começam em \`/make-prompt\` referenciando esta baseline.
- O prompt declara capacidades, regras e contratos preservados ou alterados.
- Após implementação validada, esta spec é reconciliada quando o comportamento sistêmico muda.
- Divergência entre spec e sistema é registrada como drift, sem escolha silenciosa de fonte.
`;

function validate(content) {
  const directory = mkdtempSync(path.join(tmpdir(), "validate-system-spec-"));
  const file = path.join(directory, "system.md");
  writeFileSync(file, content, "utf8");
  return validateSystemSpec(file);
}

test("accepts a traceable partial system baseline", () => {
  const result = validate(VALID);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, { capabilities: 1, rules: 1, contracts: 1, gaps: 1 });
  assert.equal(result.status, "Baseline parcial");
});

test("rejects unresolved markers and checkboxes", () => {
  const result = validate(VALID.replace(
    "- Registro, consulta e cancelamento de pedidos.",
    "- [ ] TODO: Registro, consulta e cancelamento de pedidos.",
  ));
  assert.ok(result.errors.some((error) => error.includes("unresolved marker")));
  assert.ok(result.errors.some((error) => error.includes("checkboxes are not allowed")));
});

test("requires each capability in coverage and traceability", () => {
  let result = validate(VALID.replace(
    "| `CAP-001` | Confirmado | `README.md`, `tests/orders.test.js` | Capacidade e limites coerentes nas fontes. |\n",
    "",
  ));
  assert.ok(result.errors.some((error) => error.includes("capability missing from coverage register: CAP-001")));

  result = validate(VALID.replace(
    "| `CAP-001` | `ACT-001` | `BR-001` | `CON-001` | `ENT-001` | `SQR-001` | `INT-001` |\n",
    "",
  ));
  assert.ok(result.errors.some((error) => error.includes("capability missing from system traceability: CAP-001")));
});

test("requires capability actors rules contracts and evidence", () => {
  const result = validate(VALID.replace("**Regras relacionadas:** `BR-001`.\n", ""));
  assert.ok(result.errors.some((error) => error.includes("CAP-001 missing concrete field: Regras relacionadas")));
  assert.ok(result.errors.some((error) => error.includes("CAP-001 must reference at least one BR-* ID")));
});

test("rejects references to unknown IDs", () => {
  const result = validate(VALID.replace("`BR-001`, `CON-001`", "`BR-999`, `CON-001`"));
  assert.ok(result.errors.some((error) => error.includes("reference to unknown ID: BR-999")));
});

test("validated baseline cannot retain gaps", () => {
  const result = validate(VALID.replace("**Status:** Baseline parcial", "**Status:** Baseline validada"));
  assert.ok(result.errors.some((error) => error.includes("Baseline validada cannot contain GAP-* entries")));
});

test("requires evidence for normative entries", () => {
  const result = validate(VALID.replace(" **Evidência:** `tests/orders.test.js`.", ""));
  assert.ok(result.errors.some((error) => error.includes("BR-001 missing evidence")));
});

test("requires sequential stable IDs", () => {
  const result = validate(VALID.replaceAll("ACT-002", "ACT-003"));
  assert.ok(result.errors.some((error) => error.includes("ACT IDs must be sequential")));
});
