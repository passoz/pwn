#!/usr/bin/env bash
# ==============================================================================
# Piwerness (pwn) — Preparação de Work de Reimplementação de Sistema Legado
# ==============================================================================
# Cria a cadeia completa e VÁLIDA de um Work a partir de uma spec legada
# (discovery → requirements → PRD → spec → plan + contrato V4 congelado),
# aprova os 5 gates determinísticos, valida os schemas e exibe a cápsula.
# A spec legada é copiada para `.piwerness/work/<id>/legacy-spec.md`.
#
# USO:
#   ./prepare-legacy-reimplementation.sh <caminho-para-spec.md> [work-id]
#
# AMBIENTE:
#   PWN_DIR  diretório do projeto-alvo (default: cwd)
#   PWN_BIN  comando do CLI (default: `pwn` no PATH, senão bun <repo>/bin/pwn.js)
# ==============================================================================

set -euo pipefail

LEGACY_SPEC="${1:-}"
WORK_ID="${2:-}"

if [ -z "$LEGACY_SPEC" ]; then
  echo "❌ Uso: $0 <caminho-para-spec.md> [work-id]"
  echo "   Variáveis: PWN_DIR=<projeto-alvo> PWN_BIN='<comando-do-cli>'"
  exit 1
fi
if [ ! -f "$LEGACY_SPEC" ]; then
  echo "❌ Spec legada não encontrada: $LEGACY_SPEC"
  exit 1
fi
LEGACY_SPEC_ABS="$(cd "$(dirname "$LEGACY_SPEC")" && pwd)/$(basename "$LEGACY_SPEC")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -n "${PWN_BIN:-}" ]; then
  PWN="$PWN_BIN"
elif command -v pwn >/dev/null 2>&1; then
  PWN="pwn"
else
  PWN="bun $REPO_ROOT/bin/pwn.js"
fi

TARGET_DIR="${PWN_DIR:-$PWD}"
if [ ! -d "$TARGET_DIR" ]; then
  echo "❌ PWN_DIR não existe: $TARGET_DIR"
  exit 1
fi
cd "$TARGET_DIR"

TITLE="Reimplementação do legado $(basename "$LEGACY_SPEC")"

echo "================================================================================"
echo "🚀 [PIWERNESS LEGADO] $TITLE"
echo "   Origem: $LEGACY_SPEC_ABS"
echo "   Alvo:   $TARGET_DIR"
echo "   CLI:    $PWN"
echo "================================================================================"
echo ""

# ── ETAPA 1: cadeia completa e válida (com snapshot da spec legada) ───────────
echo "🔹 [1/4] Criando cadeia de artefatos (scaffold + spec legada)..."
SCAFFOLD_OUT="$(eval "$PWN work scaffold --title \"\$TITLE\" --source \"$LEGACY_SPEC_ABS\" ${WORK_ID:+--work $WORK_ID}")"
echo "$SCAFFOLD_OUT"
echo ""

RESOLVED_ID="$(printf '%s' "$SCAFFOLD_OUT" | grep -oE 'Work [0-9]{4}' | head -1 | grep -oE '[0-9]{4}' || true)"
RESOLVED_ID="${RESOLVED_ID:-${WORK_ID:-0001}}"
echo "✓ Work ID resolvido: $RESOLVED_ID"
echo ""

# ── ETAPA 2: validar contratos congelados ─────────────────────────────────────
echo "🔹 [2/4] Validando contratos V4 congelados..."
eval "$PWN work contract --work $RESOLVED_ID"
echo ""

# ── ETAPA 3: gates determinísticos + schemas ─────────────────────────────────
echo "🔹 [3/4] Avaliando os 5 portões determinísticos..."
for GATE in GATE-DISC-REQ GATE-REQ-PRD GATE-PRD-SPEC GATE-SPEC-PLAN GATE-PLAN-CONTRACT; do
  echo "  ↳ $GATE"
  eval "$PWN work gate $GATE --work $RESOLVED_ID > /dev/null"
done
echo "✓ Cadeia de 5 gates aprovada."
eval "$PWN validate --work $RESOLVED_ID"
echo ""

# ── ETAPA 4: cápsula de contexto ─────────────────────────────────────────────
echo "🔹 [4/4] Cápsula de contexto congelada (V4):"
echo "--------------------------------------------------------------------------------"
eval "$PWN task capsule 1.1 $RESOLVED_ID"
echo "--------------------------------------------------------------------------------"
echo ""
echo "================================================================================"
echo "✅ [PRÉ-IMPLEMENTAÇÃO CONCLUÍDA]"
echo "================================================================================"
echo "👉 Próximos passos:"
echo "   1. Detalhe .piwerness/work/$RESOLVED_ID/plan.json usando legacy-spec.md como fonte."
echo "   2. Regenerar o markdown:  $PWN work plan --work $RESOLVED_ID --force"
echo "   3. Executar sob sandbox:  $PWN work run --work $RESOLVED_ID --task 1.1 -- bun test"
echo "================================================================================"
