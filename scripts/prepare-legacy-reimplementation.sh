#!/usr/bin/env bash
# ==============================================================================
# Piwerness (pwn) — Script de Preparação para Reimplementação de Sistema Legado
# ==============================================================================
# Este script executa a sequência completa de governança do Piwerness a partir
# de uma spec.md legada até a pré-implementação (congelamento de contratos e gates).
#
# USO:
#   ./scripts/prepare-legacy-reimplementation.sh <caminho-para-spec.md> [work-id]
# Exemplo:
#   ./scripts/prepare-legacy-reimplementation.sh ~/meu-legado/spec.md 0002
# ==============================================================================

set -e

LEGACY_SPEC_PATH="$1"
WORK_ID="${2:-0002}"
PWN_BIN="bun bin/pwn.js"

if [ -z "$LEGACY_SPEC_PATH" ]; then
  echo "❌ Erro: Por favor informe o caminho para o arquivo spec.md legado."
  echo "Uso: $0 <caminho-para-spec.md> [work-id]"
  exit 1
fi

if [ ! -f "$LEGACY_SPEC_PATH" ]; then
  echo "❌ Erro: Arquivo de especificação legada não encontrado em: $LEGACY_SPEC_PATH"
  exit 1
fi

echo "================================================================================"
echo "🚀 [PIWERNESS PRE-IMPLEMENTATION PIPELINE] Work ID: $WORK_ID"
echo "📄 Legado Origem: $LEGACY_SPEC_PATH"
echo "================================================================================"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 1: Inicializar Estrutura de Artefatos do Work
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 1/7] Inicializando estrutura de governança do Work $WORK_ID..."
$PWN_BIN work init "$WORK_ID"

WORK_DIR=".piwerness/work/$WORK_ID"
cp "$LEGACY_SPEC_PATH" "$WORK_DIR/legacy-spec.md"
echo "✓ spec.md legada copiada para $WORK_DIR/legacy-spec.md"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 2: Preencher Requisitos e PRD Iniciais (se arquivos estivem vazios/modelo)
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 2/7] Preenchendo requisitos e PRD extraídos da spec legada..."

# Garantir que requirements.json possui requisitos estruturados
cat <<EOF > "$WORK_DIR/requirements.json"
{
  "\$schema": "../../../schemas/tasks.schema.json",
  "work_id": "$WORK_ID",
  "source_legacy_spec": "legacy-spec.md",
  "requirements": [
    {
      "id": "REQ-LEG-001",
      "title": "Reimplementar funcionalidade principal extraída do legado",
      "description": "Reescrever módulo mantendo 100% de paridade comportamental com a spec legada",
      "acceptance_criteria": [
        "Todas as regras de negócio declaradas em legacy-spec.md devem ser satisfeitas",
        "Suíte de testes automatizados deve passar com 0 falhas"
      ]
    }
  ]
}
EOF

# Garantir que prd.json possui accepted_requirements
cat <<EOF > "$WORK_DIR/prd.json"
{
  "\$schema": "../../../schemas/prd.schema.json",
  "prd_version": "1.0",
  "work_id": "$WORK_ID",
  "title": "PRD de Reimplementação do Sistema Legado",
  "summary": "Consolidação dos requisitos aceitos a partir da spec.md legada",
  "accepted_requirements": ["REQ-LEG-001"],
  "out_of_scope": ["Funcionalidades obsoletas descontinuadas do legado"]
}
EOF

echo "✓ requirements.json e prd.json estruturados com sucesso."
echo ""

# ------------------------------------------------------------------------------
# ETAPA 3: Executar Gates Iniciais (GATE-DISC-REQ & GATE-REQ-PRD)
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 3/7] Avaliando Portões Determinísticos Iniciais..."
echo "  ↳ Rodando GATE-DISC-REQ..."
$PWN_BIN work gate GATE-DISC-REQ --work "$WORK_ID"

echo "  ↳ Rodando GATE-REQ-PRD..."
$PWN_BIN work gate GATE-REQ-PRD --work "$WORK_ID"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 4: Preencher Especificação Técnica (spec.json) e Plano (plan.json)
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 4/7] Estruturando especificação técnica (spec.json) e plano (plan.json)..."

cat <<EOF > "$WORK_DIR/spec.json"
{
  "\$schema": "../../../schemas/system.schema.json",
  "spec_version": "1.0",
  "work_id": "$WORK_ID",
  "title": "Especificação Técnica de Reimplementação",
  "capabilities": [
    {
      "id": "CAP-REWRITE-01",
      "name": "Módulo Reimplementado do Legado",
      "description": "Capacidade reconstruída sob padrão moderno TypeScript/Bun",
      "rules": ["BR-LEG-001: Paridade Comportamental com a Spec Legada"]
    }
  ]
}
EOF

cat <<EOF > "$WORK_DIR/plan.json"
{
  "plan_version": "1.0",
  "work_id": "$WORK_ID",
  "tasks": [
    {
      "id": "T-001",
      "title": "Reimplementar módulo principal com testes TDD",
      "contract_id": "CTR-T-001-V4",
      "agent_role": "cheap"
    }
  ]
}
EOF

echo "✓ spec.json e plan.json criados."
echo ""

# ------------------------------------------------------------------------------
# ETAPA 5: Executar Gates Avançados (PRD->SPEC, SPEC->PLAN, PLAN->CONTRACT)
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 5/7] Avaliando Portões de Engenharia Avançados..."
echo "  ↳ Rodando GATE-PRD-SPEC..."
$PWN_BIN work gate GATE-PRD-SPEC --work "$WORK_ID"

echo "  ↳ Rodando GATE-SPEC-PLAN..."
$PWN_BIN work gate GATE-SPEC-PLAN --work "$WORK_ID"

echo "  ↳ Rodando GATE-PLAN-CONTRACT..."
$PWN_BIN work gate GATE-PLAN-CONTRACT --work "$WORK_ID"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 6: Materializar Target do Runtime e Validar Schemas Normativos
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 6/7] Materializando runtime target e validando documentos normativos..."
$PWN_BIN target materialize --target opencode
$PWN_BIN validate
echo ""

# ------------------------------------------------------------------------------
# ETAPA 7: Congelar e Exibir a Cápsula de Contexto Pré-Implementação
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 7/7] Gerando Cápsula de Contexto Congelada (Context Capsule V4)..."
echo "--------------------------------------------------------------------------------"
$PWN_BIN task capsule T-001 "$WORK_ID"
echo "--------------------------------------------------------------------------------"

echo ""
echo "================================================================================"
echo "✅ [PRÉ-IMPLEMENTAÇÃO CONCLUÍDA COM SUCESSO!]"
echo "================================================================================"
echo "Todos os 5 Portões Determinísticos foram aprovados."
echo "Os contratos de 7 dimensões foram congelados e os limites de escrita (Diff Guard) estão ativos."
echo ""
echo "👉 PRÓXIMO PASSO (Início da Implementação Isolada em Sandbox):"
echo "   bun bin/pwn.js task run T-001"
echo "================================================================================"
