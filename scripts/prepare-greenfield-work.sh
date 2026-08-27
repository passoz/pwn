#!/usr/bin/env bash
# ==============================================================================
# Piwerness (pwn) — Script de Preparação para Novo Projeto (Greenfield)
# ==============================================================================
# Este script executa a esteira autônoma de governança do Piwerness a partir de
# uma ideia bruta (sem spec legada previa) cobrindo todas as pré-etapas até antes
# da implementação em código (congelamento de contratos V4 e aprovação em gates).
#
# USO:
#   ./scripts/prepare-greenfield-work.sh "<titulo-ou-ideia-do-projeto>" [work-id]
# Exemplo:
#   ./scripts/prepare-greenfield-work.sh "Novo Módulo de Pagamentos PIX" 0004
# ==============================================================================

set -e

WORK_TITLE="${1:-Novo Projeto Greenfield Piwerness}"
PROVIDED_WORK_ID="$2"
PWN_BIN="bun bin/pwn.js"

echo "================================================================================"
echo "🚀 [PIWERNESS GREENFIELD PIPELINE]"
echo "💡 Ideia / Título: $WORK_TITLE"
echo "================================================================================"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 1: Inicializar Estrutura de Artefatos do Work (Auto-Incremento Inteligente)
# ------------------------------------------------------------------------------
if [ -n "$PROVIDED_WORK_ID" ]; then
  INIT_OUTPUT=$($PWN_BIN work init "$PROVIDED_WORK_ID")
else
  INIT_OUTPUT=$($PWN_BIN work init)
fi

echo "$INIT_OUTPUT"

# Extrair Work ID resolvido da saída do comando init
WORK_ID=$(echo "$INIT_OUTPUT" | grep -oP 'Work \K[0-9]{4}' | head -n 1)
if [ -z "$WORK_ID" ]; then
  WORK_ID="0001"
fi

echo "✓ Work ID resolvido: $WORK_ID"
WORK_DIR=".piwerness/work/$WORK_ID"
echo ""

# ------------------------------------------------------------------------------
# ETAPA 2: Gerar Artefatos de Discovery, Requisitos e PRD
# ------------------------------------------------------------------------------
echo "🔹 [ETAPA 2/7] Gerando Discovery, Requisitos e PRD a partir da ideia..."

# 2.1 Discovery (Intake & Grilling Inicial)
cat <<EOF > "$WORK_DIR/discovery.json"
{
  "work_id": "$WORK_ID",
  "title": "$WORK_TITLE",
  "grilling_depth": "medium",
  "summary": "Levantamento de escopo e restrições para a construção greenfield de $WORK_TITLE",
  "key_decisions": [
    "Adotar arquitetura modular baseada em contratos V4",
    "Garantir 100% de cobertura com suíte de testes TDD"
  ]
}
EOF

# 2.2 Requisitos (requirements.json)
cat <<EOF > "$WORK_DIR/requirements.json"
{
  "\$schema": "../../../schemas/tasks.schema.json",
  "work_id": "$WORK_ID",
  "requirements": [
    {
      "id": "REQ-GF-001",
      "title": "Implementar funcionalidade principal de $WORK_TITLE",
      "description": "Desenvolver módulo greenfield atendendo ao contrato de arquitetura do Piwerness",
      "acceptance_criteria": [
        "Componente deve ser testável e passar em 100% dos testes unitários",
        "Modificações restritas aos diretórios da allowlist de escrita"
      ]
    }
  ]
}
EOF

# 2.3 Decisão de Produto (prd.json)
cat <<EOF > "$WORK_DIR/prd.json"
{
  "\$schema": "../../../schemas/prd.schema.json",
  "prd_version": "1.0",
  "work_id": "$WORK_ID",
  "title": "PRD — $WORK_TITLE",
  "summary": "Especificação funcional para construção do novo módulo",
  "accepted_requirements": ["REQ-GF-001"],
  "out_of_scope": ["Integrações com sistemas legado não declarados"]
}
EOF

echo "✓ discovery.json, requirements.json e prd.json gerados."
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
  "title": "Especificação Técnica Greenfield — $WORK_TITLE",
  "capabilities": [
    {
      "id": "CAP-GF-01",
      "name": "$WORK_TITLE",
      "description": "Capacidade autônoma desenvolvida sob Bun/TypeScript",
      "rules": ["BR-GF-001: Respeitar limites contratuais V4 e Diff Guard"]
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
      "title": "Implementar funcionalidade atômica inicial de $WORK_TITLE",
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
echo "✅ [PRÉ-IMPLEMENTAÇÃO GREENFIELD CONCLUÍDA COM SUCESSO!]"
echo "================================================================================"
echo "Todos os 5 Portões Determinísticos foram aprovados."
echo "Os contratos de 7 dimensões foram congelados e os limites de escrita (Diff Guard) estão ativos."
echo ""
echo "👉 PRÓXIMO PASSO (Início da Implementação Isolada em Sandbox):"
echo "   bun bin/pwn.js task run T-001"
echo "================================================================================"
