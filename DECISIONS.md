# Decisões Arquiteturais — Piwerness

Este documento registra decisões arquiteturais significativas do projeto. Decisões aqui sobrepõem decisões anteriores em `SPEC.md` quando há conflito.

---

## DEC-029 — JSON para documentos normativos (revisão de DEC-001)

**Status:** Accepted

**Data:** 2026-08-26

**Supersedes:** DEC-001 (parcialmente)

**Contexto:**

DEC-001 estabelecia "YAML para estrutura; Markdown para conteúdo destinado ao LLM". Essa decisão foi tomada antes da necessidade de rigidez se tornar evidente.

O projeto precisa de documentos normativos (pipelines, PRDs, specs, tasks, evidence, baseline do sistema) que sejam:
- Validáveis automaticamente via schema
- Rígidos o suficiente para impedir "encher linguiça" por modelos LLM
- Processáveis por código sem parsing frágil (regex em Markdown)
- Rastreáveis e verificáveis em gates determinísticos

Markdown é legível para humanos, mas é "texto solto" — estrutura é convenção, validação depende de regex, e modelos podem facilmente adicionar conteúdo não estruturado ou ignorar campos esperados.

**Decisão:**

Adotar **JSON** como formato para todos os documentos normativos do Piwerness:

| Tipo | Formato | Schema |
|------|---------|--------|
| Pipelines | JSON | `schemas/pipeline.schema.json` |
| PRDs | JSON | `schemas/prd.schema.json` |
| Specs (baseline do sistema) | JSON | `schemas/system.schema.json` |
| Tasks (planos atomizados) | JSON | `schemas/tasks.schema.json` |
| Evidence (registros de evidência) | JSON | `schemas/evidence.schema.json` |

**Exceções (mantêm formatos anteriores):**
- **Documentação humana** (README, guias, tutoriais) → Markdown.
- **Transcrições e atas** → Markdown.
- **Arquivos descritivos livres** (referenciados por JSON) → Markdown.
- **Configurações de runtime** (`.pi/`, `opencode.jsonc`, etc.) → conforme cada runtime.

Cada documento JSON normativo deve:
1. Referenciar seu schema via `$schema`.
2. Ser validável automaticamente antes de qualquer processamento.
3. Ter campos obrigatórios que impedem omissões.
4. Ser rejeitado pelo gate se não validar.

**Consequências:**

Positivas:
- Validação automática com `ajv`, `zod` ou similar.
- Campos obrigatórios garantem completude.
- Dificulta "modelos burros" improvisarem — se o campo é obrigatório, tem que ter valor.
- Gates podem validar estrutura antes de processar.
- Diff/merge mais limpo.
- Elimina ambiguidade sobre "o que é normativo".

Negativas:
- Edição manual menos ergonômica.
- Menos legível para leitura rápida.
- Requer tooling para edição confortável.

Mitigações:
- CLI `pwn` gera templates JSON automaticamente.
- `pwn validate` verifica conformidade com schemas.
- Editor visual (Fase 7) para pipelines e specs.
- Arquivos Markdown descritivos podem complementar (via campo `description_file`).

**Decisões afetadas:**
- **DEC-001** → superseded parcialmente (YAML foi substituído por JSON para normativos).
- **DEC-008** → Pipeline é JSON, não YAML. Editor visual (DEC-020) deve adaptar-se.
- **DEC-020** → Editor visual deve suportar JSON (não apenas YAML).

**Rastreabilidade:**
- Implementado em: `schemas/*.schema.json`, `packs/core/pipeline-core.json`
- Próximo: converter `SPEC.md` → `spec.json`, `.specs/system.md` → `.specs/system.json`

---

## Formato de ID

Decisões usam o formato `DEC-XXX` onde XXX é um número sequencial de 3 dígitos.

Decisões novas (pós v1.2) são registradas neste arquivo. Decisões anteriores permanecem em `SPEC.md §15` até serem explicitamente superseded.

**Regra de supersede:** uma decisão com `Supersedes: DEC-XXX` substitui a decisão anterior. O texto da decisão anterior em SPEC.md permanece para histórico, mas não é mais normativo.
