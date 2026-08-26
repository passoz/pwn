# Proveniência do Port: software-engineering

- **Repositório de Origem:** `/home/passoz/dev/ai-engineering-skills`
- **Commit de Origem:** `43b295d0140d89bf1bd5ef6a9eaead536f9ddda5`
- **Data da Origem:** Fri Aug 21 10:03:36 2026 +0000
- **Data do Port:** 2026-08-26
- **Status da Linhagem:** Port independente v3 com proveniência registrada. Sem sincronização bidirecional automática.

## Regras de Governança do Port (DEC-015 / BR-004)

1. O repositório original não é removido, alterado ou redirecionado pelo Piwerness.
2. A primeira importação preserva comportamento, contratos, testes e documentação antes de evoluir funcionalidades.
3. Este arquivo `PORTED_FROM.md` registra a linhagem e inventário do conteúdo portado.
4. Os arquivos portados passam a ter evolução própria neste repositório.
5. Atualização futura exige `pwn pack diff software-engineering --source <path>` e port explícito.
6. Os adapters do Piwerness usam `/pwn-*` para coexistir pacificamente com `/make-*` da origem.

## Inventário Portado

- `skills/` -> `packs/software-engineering/skills/`
- `scripts/` -> `packs/software-engineering/scripts/`
- `adapters/` -> `packs/software-engineering/adapters/`
- `tests/` -> `packs/software-engineering/tests/`
- `docs/` -> `packs/software-engineering/docs/`
- `package.json` -> `packs/software-engineering/package.json`
- `CONTEXT.md` -> `packs/software-engineering/CONTEXT.md`
- `.specs/` -> `packs/software-engineering/.specs/`
