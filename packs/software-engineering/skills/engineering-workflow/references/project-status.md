---
description: Exibe índice read-only dos Works ou panorama de um plano explicitamente selecionado.
argument-hint: "[-h | NNNN | .todo/NNNN-tasks.md | legacy] [--json]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente:

```text
Uso: /make-status [NNNN | CAMINHO | legacy] [--json]

Formas:
  /make-status                         Lista todos os Works e planos do repositório.
  /make-status 0007                    Mostra o plano `.todo/0007-tasks.md`.
  /make-status .todo/0007-tasks.md     Usa o caminho canônico explícito.
  /make-status legacy                  Mostra `.todo/tasks.md` durante compatibilidade.
  /make-status --json                  Retorna o índice em JSON.
```

## PROTOCOLO

1. Read-only: não altere plano, evidência, código ou documentação.
2. Sem alvo, liste `.work/NNNN.json`, artefatos e panorama de todos os Works; não escolha o plano mais recente.
3. Com alvo, aceite somente `NNNN`, `.todo/NNNN-tasks.md` ou `legacy`.
4. Não execute testes, builds, rede ou gates.
5. `[x]`, `[ ]`, `[!]`, evidência namespaced e atestado candidato são fatos distintos.
6. Evidência divergente aparece como `STALE`.
7. Não exponha conteúdo de logs ou secrets.

## EXECUÇÃO

Resolva `skill_dir` e execute uma vez:

```bash
node "SKILL_DIR/scripts/project_status.js" [ALVO] [--json]
```

Sem alvo, omita `[ALVO]`. Preserve stdout, stderr e exit reais. Responda com a saída sem reinterpretar.

## ESTADOS

O panorama de um plano mantém a precedência:

1. `INVALID PLAN`;
2. `STALE EVIDENCE`;
3. `BLOCKED`;
4. `INCONSISTENT STATE`;
5. `IN PROGRESS`;
6. `INCONSISTENT ORDER`;
7. `NOT STARTED`;
8. `TASKS COMPLETE`;
9. `COMPLETE`;
10. `NO TASKS`.

Evidência usa `.todo/evidence/NNNN/`. Um plano v3 precisa coincidir com `.work/NNNN.json` e `.todo/NNNN-tasks.md`. O índice também mostra `legacy` sem atribuir número silenciosamente.
