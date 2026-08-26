---
description: Cria migration SQL + sqlc query para uma tabela
argument-hint: "[-h | nome-tabela] [colunas]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem alterar banco ou arquivos:

```text
Uso: /migration NOME_TABELA [COLUNAS]

Formas:
  /migration invoices "number TEXT, total INTEGER"   Cria migration e queries para a tabela.
  /migration invoices                                Solicita colunas ausentes antes de criar.
  /migration -h                                      Exibe esta ajuda sem gerar migration.
```

Cria migration e sqlc query para a tabela **$1**:

## Migration

1. Criar `db/migrations/XXXXXX_${1}.up.sql`:
   ```sql
   CREATE TABLE ${1} (
       id TEXT PRIMARY KEY,           -- UUID v7
       ${2}
       created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
       updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
       deleted_at DATETIME            -- soft delete
   );
   ```
2. Criar `db/migrations/XXXXXX_${1}.down.sql`:
   ```sql
   DROP TABLE IF EXISTS ${1};
   ```

## Queries sqlc

3. Criar `db/queries/${1}.sql`:
   ```sql
   -- name: Create${1^} :one
   INSERT INTO ${1} (id, ${2//[^a-z_ ]/})  -- ajustar campos
   VALUES (?, ?, ?, ?, ?)
   RETURNING *;

   -- name: Get${1^} :one
   SELECT * FROM ${1} WHERE id = ? AND deleted_at IS NULL;

   -- name: List${1^}s :many
   SELECT * FROM ${1} WHERE deleted_at IS NULL ORDER BY created_at DESC;

   -- name: Update${1^} :exec
   UPDATE ${1} SET ${2//[^a-z_ ]/} WHERE id = ?;

   -- name: SoftDelete${1^} :exec
   UPDATE ${1} SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?;
   ```

4. Rodar `sqlc generate`
5. Rodar `go build ./...` pra verificar se compila
