---
description: Cria entidade completa do domínio pra fora (entity → service → API → React)
argument-hint: "[-h | entidade] [campos]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem alterar o projeto:

```text
Uso: /entity ENTIDADE [CAMPOS]

Formas:
  /entity invoice "number string, total int64"   Cria a entidade completa com os campos informados.
  /entity invoice                                Solicita os campos ausentes antes de implementar.
  /entity -h                                     Exibe esta ajuda sem criar código.
```

Cria a entidade **$1** seguindo clean architecture do domínio pra fora:

## Domain

1. **Entity** em `internal/domain/entity/${1}.go`:
   ```go
   type ${1^} struct {
       ID        string    // UUID v7
       ${2}
       CreatedAt time.Time
       UpdatedAt time.Time
       DeletedAt *time.Time // soft delete
   }
   ```

2. **Repository interface** em `internal/domain/repository/${1}_repository.go`:
   ```go
   type ${1^}Repository interface {
       Create(ctx context.Context, ${1} *${1^}) error
       GetByID(ctx context.Context, id string) (*${1^}, error)
       List(ctx context.Context) ([]${1^}, error)
       Update(ctx context.Context, ${1} *${1^}) error
       SoftDelete(ctx context.Context, id string) error
   }
   ```

## Database

3. **Migration** em `db/migrations/` com campos: $2
4. **Queries sqlc** em `db/queries/${1}s.sql` (Create, GetByID, List, Update, SoftDelete)
5. Rodar `sqlc generate`

## Implementação

6. **Repository** em `internal/repository/sqlite/${1}_repository.go` implementando a interface
7. **Service** em `internal/service/${1}_service.go` com:
   - Validação (validator v10)
   - Logs (slog)
   - Gerar UUID v7 na criação
8. **Handler da API** em `internal/handler/api/${1}_handler.go` com endpoints REST

## Frontend React

9. **Service de API** em `frontend/src/services/${1}s.ts` com funções fetch para `/api/v1/${1}s`
10. **Página de listagem** em `frontend/src/pages/${1^}List.tsx` com tabela e ações (criar/editar/excluir em modais)
11. **Rota** adicionada em `frontend/src/App.tsx`

Usar a stack padrão: net/http, sqlc, validator v10, slog, React + TypeScript + Vite, glassmorphism.
