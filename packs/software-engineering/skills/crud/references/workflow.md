---
description: Cria um CRUD completo de uma entidade seguindo a stack (Go + React SPA)
argument-hint: "[-h | entidade] [campos]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem alterar o projeto:

```text
Uso: /crud ENTIDADE [CAMPOS]

Formas:
  /crud user "name string, email string"   Cria o CRUD de user com os campos informados.
  /crud product                            Solicita os campos ausentes antes de implementar.
  /crud -h                                 Exibe esta ajuda sem criar código.
```

Cria um CRUD completo para a entidade **$1** seguindo a stack padrão:

## Backend (API REST)

1. **Migration** em `db/migrations/` com campos: $2
   - ID UUID v7 (TEXT), created_at, updated_at, deleted_at (nullable)
2. **Query SQL** em `db/queries/${1}s.sql` com:
   - Create, GetByID, List, Update, SoftDelete (UPDATE deleted_at)
3. Rodar `sqlc generate`
4. **Repository** em `internal/repository/sqlite/` implementando a interface
5. **Service** em `internal/service/` com validação (validator v10) + logs (slog)
6. **Handler da API** em `internal/handler/api/` com:
   - `POST /api/v1/${1}s` — criar
   - `GET /api/v1/${1}s/{id}` — obter
   - `GET /api/v1/${1}s` — listar
   - `PUT /api/v1/${1}s/{id}` — atualizar
   - `DELETE /api/v1/${1}s/{id}` — soft delete
7. **Rotas registradas** em `cmd/server/main.go` com middleware chain

## Frontend React

8. **Página de listagem** em `frontend/src/pages/${1^}List.tsx`:
   - Tabela com dados carregados via fetch(`/api/v1/${1}s`)
   - Botão "Novo" que abre modal de criação
   - Botão "Editar" em cada linha que abre modal de edição
   - Botão "Excluir" com confirmação

9. **Modal de formulário** em `frontend/src/components/${1^}Form.tsx`:
   - Formulário de criar/editar com validação
   - Submit via POST ou PUT para `/api/v1/${1}s`
   - Fecha modal e recarrega listagem após sucesso

10. **Modal de detalhes** (opcional) em `frontend/src/components/${1^}Detail.tsx`

11. **Rota** adicionada em `frontend/src/App.tsx`:
    ```tsx
    <Route path="/${1}s" element={<${1^}List />} />
    ```

12. **Service de API** em `frontend/src/services/${1}s.ts`:
    ```ts
    export const list${1^}s = () => fetch('/api/v1/${1}s')
    export const get${1^} = (id: string) => fetch(`/api/v1/${1}s/${id}`)
    export const create${1^} = (data: ${1^}Input) => fetch('/api/v1/${1}s', { method: 'POST', body: JSON.stringify(data) })
    export const update${1^} = (id: string, data: ${1^}Input) => fetch(`/api/v1/${1}s/${id}`, { method: 'PUT', body: JSON.stringify(data) })
    export const delete${1^} = (id: string) => fetch(`/api/v1/${1}s/${id}`, { method: 'DELETE' })
    ```

Usar a stack padrão: Go net/http, sqlc, validator v10, slog, React + TypeScript + Vite, glassmorphism.
