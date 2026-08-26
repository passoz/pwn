---
name: sqlc
description: Geração de código Go a partir de SQL puro usando sqlc. Sem ORM, queries tipadas.
---

# sqlc

## Setup

```yaml
# sqlc.yaml
version: "2"
sql:
  - engine: "sqlite"
    queries: "db/queries/"
    schema: "db/migrations/"
    gen:
      go:
        package: "repository"
        out: "internal/repository/sqlite"
        sql_package: "database/sql"
        emit_interface: true
        emit_json_tags: true
        output_db_file_name: "db.go"
        output_models_file_name: "models.go"
```

## Estrutura

```
db/
├── migrations/          # SQL migrations (golang-migrate)
│   ├── 000001_users.up.sql
│   ├── 000001_users.down.sql
│   └── ...
└── queries/             # SQL queries para o sqlc gerar
    ├── users.sql
    └── ...
```

## Queries SQL

```sql
-- db/queries/users.sql
-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC;

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: CreateUser :one
INSERT INTO users (id, name, email, password_hash)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: UpdateUser :exec
UPDATE users SET name = ?, email = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;
```

## Repository Pattern

```go
// internal/domain/repository/user_repository.go (port)
type UserRepository interface {
    List(ctx context.Context) ([]User, error)
    GetByID(ctx context.Context, id string) (*User, error)
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id string) error
}

// internal/repository/sqlite/user_repository.go (adapter)
type userRepository struct {
    db      *sql.DB
    queries *Queries
}

func NewUserRepository(db *sql.DB) domain.UserRepository {
    return &userRepository{db: db, queries: New(db)}
}
```

## Comandos

```bash
# Gerar código após criar/editar queries
sqlc generate

# Verificar se as queries estão corretas
sqlc vet

# Compilar para che se as interfaces batem
go build ./...
```
