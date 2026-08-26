---
name: go-test
description: Padrões de teste para Go — unitários em tudo, integração com banco real, e2e dos handlers web com httptest.
---

# Testes

## Regras

- **Testes unitários em TODO código** — nenhuma função ou método relevante sem teste
- **Testes de integração** em toda funcionalidade — banco real (SQLite), HTTP real (httptest)
- **Código só é validado após testes passarem** — nada de commit sem `go test ./...` passando

## Pilha de Testes

| Tipo | O que testa | Ferramenta |
|------|-------------|------------|
| **Unitário** | Service, validação, lógica pura | `testing` stdlib + mocks manuais |
| **Integração** | Repository com banco real, handler API HTTP | `testing` + `httptest` + `testcontainers-go` |
| **API HTTP** | Handlers REST, middlewares, auth, JSON | `httptest` stdlib |
| **Web** | Handlers web/, serve SPA corretamente, fallback de rotas | `httptest` stdlib |

## Estrutura

```text
internal/
├── repository/
│   ├── sqlite/
│   │   ├── user_repository.go
│   │   └── user_repository_test.go    # integração com SQLite real
│   └── mocks/
│       └── user_repository.go         # mock manual (sem lib)
├── service/
│   ├── user_service.go
│   └── user_service_test.go           # unitário com mocks
├── handler/
│   ├── api/
│   │   ├── user_handler.go
│   │   └── user_handler_test.go       # integração HTTP com httptest
│   └── web/
│       ├── spa_handler.go
│       └── spa_handler_test.go        # httptest: serve SPA
├── middleware/
│   ├── auth.go
│   └── auth_test.go                   # httptest: middleware chain
```

## Unitário (mock manual)

```go
// internal/repository/mocks/user_repository.go
type MockUserRepository struct {
    users []User
    err   error
}

func (m *MockUserRepository) List(ctx context.Context) ([]User, error) {
    return m.users, m.err
}

// internal/service/user_service_test.go
func TestCreateUser(t *testing.T) {
    t.Parallel()
    mock := &mocks.MockUserRepository{}
    svc := NewUserService(mock)
    // testa regras de negócio, validação, erros esperados
}
```

## Integração (banco real + HTTP real)

```go
// internal/repository/sqlite/user_repository_test.go
func TestUserRepository(t *testing.T) {
    t.Parallel()
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        t.Fatal(err)
    }
    defer db.Close()
    runMigrations(db)

    repo := NewUserRepository(db)
    // testa CRUD real no banco
}

// internal/handler/api/user_handler_test.go
func TestListUsersHandler(t *testing.T) {
    t.Parallel()
    mock := &mocks.MockUserRepository{users: testUsers}
    svc := service.NewUserService(mock)
    handler := NewUserHandler(svc)

    mux := http.NewServeMux()
    handler.Register(mux, authMiddleware)

    req := httptest.NewRequest("GET", "/api/v1/users", nil)
    w := httptest.NewRecorder()
    mux.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
    }
}
```

## Web (httptest — serve SPA)

O handler web serve o SPA embedado e faz fallback de rotas para o React Router:

```go
// internal/handler/web/spa_handler_test.go
func TestSPA_ServesIndex(t *testing.T) {
    srv := setupTestServer(t)
    defer srv.Close()

    req := httptest.NewRequest(http.MethodGet, "/", nil)
    rec := httptest.NewRecorder()
    srv.ServeHTTP(rec, req)

    assert.Equal(t, http.StatusOK, rec.Code)
    assert.Contains(t, rec.Body.String(), `<div id="root">`)
}
```

## Comandos

```bash
# Unitários + integração
go test ./...

# Com cobertura (mínimo 80%)
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Race detector
go test -race ./...

# Tudo
go test ./...
```

## Cobertura Mínima

- **Unitários:** 90%+ das linhas de service/domain
- **Integração:** 100% dos endpoints handler API
- **Web:** serve o SPA e fallback de rota corretamente
