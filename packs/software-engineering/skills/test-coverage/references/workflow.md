---
description: Verifica a cobertura de testes da última implementação e implementa os testes faltantes
argument-hint: "[-h | scope] [commit-ref]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem rodar testes ou alterar código:

```text
Uso: /test-coverage [all|unit|integration|api|e2e] [COMMIT_REF]

Formas:
  /test-coverage                    Analisa todas as mudanças recentes.
  /test-coverage unit               Limita a testes unitários.
  /test-coverage api HEAD~2         Analisa API desde a referência informada.
  /test-coverage -h                 Exibe esta ajuda sem executar testes.
```

Verifica a cobertura de testes das alterações mais recentes e implementa os testes que estão faltando, seguindo os padrões de teste da stack.

## Análise

1. **Identificar o que mudou:**
   - Rodar `git diff --stat HEAD~1` (ou `$2` se informado) para ver os arquivos alterados
   - Se for um commit específico, usar `git diff --stat $2..HEAD`
   - Categorizar as mudanças: handlers API, services, repositories, migrations, frontend

2. **Verificar cobertura existente:**
   - Para cada arquivo Go alterado, verificar se existe o `_test.go` correspondente
   - Rodar `go test -coverprofile=coverage.out ./...` e analisar oCoverage por pacote
   - Identificar funções/métodos não testados com:
     ```bash
     go tool cover -func=coverage.out | grep -E "(0\.0%)|($(git diff --name-only HEAD~1 | grep '\.go$' | sed 's/\.go$//' | tr '\n' '|'))"
     ```

3. **Prioridade dos testes a implementar (por tipo):**

   | Prioridade | Tipo | Onde | O que testar |
   |-----------|------|------|-------------|
   | 🔴 Alta | Unitário | `internal/service/` | Lógica de negócio, validações, casos de erro |
   | 🔴 Alta | Unitário | `internal/domain/` | Entidades, constantes, regras de domínio |
   | 🟡 Média | API HTTP | `internal/handler/api/` | Status codes, body JSON, auth, validação de entrada |
   | 🟡 Média | Integração | `internal/repository/sqlite/` | Queries SQL, migrations, banco real |
   | 🟢 Baixa | E2E Web | `internal/handler/web/` | SPA serving, fallback de rotas |
   | 🟢 Baixa | Regressão | Todo o projeto | `go test -count=1` sem cache |

## Implementação

4. **Criar testes unitários** (se faltando):
   - Usar `testing` stdlib + mocks manuais (sem mock framework)
   - Testar casos de sucesso e erro (entrada inválida, não encontrado, conflito, etc.)
   - Usar `t.Run()` para subtests com nomes descritivos
   - Seguir padrão: `func Test${NomeDoServico}_${Metodo}(t *testing.T)`

   ```go
   func TestUserService_Create(t *testing.T) {
       t.Run("success", func(t *testing.T) {
           // arrange
           // act
           // assert
       })
       t.Run("invalid email", func(t *testing.T) {
           // arrange
           // act
           // assert
       })
       t.Run("duplicate email", func(t *testing.T) {
           // arrange
           // act
           // assert
       })
   }
   ```

5. **Criar testes de API HTTP** (se handlers alterados):
   - Usar `httptest` stdlib
   - Testar: status code, headers CORS, body JSON, validação (validator), auth (token ausente/inválido)

   ```go
   func TestUserHandler_Create(t *testing.T) {
       t.Run("returns 201 on success", func(t *testing.T) { /* ... */ })
       t.Run("returns 400 on invalid body", func(t *testing.T) { /* ... */ })
       t.Run("returns 401 without token", func(t *testing.T) { /* ... */ })
   }
   ```

6. **Criar testes de integração** (se repositories alterados):
   - Usar banco SQLite em memória (`:memory:`)
   - Rodar migrations antes de cada teste
   - Testar CRUD completo + soft delete + listagem

   ```go
   func TestUserRepository_Integration(t *testing.T) {
       db := setupTestDB(t)  // SQLite :memory: + migrations
       repo := NewUserRepository(db)

       t.Run("create and get by id", func(t *testing.T) { /* ... */ })
       t.Run("list returns all non-deleted", func(t *testing.T) { /* ... */ })
       t.Run("soft delete sets deleted_at", func(t *testing.T) { /* ... */ })
   }
   ```

7. **Executar tudo e verificar:**

   ```bash
   go test ./... -count=1 -coverprofile=coverage.out
   go tool cover -func=coverage.out
   ```

8. **Se cobertura do pacote alterado estiver abaixo de 80%**, continuar adicionando testes até atingir.

## Regras

- Código novo SEMPRE vem com testes no mesmo commit — sem exceção
- Testes devem rodar sem falhas: `go test ./... -count=1`
- Cobertura mínima por pacote alterado: **80%**
- Usar `t.Parallel()` em testes independentes
- Nomear testes com clareza: `TestPacote_Funcao_Caso`
- Manter mocks manuais e simples — sem mockgen, sem testify
