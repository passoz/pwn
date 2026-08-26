---
description: Gera setup Docker completo (único binário), buildando binário no host para rapidez
argument-hint: "[-h | nome-do-projeto]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem alterar o projeto:

```text
Uso: /docker [NOME_DO_PROJETO]

Formas:
  /docker minha-app    Gera o setup Docker para o nome informado.
  /docker              Usa o projeto atual e o nome detectado.
  /docker -h           Exibe esta ajuda sem criar arquivos.
```

Gera a estrutura Docker para o projeto ${1:-projeto}.

> ⚠️ **Lesson learned:** Docker build multi-stage compilando Go dentro do container é **muito lento** (>2min) e frequentemente timeouta. A abordagem correta é compilar o binário **na máquina host** (segundos) e só empacotar em imagem leve.

> ⚠️ **CGO/SQLite:** Se usar `mattn/go-sqlite3` (CGO), o binário linka com glibc e **NÃO funciona em Alpine** (musl). Use **Debian** como base. Alternativa: usar `modernc.org/sqlite` (pure Go, sem CGO) que funciona em qualquer imagem.

## 1. Dockerfile

```dockerfile
# Imagem leve (base Debian para compatibilidade glibc com CGO)
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY bin/server /bin/server
EXPOSE 3000
CMD ["/bin/server"]
```

> ⚠️ O frontend React já está embutido no binário via `//go:embed`. Basta copiar o binário.

## 2. docker-compose.yml (dev)

```yaml
services:
  server:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    volumes:
      - data:/data
    environment:
      - DATABASE_PATH=/data/app.db
      - JWT_SECRET=dev-secret
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/healthz"]
      interval: 10s

volumes:
  data:
```

## 3. docker-compose.test.yml

```yaml
services:
  server-test:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "9080:3000"
    environment:
      - DATABASE_PATH=/tmp/app_test.db
      - JWT_SECRET=test-secret
      - TEST_MODE=true

  e2e:
    image: golang:1.26-bookworm
    working_dir: /app
    volumes:
      - .:/app
    command: go test -run E2E ./internal/handler/web/... -v
    depends_on:
      - server-test
```

## 4. docker-compose.prod.yml

```yaml
services:
  server:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    volumes:
      - data:/data
    environment:
      - DATABASE_PATH=/data/app.db
      - JWT_SECRET=${JWT_SECRET}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/healthz"]
      interval: 30s

volumes:
  data:
```

## 5. Makefile (target docker-up)

```makefile
# Build rápido: compila frontend + binário no host (segundos) e só empacota em imagem leve
docker-up:
	@echo "=== Build rápido Docker ==="
	@echo "Instalando dependências do frontend..."
	@cd frontend && npm install
	@echo "Build do React..."
	@cd frontend && npm run build
	@echo "Compilando binário Go (host)..."
	@mkdir -p bin
	CGO_ENABLED=1 go build -o bin/server ./cmd/server
	@echo "Empacotando imagem Docker (0.1s)..."
	docker build -t projeto-server -f Dockerfile .
	@echo "Subindo container..."
	docker compose up -d
	@sleep 2
	@echo "App: http://localhost:3000"
```

## 6. .dockerignore

```
.git/
.gitignore
*.md
data/
tmp/
frontend/node_modules/
frontend/src/
.env
.env.example
**/*.log
Makefile
README.md
```

> ⚠️ **Importante:** NÃO colocar `bin/` nem `frontend/dist/` no `.dockerignore` — o binário e o build do React são necessários.

## 7. .air.server.toml

```toml
root = "."
testdata_dir = "."
tmp_dir = "tmp"

[build]
cmd = "go build -o ./tmp/server ./cmd/server"
bin = "tmp/server"
delay = 1000
exclude_dir = ["bin", "tmp", "vendor"]
include_ext = ["go", "tpl", "tmpl", "html"]
exclude_regex = ["_test.go"]
```

## Observações sobre CGO

- Se usar **`mattn/go-sqlite3`** (padrão): requer `CGO_ENABLED=1` e imagem **Debian** (glibc)
- Se usar **`modernc.org/sqlite`**: `CGO_ENABLED=0` funciona, imagem **Alpine** funciona
- A escolha é do projeto, mas o template assume `mattn/go-sqlite3` com Debian por ser o mais comum

## Separação futura (se um dia quiser dividir em API + frontend separados)

A arquitetura interna já está preparada: `internal/handler/api/` e `internal/handler/web/` podem virar entrypoints separados (`cmd/backend/` + `cmd/bff/`), cada um com seu Dockerfile e suas portas. Os services e repositories em `internal/` são compartilhados — sem duplicação de código.

Criar todos os arquivos na raiz do projeto.