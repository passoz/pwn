---
name: docker-compose
description: Comandos comuns de Docker Compose para projetos Go (único binário). Inclui dev com Air/Delve e prod multi-stage.
---

# Docker Compose

## Dev

```bash
# Subir o servidor com hot reload
docker compose up -d

# Ver logs
docker compose logs -f server

# Rodar migrate dentro do container
docker compose exec server migrate -path /app/db/migrations up

# Debug com Delve (porta 2345 exposta)
docker compose exec server dlv connect :2345

# Reconstruir sem cache
docker compose build --no-cache server

# Parar tudo
docker compose down
```

## Prod

```bash
# Build da imagem
docker compose -f docker-compose.prod.yml build

# Subir em produção
docker compose -f docker-compose.prod.yml up -d

# Verificar health
curl http://localhost:3000/healthz
curl http://localhost:3000/readyz
```

## Estrutura esperada

```yaml
services:
  server:   # Go único binário com Air (dev) ou binário (prod)
```

## DB

```bash
# Rodar migrations
docker compose exec server migrate -path /app/db/migrations up

# Reverter última migration
docker compose exec server migrate -path /app/db/migrations down 1

# Gerar queries sqlc
docker compose exec server sqlc generate
```
