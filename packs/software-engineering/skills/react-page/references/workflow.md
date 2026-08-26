---
description: Cria uma nova página/rota no React SPA (usar só quando modal não fizer sentido)
argument-hint: "[-h | nome] [rota]"
---

## AJUDA (`-h`)

Se `$@`, sem espaços externos, for exatamente `-h` ou `--help`, responda somente com o bloco abaixo e encerre sem alterar o frontend:

```text
Uso: /page NOME [ROTA]

Formas:
  /page reports /reports   Cria a página reports na rota informada.
  /page reports            Usa a rota derivada /reports.
  /page -h                 Exibe esta ajuda sem criar página.
```

Cria uma nova página React para **$1**.

## Rota no React

1. Adicionar rota em `frontend/src/App.tsx`:
   ```tsx
   <Route path="${2:-/$1}" element={<${1^}Page />} />
   ```

## Página React

2. Criar `frontend/src/pages/${1^}Page.tsx`:
   - Layout glassmorphism (backdrop-blur, bg-white/10, border-white/20)
   - Loading state com spinner/placeholder enquanto carrega dados
   - Empty state quando não há dados
   - Error state com botão de retry
   - Modais para formulários e detalhes em vez de navegar para sub-rotas

## Handler no servidor (se necessário)

3. Criar handler em `internal/handler/web/${1}_handler.go` que serve dados:
   - Chama os services internos (`internal/service/`)
   - Retorna JSON (não HTML) — quem renderiza é o React

## Service de API no frontend

4. Criar `frontend/src/services/${1}s.ts` com as chamadas fetch para `/api/v1/${1}s`

Stack padrão: Go net/http, React + TypeScript + Vite, glassmorphism.
