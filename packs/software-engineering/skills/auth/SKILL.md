---
name: auth
description: Referência do sistema de autenticação — interfaces, endpoints, JWT, como criar adapter OAuth2.
---

# Autenticação

## Arquitetura

```
internal/
├── domain/
│   └── auth.go                # Interface AuthService + tipos
├── auth/
│   └── local/                 # Implementação padrão (email + bcrypt + JWT)
│       ├── service.go
│       ├── service_test.go
│       └── ...
└── handler/
    └── api/
        └── auth_handler.go    # Rotas de auth REST (/api/v1/auth/*)
```

## Interface (domínio)

```go
// internal/domain/auth.go
type AuthService interface {
    Authenticate(ctx context.Context, email, password string) (*AuthUser, error)
    ValidateToken(ctx context.Context, token string) (*AuthUser, error)
    RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
    RevokeToken(ctx context.Context, token string) error
}

type AuthUser struct {
    ID          string
    Email       string
    Name        string
    Roles       []string
    Permissions []string
}

type TokenPair struct {
    AccessToken  string
    RefreshToken string
    ExpiresAt    time.Time
}
```

## Endpoints

```
POST /api/v1/auth/register    # email + password → TokenPair
POST /api/v1/auth/login       # email + password → TokenPair
POST /api/v1/auth/refresh     # refresh_token → TokenPair
POST /api/v1/auth/logout      # revoga token
GET  /api/v1/auth/me          # usuário atual (token válido)
```

## JWT

- Access token: 15 minutos
- Refresh token: 7 dias
- Claims: `sub` (user ID), `exp`, `iat`, `jti` (UUID v4)
- Assinatura: HMAC-SHA256 com secret do `.env`
- Lib: `github.com/golang-jwt/jwt/v5`

## bcrypt

- Custo: 12
- Hash gerado no register, comparado no login
- Lib: `golang.org/x/crypto/bcrypt`

## Middleware

```go
// internal/middleware/auth.go
func Auth(authService domain.AuthService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := extractBearerToken(r)
            user, err := authService.ValidateToken(r.Context(), token)
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            ctx := context.WithValue(r.Context(), userKey, user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## Como adicionar em novas rotas

```go
mux.Handle("POST /api/v1/${1}s", middleware.Auth(authSvc)(handler.Create))
// Ou pública:
mux.Handle("GET /api/v1/healthz", health.Liveness)
```

## Adapter OAuth2 (futuro)

```go
// internal/auth/oauth2/service.go
type OAuth2Service struct {
    providers map[string]Provider
}

type Provider interface {
    AuthURL(state string) string
    Exchange(ctx context.Context, code string) (*TokenPair, error)
    ValidateToken(ctx context.Context, token string) (*AuthUser, error)
}

// Só implementar a interface e injetar no lugar do auth local
```

## Rotas públicas vs protegidas

| Rota | Auth |
|------|------|
| `POST /api/v1/auth/register` | ❌ Pública |
| `POST /api/v1/auth/login` | ❌ Pública |
| `POST /api/v1/auth/refresh` | ❌ Pública |
| `GET /api/v1/healthz` | ❌ Pública |
| `GET /api/v1/readyz` | ❌ Pública |
| `GET /api/v1/auth/me` | ✅ Protegida |
| `POST /api/v1/auth/logout` | ✅ Protegida |
| `GET /api/v1/**` | ✅ Protegida (exceto auth) |
| `POST /api/v1/**` | ✅ Protegida |
| `PUT /api/v1/**` | ✅ Protegida |
| `DELETE /api/v1/**` | ✅ Protegida |
