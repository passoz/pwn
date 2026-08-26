---
name: htmx
description: HTMX + Go html/template — atributos reais, padrões corretos, erros comuns. Use ao criar ou modificar qualquer frontend HTMX.
---

# HTMX + Go

## Atributos que EXISTEM (use estes)

`hx-get`, `hx-post`, `hx-put`, `hx-patch`, `hx-delete`, `hx-trigger`, `hx-target`, `hx-swap`, `hx-indicator`, `hx-vals`, `hx-headers`, `hx-request`, `hx-include`, `hx-confirm`, `hx-disable`, `hx-boost`, `hx-push-url`, `hx-preserve`, `hx-disabled-elt`, `hx-on*`

## Atributos que NÃO EXISTEM (NUNCA use)

✗ `hx-modal`, `hx-dialog`, `hx-toast`, `hx-notify`, `hx-redirect`, `hx-reload`, `hx-navigate`, `hx-route`, `hx-validate`, `hx-success`, `hx-error`, `hx-loading`, `hx-form`, `hx-submit`

## hx-swap válidos

`innerHTML` (padrão), `outerHTML`, `beforebegin`, `afterbegin`, `beforeend`, `afterend`, `none`, `delete`

## hx-trigger válidos

`click`, `change`, `load`, `revealed`, `intersect`, `mouseenter`, `mouseleave`, `keydown`, `keyup`, `focus`, `blur`, `submit`

Com modificadores: `click once`, `click delay:500ms`, `change throttle:2s`, `every 5s`, `load delay:100ms`, `intersect threshold:0.5`

## Regras de ouro

1. **Resposta é HTML, nunca JSON** — handlers REST retornam JSON (prefixo `/api/v1/`), handlers web retornam HTML. HTMX só fala com handlers web.
2. **Fragmento, não página** — uma requisição HTMX retorna um pedaço de HTML (ex: `<div id="user-list">...`), nunca um `<html>` completo.
3. **hx-target é obrigatório** quando o destino difere do elemento que disparou.
4. **hx-swap="outerHTML"** quando o próprio elemento deve ser substituído (comum em listas e modais).
5. **Modal usa `<dialog>` nativo** — `hx-get` carrega o conteúdo, `<dialog>` faz o show/close. Não inventar `hx-modal`.
6. **CSRF token** via `hx-headers` no `<body>`: `<body hx-headers='{"X-CSRF-Token":"{{.CSRFToken}}"}'>`
7. **Timeout** sempre: `hx-request='{"timeout":15000}'` + `hx-target-error="#error-msg"`

## Padrões Go + HTMX

### Handler retorna fragmento

```go
func (h *UserHandler) ListFragment(w http.ResponseWriter, r *http.Request) {
    users, err := h.svc.ListUsers(r.Context())
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        h.tmpl.ExecuteTemplate(w, "error_fragment.html", map[string]any{
            "Message": "Erro ao carregar usuários",
        })
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    h.tmpl.ExecuteTemplate(w, "users_list_fragment.html", map[string]any{
        "Users": users,
    })
}
```

### Fragmento de listagem

```html
<div id="user-list">
  {{range .Users}}
  <div class="flex items-center justify-between p-2 bg-white/10 rounded-lg">
    <span>{{.Name}}</span>
    <button hx-delete="/users/{{.ID}}"
            hx-target="#user-list"
            hx-swap="outerHTML"
            hx-confirm="Excluir {{.Name}}?"
            class="text-red-400 hover:text-red-300">
      Excluir
    </button>
  </div>
  {{else}}
  <p class="text-white/60">Nenhum usuário encontrado.</p>
  {{end}}
</div>
```

### Botão carregar conteúdo em modal

```html
<button hx-get="/users/{{.ID}}/edit"
        hx-target="#modal-content"
        hx-swap="innerHTML"
        onclick="document.getElementById('user-modal').showModal()">
  Editar
</button>

<dialog id="user-modal" class="backdrop-blur bg-white/10 rounded-xl p-6">
  <div id="modal-content">
    <!-- Conteúdo carregado via hx-get -->
  </div>
  <button onclick="document.getElementById('user-modal').close()"
          class="mt-4 text-white/60 hover:text-white">
    Fechar
  </button>
</dialog>
```

### Formulário com submit HTMX

```html
<form hx-post="/users"
      hx-target="#user-list"
      hx-swap="outerHTML"
      hx-request='{"timeout":15000}'
      hx-target-error="#form-error">
  <input type="text" name="name" required
         class="w-full p-2 bg-white/10 rounded border border-white/20">
  <button type="submit" class="mt-2 px-4 py-2 bg-blue-500 rounded">
    Salvar
  </button>
  <div id="form-error" class="text-red-400 mt-2"></div>
</form>
```

### Resposta de formulário com erro

```go
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        h.tmpl.ExecuteTemplate(w, "form_error.html", map[string]any{
            "Message": "Dados inválidos",
        })
        return
    }

    user, err := h.svc.CreateUser(r.Context(), r.FormValue("name"))
    if err != nil {
        w.WriteHeader(http.StatusUnprocessableEntity)
        h.tmpl.ExecuteTemplate(w, "form_error.html", map[string]any{
            "Message": err.Error(),
        })
        return
    }

    // Retorna o fragmento atualizado com o novo item
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    h.tmpl.ExecuteTemplate(w, "users_list_fragment.html", map[string]any{
        "Users": []User{user}, // ou recarrega a lista
    })
}
```

## Erros comuns que o modelo comete

| Erro | Correto |
|------|---------|
| `hx-modal="true"` | Usar `<dialog>` nativo + `hx-get` no botão |
| `hx-validate="true"` | Validar no servidor, retornar HTML com erro |
| `hx-redirect="/login"` | Retornar `HX-Redirect: /login` no header da resposta |
| `hx-reload="true"` | Retornar `HX-Refresh: true` no header da resposta |
| `hx-toast` | Usar um `div#toast` com hx-swap e CSS |
| `hx-success` / `hx-error` | Usar `hx-target-error` + retornar status code diferente |
| Retornar JSON em resposta HTMX | Retornar HTML sempre |
| `hx-get` com `hx-swap="innerHTML"` em formulário | `hx-post` em formulário, não `hx-get` |
| Esquecer `hx-target` | Sempre definir `hx-target` se o destino não for o próprio elemento |
