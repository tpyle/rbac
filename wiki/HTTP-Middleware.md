# HTTP Middleware

The enforcer provides three middleware constructors. Each returns an `rbac.Middleware` (`func(http.Handler) http.Handler`).

| Middleware | Admits the request if the user… |
|---|---|
| `RequireAnyRole(roles...)` | has at least one of the roles (directly or inherited) |
| `RequireAllPermissions(perms...)` | holds every permission |
| `RequireAnyPermission(perms...)` | holds at least one permission |

They panic at construction if given no arguments or an invalid role/permission (for example a wildcard), because that is a programming error. Finding it at startup beats a route that silently allows or denies everyone.

## Ordering

rbac reads the claims that auth's middleware puts in the request context. **Mount rbac inside `RequireAuthHandler` (or `AuthHandler`).**

```go
protected := http.NewServeMux()
protected.Handle("GET /posts", e.RequireAllPermissions("posts:read")(listPosts))
protected.Handle("DELETE /posts/{id}", e.RequireAllPermissions("posts:delete")(deletePost))
protected.Handle("GET /admin/", e.RequireAnyRole("admin")(adminUI))

mux := http.NewServeMux()
mux.HandleFunc("POST /login", login)            // public
mux.Handle("/", a.RequireAuthHandler(protected)) // everything else
```

Middleware can be stacked; the outermost runs first:

```go
h := e.RequireAnyRole("staff")(e.RequireAllPermissions("billing:refund")(refund))
```

## Responses

| Situation | Error passed to the handler | Default response |
|---|---|---|
| No claims in context (not authenticated) | wraps `ErrNoClaims` | `401 {"error":"unauthorized"}` with `WWW-Authenticate: Bearer` |
| Authenticated but lacking access | wraps `ErrForbidden` | `403 {"error":"forbidden"}` |
| Anything else (store down, malformed claim, ...) | the error | `500 {"error":"internal_error"}`, logged |

Error details are never sent to the client.

### Custom responses

```go
rbac.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rbac.ErrNoClaims):
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.Is(err, rbac.ErrForbidden):
		renderTemplate(w, "forbidden.html")
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
})
```

Internal errors are logged at error level with the configured `slog.Logger` before the handler is called. A check abandoned because the client disconnected (the request context was cancelled) is logged at debug level instead, so ordinary disconnects don't trigger error alerts; the handler is still called, though the client won't see the response. Deadline errors are still logged as errors, since they usually mean a slow store.

## Checks inside handlers

Middleware covers whole routes. For decisions that depend on the request (ownership, optional features), call the checks directly:

```go
func updatePost(w http.ResponseWriter, r *http.Request) {
	post := loadPost(r.PathValue("id"))
	sub, _ := auth.SubjectFromContext(r.Context())
	canEditAny, err := e.Can(r.Context(), "posts:edit:any")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if post.Author != sub && !canEditAny {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ...
}
```

Each check resolves access separately. With nothing embedded, every check is a `RoleStore` lookup, so cache inside your `RoleStore` if a request makes many checks.

## Testing handlers

Use `auth.ContextWithClaims` to put claims in a request without a real token:

```go
ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{
	Subject: "alice",
	Extra:   map[string]any{"roles": []any{"editor"}},
})
r := httptest.NewRequestWithContext(ctx, "GET", "/posts", nil)
```

auth's own middleware discards claims set this way and verifies the request's token, so they only reach rbac when its middleware is used without auth's in front of it, as in a unit test.
