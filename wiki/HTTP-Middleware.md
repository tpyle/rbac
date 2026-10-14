# HTTP Middleware

The enforcer provides three middleware constructors. Each returns an `rbac.Middleware` (`func(http.Handler) http.Handler`).

| Middleware | Admits the request if the user… |
|---|---|
| `RequireAnyRole(roles...)` | has at least one of the roles (directly or inherited) |
| `RequireAllPermissions(perms...)` | holds every permission |
| `RequireAnyPermission(perms...)` | holds at least one permission |

They panic at construction if given no arguments or an invalid role/permission (for example a wildcard), because that is a programming error. They also panic if the enforcer could never answer them: `RequireAnyRole` without a `RoleStore` or embedded roles, and the permission middleware without a `RoleStore` or any embedded claims. Finding it at startup beats a route that silently allows or denies everyone, or answers every request with a 500.

## Scoped middleware

`RequireAnyRoleOn`, `RequireAllPermissionsOn` and `RequireAnyPermissionOn` check access to the resource a request acts on (see [Scoped Permissions](Scoped-Permissions.md)). Their first argument is an `rbac.ResourceFunc`, `func(*http.Request) (string, error)`, which names the resource. `rbac.PathResource` covers the common case by filling `{name}` placeholders from the request's path values:

```go
doc := rbac.PathResource("projects/{project}/docs/{doc}")
project := rbac.PathResource("projects/{project}")

protected.Handle("GET /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:read")(getDoc))
protected.Handle("PUT /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:write")(putDoc))
protected.Handle("DELETE /projects/{project}", e.RequireAnyRoleOn(project, "owner")(deleteProject))
```

The scoped middleware panics at construction if the enforcer has no `ScopedRoleStore`, and the scoped permission middleware also if it has no policy (only the policy turns bound roles into permissions). Otherwise every user without a global grant would get a 500. `PathResource` panics at construction on unbalanced braces, an empty `{}` or a pattern that couldn't produce a valid resource.

`PathResource` never sees the `ServeMux` pattern, so it can't check that its placeholder names match the route's wildcards. A misspelled name reads an empty path value, and every request gets a 400 that isn't logged (400s are client errors). Use the same names in both patterns, and test each scoped route at least once with a request that should succeed.

At request time, an empty path value or one that makes the resource invalid (whitespace, a `*`, `.` or `..` segment) is rejected with `ErrInvalidScope`, which the default handler answers with 400. The claims are checked first, so an anonymous request still gets 401.

Path values are unescaped: `/projects/42%2Fdocs/docs/1` matches `/projects/{project}/docs/{doc}` with `project` = `42/docs`. Because a `/` inside a value would change which scopes are the resource's ancestors, a `{name}` value containing `/` is rejected. Use `{name...}` in the `PathResource` pattern where a value may span several segments, to match a `ServeMux` `{name...}` wildcard:

```go
mux.Handle("GET /files/{path...}", e.RequireAllPermissionsOn(rbac.PathResource("files/{path...}"), "files:read")(getFile))
```

For resources that aren't in the path, write your own `ResourceFunc`. Return an error wrapping `rbac.ErrInvalidScope` for bad input (400), and any other error for internal failures (500).

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
| Scoped middleware found no valid resource | wraps `ErrInvalidScope` | `400 {"error":"bad_request"}` |
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

Each check resolves access separately. With nothing embedded, every check is a `RoleStore` lookup, and every scoped check that global grants don't answer is a `ScopedRoleStore` lookup, so cache inside your stores if a request makes many checks.

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
