# Getting Started

## Install

```bash
go get github.com/tpyle/rbac
```

`rbac` requires Go 1.26 or later and `github.com/tpyle/auth/v2`.

## 1. Define a policy

In code:

```go
policy, err := rbac.NewPolicy(map[string]rbac.RoleDefinition{
	"viewer": {Permissions: []string{"posts:read"}},
	"editor": {Inherits: []string{"viewer"}, Permissions: []string{"posts:*"}},
	"admin":  {Inherits: []string{"editor"}, Permissions: []string{"users:*"}},
})
```

Or from a file (see [Policies](Policies.md)):

```go
f, _ := os.Open("policy.yaml")
defer f.Close()
policy, err := rbacyaml.LoadPolicy(f)
```

## 2. Tell rbac where user roles live

Implement `rbac.RoleStore` on your database (see [Storage](Storage.md)), or use the in-memory store while prototyping:

```go
roles := rbac.NewMemoryRoleStore()
roles.SetRoles("alice", "editor")
```

## 3. Create the enforcer

```go
enforcer, err := rbac.New(
	rbac.WithRoleStore(roles),
	rbac.WithPolicy(policy),
	rbac.WithEmbedRoles(true),
	rbac.WithEmbedPermissions(false),
)
```

What you embed is a trade-off between speed and freshness; see [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md).

## 4. Connect it to auth

```go
a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithRefreshTokenStore(refreshTokens),
	auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
)
```

If you already have a claims provider, pass it in and its claims are kept:

```go
auth.WithClaimsProvider(enforcer.ClaimsProvider(myClaimsProvider))
```

## 5. Check access

With middleware, mounted inside auth's middleware:

```go
mux := http.NewServeMux()
mux.Handle("POST /posts", enforcer.RequireAllPermissions("posts:create")(createPost))
mux.Handle("GET /admin", enforcer.RequireAnyRole("admin")(adminPage))
handler := a.RequireAuthHandler(mux)
```

Or inside handlers, for finer decisions:

```go
func editPost(w http.ResponseWriter, r *http.Request) {
	ok, err := enforcer.Can(r.Context(), "posts:edit")
	if err != nil { /* 500 */ }
	if !ok && !isAuthor(r) { /* 403 */ }
	// ...
}
```

Outside HTTP, check claims you verified yourself, or a user directly:

```go
claims, err := a.VerifyAccessToken(ctx, token)
ok, err := enforcer.ClaimsCanAll(ctx, claims, "posts:read")

ok, err = enforcer.SubjectCan(ctx, "alice", "posts:read") // ignores tokens
```

## Next steps

- Run [`examples/basic`](../examples/basic), [`examples/server`](../examples/server) and [`examples/scoped`](../examples/scoped).
- Read [HTTP Middleware](HTTP-Middleware.md) and [Error Handling](Error-Handling.md).
- To grant roles on individual resources ("editor of project 42"), read [Scoped Permissions](Scoped-Permissions.md).
