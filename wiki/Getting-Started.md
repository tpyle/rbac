# Getting Started

## Install

```bash
go get github.com/tpyle/rbac
go get github.com/tpyle/rbac/authrbac # to use it with github.com/tpyle/auth/v2
```

`rbac` requires Go 1.26 or later. This guide uses [`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth) for authentication; to use another library, see [Connecting Authentication](Authentication.md).

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
	authrbac.Option(), // read the claims auth verifies
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

auth calls the claims provider on every login and refresh. If you already have one, pass it in and its claims are kept:

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
ok, err := enforcer.ClaimsCanAll(ctx, authrbac.Claims(claims), "posts:read")

ok, err = enforcer.SubjectCan(ctx, "alice", "posts:read") // ignores tokens
```

## Next steps

- Run [`authrbac/examples/basic`](../authrbac/examples/basic), [`authrbac/examples/server`](../authrbac/examples/server) and [`authrbac/examples/scoped`](../authrbac/examples/scoped) (from the `authrbac` directory), or the auth-free [`examples/basic`](../examples/basic) and [`examples/middleware`](../examples/middleware).
- Read [HTTP Middleware](HTTP-Middleware.md) and [Error Handling](Error-Handling.md).
- To grant roles on individual resources ("editor of project 42"), read [Scoped Permissions](Scoped-Permissions.md).
