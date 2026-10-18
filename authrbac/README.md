# authrbac

Connects [`github.com/tpyle/rbac`](..) to
[`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth). It is its own
module so that rbac doesn't depend on auth.

```bash
go get github.com/tpyle/rbac/authrbac
```

```go
enforcer, err := rbac.New(
	authrbac.Option(), // read auth's verified claims, reject auth's reserved claim names
	rbac.WithRoleStore(roles),
	rbac.WithPolicy(policy),
)

a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)), // embed roles in tokens
)

mux := http.NewServeMux()
mux.Handle("DELETE /posts/{id}", enforcer.RequireAllPermissions("posts:delete")(deletePost))
http.ListenAndServe(":8080", a.RequireAuthHandler(mux))

// Claims verified outside a request:
claims, err := a.VerifyAccessToken(ctx, token)
ok, err := enforcer.ClaimsCanAll(ctx, authrbac.Claims(claims), "posts:read")
```

Examples: [`examples/basic`](examples/basic), [`examples/server`](examples/server)
and [`examples/scoped`](examples/scoped), run from this directory
(`go run ./examples/server`). See also
[Connecting Authentication](../wiki/Authentication.md).
