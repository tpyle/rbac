# rbac

Role-based access control for Go services authenticated with
[`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth). Define roles and
permissions, optionally embed them in access tokens, and check them with
`HasRole`, `Can` or `net/http` middleware.

```bash
go get github.com/tpyle/rbac
```

## Features

- **Policies**: roles hold permission grants and can inherit other roles.
  Inheritance cycles and references to undefined roles are rejected up front.
- **Wildcards**: permissions are colon-separated (`posts:comments:delete`);
  grants can use `*` segments (`posts:*`, `*:read`, `*`).
- **Your choice of token contents**: embed roles, permissions, both or
  neither. Checks use the token's claims when present and fall back to your
  database otherwise, so every combination works.
- **Hooks for your storage**: implement `RoleStore` (user → roles) and
  optionally `PolicyProvider` (role → permissions) on your database. In-memory
  and cached implementations are included.
- **Policy files**: JSON with the standard library, YAML through the
  `rbacyaml` subpackage.
- **HTTP middleware**: `RequireAnyRole`, `RequireAllPermissions` and
  `RequireAnyPermission`, with 401/403 JSON responses.

## Quick start

```go
policy, err := rbacyaml.LoadPolicy(f) // or rbac.ParsePolicyJSON / rbac.NewPolicy

enforcer, err := rbac.New(
	rbac.WithRoleStore(myRoleStore),  // reads user → roles from your database
	rbac.WithPolicy(policy),
	rbac.WithEmbedRoles(true),        // put roles in the token
	rbac.WithEmbedPermissions(false), // resolve permissions from roles instead
)

a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)), // embeds the claims
)

mux := http.NewServeMux()
mux.Handle("DELETE /posts/{id}", enforcer.RequireAllPermissions("posts:delete")(deletePost))
mux.Handle("GET /admin", enforcer.RequireAnyRole("admin")(adminPage))
http.ListenAndServe(":8080", a.RequireAuthHandler(mux)) // auth runs first

// Or check inside a handler:
ok, err := enforcer.Can(r.Context(), "posts:publish")
```

```yaml
roles:
  viewer: { permissions: ["posts:read"] }
  editor: { inherits: [viewer], permissions: ["posts:*"] }
  admin:  { inherits: [editor], permissions: ["users:*"] }
```

## How checks are answered

| Configuration | `HasRole` | `Can` |
|---|---|---|
| nothing embedded | `RoleStore` + policy | `RoleStore` + policy |
| roles (default) | token (+ policy, if configured) | token roles + policy |
| permissions | `RoleStore` + policy | token |
| both | token (+ policy, if configured) | token |

If a token lacks an enabled claim (for example it was issued before the claim
was enabled), the check falls back to the `RoleStore`. Embedded claims are
refreshed whenever auth refreshes the access token, so they can be up to one
access-token lifetime out of date. See
[Token Claims and Trade-offs](wiki/Token-Claims-and-Tradeoffs.md).

## Examples

- [`examples/basic`](examples/basic): issue a token and check it, no HTTP (`go run ./examples/basic`).
- [`examples/server`](examples/server): a JSON API with role- and permission-protected routes, using [`examples/server/policy.yaml`](examples/server/policy.yaml).

## Documentation

- [Getting Started](wiki/Getting-Started.md)
- [Policies](wiki/Policies.md): roles, inheritance, wildcards, policy files
- [Configuration](wiki/Configuration.md)
- [Token Claims and Trade-offs](wiki/Token-Claims-and-Tradeoffs.md)
- [Storage](wiki/Storage.md): `RoleStore`, `PolicyProvider`, schemas
- [HTTP Middleware](wiki/HTTP-Middleware.md)
- [Error Handling](wiki/Error-Handling.md)

API reference: [pkg.go.dev/github.com/tpyle/rbac](https://pkg.go.dev/github.com/tpyle/rbac)

## License

MIT
