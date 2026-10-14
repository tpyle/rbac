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
  grants can use `*` for one segment and `**` for any number (`posts:*`,
  `posts:**`, `**:read`, `**`).
- **Scoped permissions**: bind a role on one resource or a group of resources
  (`editor` of `projects/42`, `auditor` of `projects/*/docs`) and check it with
  `CanOn` / `HasRoleOn` or scoped middleware. Bindings are looked up, never
  embedded, so they apply immediately and don't grow tokens.
- **Your choice of token contents**: embed roles, permissions, both or
  neither. Checks use the token's claims when present and fall back to your
  database otherwise, so every combination works.
- **Hooks for your storage**: implement `RoleStore` (user → roles),
  optionally `ScopedRoleStore` (user → roles on resources) and
  `PolicyProvider` (role → permissions) on your database. In-memory and cached
  implementations are included.
- **Policy files**: JSON with the standard library, YAML through the
  `rbacyaml` subpackage.
- **HTTP middleware**: `RequireAnyRole`, `RequireAllPermissions`,
  `RequireAnyPermission` and their scoped `...On` variants, with 401/403 JSON
  responses.

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

// Scoped: add rbac.WithScopedRoleStore(myBindings) to rbac.New, then
doc := rbac.PathResource("projects/{project}/docs/{doc}")
mux.Handle("PUT /projects/{project}/docs/{doc}", enforcer.RequireAllPermissionsOn(doc, "docs:write")(putDoc))
ok, err = enforcer.CanOn(r.Context(), "projects/42/docs/7", "docs:write")
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
- [`examples/scoped`](examples/scoped): roles bound on projects and documents, including wildcard scopes (`go run ./examples/scoped`).

## Documentation

- [Getting Started](wiki/Getting-Started.md)
- [Policies](wiki/Policies.md): roles, inheritance, wildcards, policy files
- [Configuration](wiki/Configuration.md)
- [Scoped Permissions](wiki/Scoped-Permissions.md): roles on resources, scope patterns, resolvers
- [Token Claims and Trade-offs](wiki/Token-Claims-and-Tradeoffs.md)
- [Storage](wiki/Storage.md): `RoleStore`, `ScopedRoleStore`, `PolicyProvider`, schemas
- [HTTP Middleware](wiki/HTTP-Middleware.md)
- [Error Handling](wiki/Error-Handling.md)

API reference: [pkg.go.dev/github.com/tpyle/rbac](https://pkg.go.dev/github.com/tpyle/rbac)

## License

MIT
