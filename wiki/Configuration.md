# Configuration

An `*rbac.Enforcer` is created with `rbac.New(opts...)`. Plain settings live in `rbac.Config`; dependencies are passed as options.

## Config

| Field | Default | Description |
|---|---|---|
| `EmbedRoles` | `true` | Put the user's effective roles (assigned plus inherited) in access tokens. |
| `EmbedPermissions` | `false` | Put the user's effective grants in access tokens. |
| `RolesClaim` | `"roles"` | JWT claim name for roles. |
| `PermissionsClaim` | `"perms"` | JWT claim name for grants. |

Claim names must be non-empty, different from each other and not one of auth's reserved claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `typ`, `fam`).

**Every service must use the same values.** An enforcer only reads the claims it is configured to embed. If the issuing service embeds permissions but a checking service has `EmbedPermissions: false`, the checking service ignores the claim and looks the user up instead.

`Config` has `mapstructure` tags, so it can be loaded with Viper or similar libraries without this package depending on them:

```go
cfg := rbac.DefaultConfig()
if err := v.UnmarshalKey("rbac", &cfg); err != nil { ... }
e, err := rbac.New(rbac.WithConfig(cfg), rbac.WithRoleStore(store), rbac.WithPolicy(p))
```

```yaml
rbac:
  embed_roles: true
  embed_permissions: false
  roles_claim: roles
  permissions_claim: perms
```

## Options

| Option | Description |
|---|---|
| `WithConfig(cfg)` | Replace all `Config` fields. Later options override individual fields. |
| `WithEmbedRoles(bool)` | Set `EmbedRoles`. |
| `WithEmbedPermissions(bool)` | Set `EmbedPermissions`. |
| `WithRolesClaim(name)` | Set `RolesClaim`. |
| `WithPermissionsClaim(name)` | Set `PermissionsClaim`. |
| `WithRoleStore(store)` | Where user → role assignments come from. See [Storage](Storage.md). |
| `WithPolicy(policy)` | A fixed policy. Shorthand for `WithPolicyProvider(StaticPolicy(policy))`. |
| `WithPolicyProvider(p)` | A policy that can change at runtime, for example `NewCachedPolicyProvider`. |
| `WithErrorHandler(h)` | Custom middleware error responses. See [HTTP Middleware](HTTP-Middleware.md). |
| `WithLogger(l)` | `*slog.Logger` for internal errors in middleware. Default `slog.Default()`. |

## What New requires

`New` returns `ErrNotConfigured` if some checks could never be answered:

- **A policy is required unless `EmbedPermissions` is set.** Without permissions in the token, every permission check needs the policy.
- **A `RoleStore` is required unless roles or permissions are embedded.** With nothing in the token, every check needs a lookup.

Other combinations are accepted, since a service may never make the checks they leave unanswerable; those checks fail with `ErrNotConfigured` when called. For example:

- With only permissions embedded and no `RoleStore`, permission checks work but role checks (`HasRole`, `RequireAnyRole`) do not, because the token carries no roles.
- A token missing its claims (issued before they were enabled) can't be checked in a service with no `RoleStore`.

### Typical setups

**Issuing service** (runs auth's login and refresh): always needs a `RoleStore`, and a policy to embed permissions or expand inherited roles.

```go
rbac.New(rbac.WithRoleStore(store), rbac.WithPolicy(policy), rbac.WithEmbedPermissions(true))
```

**Downstream service with permissions embedded**: needs nothing else. It checks tokens it verified via auth's JWKS.

```go
rbac.New(rbac.WithEmbedRoles(true), rbac.WithEmbedPermissions(true))
```

**Downstream service with roles embedded**: needs the policy to turn roles into permissions.

```go
rbac.New(rbac.WithPolicy(policy))
```

**Always-fresh checks**: embed nothing and look everything up.

```go
rbac.New(rbac.WithEmbedRoles(false), rbac.WithRoleStore(store), rbac.WithPolicyProvider(cached))
```
