# rbac

`github.com/tpyle/rbac` adds role-based access control to services that authenticate users with signed tokens such as JWTs. It decides what an authenticated user may do; your authentication library decides who they are. rbac works with any such library, and the separate `github.com/tpyle/rbac/authrbac` module connects it to [`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth).

```go
import "github.com/tpyle/rbac"
```

## Concepts

- A **permission** is a colon-separated string such as `posts:write` or `posts:comments:delete`.
- A **grant** is a permission a role holds. Grants may use wildcard segments: `*` matches one segment (`posts:*` covers `posts:read`) and `**` matches any number (`posts:**` covers `posts:comments:delete`).
- A **role** holds grants and can inherit other roles. An `admin` that inherits `editor` is also an `editor`.
- A **policy** is the set of role definitions.
- A **role store** says which roles each user has globally. It is usually a database table.
- A **binding** grants a role on one resource or a group of resources, such as `editor` of `projects/42`. A **scoped role store** holds bindings.
- The **enforcer** ties these together: it embeds claims in tokens and answers checks.

## Pages

| Page | Contents |
|---|---|
| [Getting Started](Getting-Started.md) | Install, define a policy, connect to auth, protect routes |
| [Connecting Authentication](Authentication.md) | Using rbac with `github.com/tpyle/auth/v2` or any other token library |
| [Policies](Policies.md) | Permission syntax, wildcards, exceptions, inheritance, JSON and YAML files |
| [Configuration](Configuration.md) | Every `Config` field and option, and what `New` requires |
| [Scoped Permissions](Scoped-Permissions.md) | Roles on individual resources and groups of resources, scope patterns, resolvers, bindings-only services |
| [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md) | What to embed, how checks are resolved, staleness, token size |
| [Storage](Storage.md) | `RoleStore`, `ScopedRoleStore` and `PolicyProvider`, SQL examples, caching |
| [HTTP Middleware](HTTP-Middleware.md) | `RequireAnyRole`, `RequireAllPermissions`, `RequireAnyPermission`, their scoped variants, custom error responses |
| [Error Handling](Error-Handling.md) | Every sentinel error and what to do with it |
