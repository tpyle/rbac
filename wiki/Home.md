# rbac

`github.com/tpyle/rbac` adds role-based access control to services that authenticate with [`github.com/tpyle/auth/v2`](https://github.com/tpyle/auth). It decides what an authenticated user may do; `auth` decides who they are.

```go
import "github.com/tpyle/rbac"
```

## Concepts

- A **permission** is a colon-separated string such as `posts:write` or `posts:comments:delete`.
- A **grant** is a permission a role holds. Grants may use `*` segments: `posts:*` covers every `posts:` permission.
- A **role** holds grants and can inherit other roles. An `admin` that inherits `editor` is also an `editor`.
- A **policy** is the set of role definitions.
- A **role store** says which roles each user has. It is usually a database table.
- The **enforcer** ties these together: it embeds claims in tokens and answers checks.

## Pages

| Page | Contents |
|---|---|
| [Getting Started](Getting-Started.md) | Install, define a policy, connect to auth, protect routes |
| [Policies](Policies.md) | Permission syntax, wildcards, inheritance, JSON and YAML files |
| [Configuration](Configuration.md) | Every `Config` field and option, and what `New` requires |
| [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md) | What to embed, how checks are resolved, staleness, token size |
| [Storage](Storage.md) | `RoleStore` and `PolicyProvider`, SQL examples, caching |
| [HTTP Middleware](HTTP-Middleware.md) | `RequireAnyRole`, `RequireAllPermissions`, `RequireAnyPermission`, custom error responses |
| [Error Handling](Error-Handling.md) | Every sentinel error and what to do with it |
