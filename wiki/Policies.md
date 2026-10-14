# Policies

A `*rbac.Policy` maps roles to permission grants. It is validated when built, immutable afterwards, and safe to share between goroutines.

## Permissions

A permission is one or more non-empty segments separated by `:`, with no whitespace:

```
posts
posts:read
posts:comments:delete
```

The meaning of segments is up to you. A common convention is `resource:action` or `resource:sub-resource:action`.

Permissions you **check** (`Can("posts:read")`) must be concrete: no wildcards. Checking for `posts:*` returns `ErrInvalidPermission`.

## Wildcard grants

Permissions a role **holds** may use two wildcards, each as a whole segment and in any position:

| Segment | Matches |
|---|---|
| `*` | exactly one segment |
| `**` | zero or more segments |

| Grant | Matches | Does not match |
|---|---|---|
| `posts:*` | `posts:read`, `posts:delete` | `posts`, `posts:comments:delete`, `users:read` |
| `posts:**` | `posts`, `posts:read`, `posts:comments:delete` | `users:read` |
| `*:read` | `posts:read`, `users:read` | `read`, `posts:drafts:read` |
| `**:read` | `read`, `posts:read`, `posts:drafts:read` | `posts:read:own` |
| `posts:*:read` | `posts:drafts:read` | `posts:read`, `posts:a:b:read` |
| `posts:**:read` | `posts:read`, `posts:a:b:read` | `posts:write` |
| `*` | `posts`, `users` (any single segment) | `posts:read` |
| `**` | everything | |

Use `posts:*` for "every action on posts" when your permissions are `resource:action`, and `posts:**` when they nest deeper. The superuser grant is `**`. Partial wildcards such as `post*` and two `**` segments in a row are invalid.

The same rules apply to scope patterns in [scoped bindings](Scoped-Permissions.md#scope-patterns), with `/` as the separator.

`rbac.Grants(grant, perm)` exposes the matching rule, and `rbac.ValidatePermission` / `rbac.ValidateGrant` check syntax.

## Roles and inheritance

```go
policy, err := rbac.NewPolicy(map[string]rbac.RoleDefinition{
	"viewer":  {Permissions: []string{"posts:read"}},
	"author":  {Inherits: []string{"viewer"}, Permissions: []string{"posts:create"}},
	"editor":  {Inherits: []string{"author"}, Permissions: []string{"posts:*"}},
	"auditor": {Permissions: []string{"*:audit"}},
	"admin":   {Inherits: []string{"editor", "auditor"}, Permissions: []string{"users:*"}},
})
```

A role has its own grants plus those of every role it inherits, transitively. Inheritance is also visible to role checks: an `admin` passes `HasRole(ctx, "viewer")`.

`NewPolicy` rejects:

- empty role names or names containing whitespace (`ErrInvalidRole`);
- invalid grants (`ErrInvalidPermission`);
- inheriting a role that is not defined (`ErrUnknownRole`);
- inheritance cycles (`ErrRoleCycle`), with the cycle in the message, such as `a -> b -> a`.

Users may be assigned roles the policy does not define. Those roles grant no permissions, but `HasRole` still sees them, which is handy for flags such as `beta-tester`.

### Inspecting a policy

```go
policy.Roles()                        // [admin auditor author editor viewer]
policy.EffectiveRoles("editor")       // [author editor viewer]
policy.Permissions("editor")          // [posts:* posts:create posts:read]
policy.Can([]string{"editor"}, "posts:delete") // true, nil
policy.Definitions()                  // copy of the input
```

## Policy files

JSON is supported by the core package, YAML by the `rbacyaml` subpackage (kept separate so the core does not compile a YAML parser). Both use the same structure, `rbac.PolicyFile`:

```yaml
roles:
  viewer:
    permissions: ["posts:read"]
  editor:
    inherits: [viewer]
    permissions: ["posts:*"]
```

```json
{
  "roles": {
    "viewer": {"permissions": ["posts:read"]},
    "editor": {"inherits": ["viewer"], "permissions": ["posts:*"]}
  }
}
```

```go
p, err := rbac.ParsePolicyJSON(data)     // or rbac.LoadPolicyJSON(r)
p, err := rbacyaml.ParsePolicy(data)     // or rbacyaml.LoadPolicy(r)
```

Decoding is strict: unknown fields (for example a misspelled `permisions`), trailing data, extra YAML documents (other than empty ones, such as a trailing `---`; an explicit `null` document counts as data) and a missing `roles` key return `ErrInvalidPolicy`, so mistakes and empty or truncated files don't silently remove permissions. A policy with no roles must say so explicitly with `"roles": {}`.

To load a policy from a database instead, see [Storage](Storage.md#policies-in-a-database).
