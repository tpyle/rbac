# Scoped Permissions

Global roles apply everywhere: an `editor` can edit every post. Scoped permissions grant a role on **one resource or a group of resources**: "bob is an `editor` of project 42", "carol is a `viewer` of document 7", "dave is an `auditor` of every project's documents".

Scoped checks use the same policy (role definitions, inheritance, wildcard grants) as global checks. Only *where* a role applies changes.

## Concepts

- A **resource** is a concrete name such as `projects/42/docs/7`. It is split into segments on `/`, has no whitespace, empty segments, `.` or `..` segments, and contains no wildcards. Checks are always about a resource.
- A **binding** grants a role to a user on a **scope pattern**: `(bob, projects/42, editor)`.
- A **scope resolver** lists the scopes that apply to a resource: the resource itself plus the groups it belongs to. The default, `rbac.PathScopes()`, lists the resource and its ancestors, so a binding on a scope covers everything beneath it.
- A **scoped role store** returns a user's bindings. It is usually a database table.

A user's grants on a resource are their **global** grants (from the token or `RoleStore`, exactly as for `Can`) **plus** the grants of every role bound to them on a scope that applies to the resource.

## Scope patterns

Bindings may use the same wildcards as permission grants, as whole segments:

| Segment | Matches |
|---|---|
| `literal` | that exact segment |
| `*` | exactly one segment |
| `**` | zero or more segments |

A pattern matches a *scope*, not that scope's descendants. Descendants are covered because `PathScopes` lists every ancestor of the resource as a scope. Bindings and the resources they cover:

| Binding scope | Covers | Does not cover |
|---|---|---|
| `projects/42` | `projects/42`, `projects/42/docs/7` | `projects/43`, `projects` |
| `projects/42/docs/7` | `projects/42/docs/7`, `projects/42/docs/7/comments/1` | `projects/42/docs/8` |
| `projects/*` | every project and everything in it | `projects`, `users/1` |
| `projects/*/docs` | `projects/42/docs`, `projects/43/docs/1` | `projects/42`, `projects/42/settings` |
| `projects/**/secret` | `projects/secret`, `projects/42/a/b/secret/x` | `projects/42/secrets` |
| `**` | everything | |

`rbac.MatchScope(pattern, scope)` exposes the matching rule, and `rbac.ValidateScope` / `rbac.ValidateScopePattern` check syntax. Two `**` segments in a row and partial wildcards such as `proj*` are invalid.

## Setting up

```go
e, err := rbac.New(
	rbac.WithPolicy(policy),
	rbac.WithRoleStore(roles),         // global roles, as before
	rbac.WithScopedRoleStore(bindings), // scoped roles
	// rbac.WithScopeResolver(...)      // optional; default rbac.PathScopes()
)
```

See [Storage](Storage.md#scopedrolestore) for implementing `ScopedRoleStore` on a database.

## Checking

Every global check has a scoped counterpart that takes a resource:

| Global | Scoped |
|---|---|
| `HasRole(ctx, role)` | `HasRoleOn(ctx, resource, role)` |
| `HasAnyRole(ctx, roles...)` | `HasAnyRoleOn(ctx, resource, roles...)` |
| `Can(ctx, perm)` | `CanOn(ctx, resource, perm)` |
| `CanAll(ctx, perms...)` | `CanAllOn(ctx, resource, perms...)` |
| `CanAny(ctx, perms...)` | `CanAnyOn(ctx, resource, perms...)` |
| `ClaimsHaveAnyRole`, `ClaimsCanAll`, `ClaimsCanAny` | `ClaimsHaveAnyRoleOn`, `ClaimsCanAllOn`, `ClaimsCanAnyOn` |
| `SubjectHasRole`, `SubjectCan` | `SubjectHasRoleOn`, `SubjectCanOn` |
| `RequireAnyRole`, `RequireAllPermissions`, `RequireAnyPermission` | `RequireAnyRoleOn`, `RequireAllPermissionsOn`, `RequireAnyPermissionOn` |

```go
ok, err := e.CanOn(r.Context(), "projects/42/docs/7", "docs:write")
```

With `CanAllOn`, each permission may come from a different source: one from a global role and another from a binding.

For middleware, `rbac.PathResource` builds the resource from `http.ServeMux` path values:

```go
doc := rbac.PathResource("projects/{project}/docs/{doc}")
mux.Handle("PUT /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:write")(updateDoc))
```

A request whose path value is empty or would produce an invalid resource (whitespace, a `*`, `.` or `..` segment) gets `400 {"error":"bad_request"}`. Path values are unescaped, so `/projects/42%2Fdocs/docs/1` has the project value `42/docs`; a `{name}` value containing `/` is rejected so it can't make the resource look like it is inside project 42. Write `{name...}` where several segments are intended, as in a `ServeMux` `{name...}` wildcard. Any function `func(*http.Request) (string, error)` works as an `rbac.ResourceFunc`. See [HTTP Middleware](HTTP-Middleware.md#scoped-middleware).

## How a scoped check is resolved

1. Arguments are validated: roles or permissions, then the configuration (`ErrNotConfigured` without a `ScopedRoleStore`, or for permission checks without a policy), then the resource (`ErrInvalidScope`), then the claims (`ErrNoClaims`).
2. **Global grants** are checked exactly as `Can` / `HasRole` would. If they answer the check (every permission for `CanAllOn`, any for `CanAnyOn`), it succeeds without calling the resolver or the store. Admins with global roles are checked from the token alone.
3. Otherwise the **resolver** lists the scopes for the resource, the **store** returns the user's bindings for them, and bindings whose pattern matches one of the scopes contribute their roles.
4. Those roles are expanded through the **policy** (a bound `editor` is also a `viewer`) and checked against what step 2 left unanswered.

If no `RoleStore` is configured and the token carries none of the enabled claims, the user has no global grants in scoped checks (global checks return `ErrNotConfigured` in that case).

## Scoped roles only

To make bindings the **only** source of access, turn global roles off:

```go
rbac.New(rbac.WithScopedRolesOnly(), rbac.WithPolicy(policy), rbac.WithScopedRoleStore(bindings))
```

Then:

- scoped checks skip step 2 above: roles and permissions in the token, and the `RoleStore`, are never consulted, so a token issued for another service that lists global roles grants nothing here;
- every scoped check queries the store, since there are no global grants to answer it first;
- global checks (`Can`, `HasRole`, ...) return `ErrNotConfigured`, and their middleware panics at construction;
- embedding is excluded: `WithScopedRolesOnly` turns both embed settings off, and `ScopedRolesOnly` with either one set fails `Config.Validate`.

Roles still come from the policy, so a bound `editor` is a `viewer` and role [exceptions](Policies.md#exceptions) apply.

## Custom resolvers

`PathScopes` fits hierarchical names. When resources belong to groups that are not in their name (tags, teams, folders stored elsewhere), write a resolver that returns the resource plus its groups. Bindings are then made on the groups:

```go
resolver := rbac.ScopeResolverFunc(func(ctx context.Context, resource string) ([]string, error) {
	doc, err := docs.Get(ctx, resource) // resource is e.g. "docs/7"
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: no such document", rbac.ErrInvalidScope) // 400
	}
	if err != nil {
		return nil, err // 500
	}
	scopes := []string{resource, "folders/" + doc.FolderID}
	for _, tag := range doc.Tags {
		scopes = append(scopes, "tags/"+tag)
	}
	return scopes, nil
})

err := bindings.Bind("dave", "tags/finance", "auditor") // every document tagged finance
```

Returned scopes must be concrete (`ValidateScope`); an invalid one is treated as a bug and fails the check with an internal error. Return an error wrapping `rbac.ErrInvalidScope` to reject the resource itself as bad input.

## Why scoped grants are not embedded in tokens

A user can be bound on any number of resources, so embedding bindings would make tokens grow without limit, and every new binding would need a token refresh. Instead:

- global roles and permissions are embedded as configured (see [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md));
- bindings are always read from the `ScopedRoleStore`, so adding or removing one **takes effect immediately**.

The cost is one store query for each scoped check that global grants don't answer. A request that makes several scoped checks makes several queries, so cache inside your store if that matters, and keep the query indexed (see [Storage](Storage.md#scopedrolestore)).

## Things to know

- **Nonexistent resources return 403, not 404.** rbac doesn't know which resources exist. A check on `projects/999` is simply denied unless a global grant or a wildcard binding allows it. If the difference matters, look the resource up first, or have your resolver reject unknown resources.
- **There is no "list what I can access" query.** Scoped checks answer "may this user do X to this resource?". Filtering a list of resources means checking each one, or querying your bindings table directly.
- **Bound role names are not checked against the policy.** As with the `RoleStore`, a role the policy doesn't define grants nothing but still satisfies `HasRoleOn`.
