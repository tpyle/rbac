# Storage

rbac never talks to a database itself. You provide small interfaces: `RoleStore` for global roles, `PolicyProvider` for the policy and, for [scoped permissions](Scoped-Permissions.md), `ScopedRoleStore`.

## RoleStore

```go
type RoleStore interface {
	Roles(ctx context.Context, subject string) ([]string, error)
}
```

Return the roles **directly assigned** to the user; inherited roles are added from the policy. An unknown user should return an empty slice and a nil error. Returned role names must be valid (non-empty, no whitespace) or the check fails with `ErrInvalidRole`.

`subject` is the JWT `sub` claim, which auth sets to the username passed to `Login`.

It is called:

- by the claims provider on every login and refresh, if anything is embedded;
- by checks whose token lacks the needed claims;
- by `EffectiveRoles`, `Permissions`, `SubjectHasRole` and `SubjectCan`.

### PostgreSQL example

```sql
CREATE TABLE user_roles (
    subject TEXT NOT NULL,
    role    TEXT NOT NULL,
    PRIMARY KEY (subject, role)
);
```

```go
type SQLRoleStore struct{ DB *sql.DB }

func (s SQLRoleStore) Roles(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT role FROM user_roles WHERE subject = $1`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}
```

A plain function works too:

```go
rbac.WithRoleStore(rbac.RoleStoreFunc(func(ctx context.Context, subject string) ([]string, error) {
	return lookup(ctx, subject)
}))
```

### In memory

`rbac.NewMemoryRoleStore()` is safe for concurrent use and intended for tests, examples and prototypes:

```go
s := rbac.NewMemoryRoleStore()
s.SetRoles("alice", "editor")      // replace
s.AddRoles("alice", "auditor")     // add
s.RemoveRoles("alice", "editor")   // remove
```

## ScopedRoleStore

```go
type Binding struct {
	Scope string // a scope pattern, such as "projects/42" or "projects/*/docs"
	Role  string
}

type ScopedRoleStore interface {
	Bindings(ctx context.Context, subject string, scopes []string) ([]Binding, error)
}
```

`scopes` are the concrete scopes that apply to the resource being checked, from the `ScopeResolver` (for `PathScopes`, the resource and its ancestors). Return **at least**:

- every binding of the subject whose scope is one of `scopes`, and
- every binding of the subject whose scope contains a wildcard.

Returning more is fine: rbac matches every result against `scopes` itself, so returning all of a subject's bindings is a correct, if slower, implementation. Returning less silently denies access. Returned scopes must be valid patterns and roles valid names, or the check fails with an internal error. Wildcard bindings are returned for every check, so one bad wildcard row breaks all of that user's scoped checks. rbac fails closed and loudly here rather than skipping the row. Validate with `rbac.ValidateScopePattern` before writing a binding, as `MemoryScopedRoleStore.Bind` does.

It is called for each scoped check that the user's global grants don't answer.

### PostgreSQL example

```sql
CREATE TABLE role_bindings (
    subject    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    role       TEXT NOT NULL,
    is_pattern BOOLEAN GENERATED ALWAYS AS (scope LIKE '%*%') STORED,
    PRIMARY KEY (subject, scope, role)
);
-- Wildcard bindings are rare; this keeps fetching them cheap.
CREATE INDEX role_bindings_patterns ON role_bindings (subject) WHERE is_pattern;
```

```go
type SQLScopedRoleStore struct{ DB *sql.DB }

func (s SQLScopedRoleStore) Bindings(ctx context.Context, subject string, scopes []string) ([]rbac.Binding, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT scope, role FROM role_bindings
		 WHERE subject = $1 AND (scope = ANY($2) OR is_pattern)`,
		subject, pq.Array(scopes)) // or pgx, which accepts []string directly
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rbac.Binding
	for rows.Next() {
		var b rbac.Binding
		if err := rows.Scan(&b.Scope, &b.Role); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
```

`rbac.ScopedRoleStoreFunc` adapts a function.

### In memory

`rbac.NewMemoryScopedRoleStore()` is safe for concurrent use and intended for tests, examples and prototypes. `Bind` rejects an invalid scope pattern (`ErrInvalidScope`) or role name (`ErrInvalidRole`) without binding anything:

```go
s := rbac.NewMemoryScopedRoleStore()
err := s.Bind("bob", "projects/42", "editor")       // add
err = s.Bind("dave", "projects/*/docs", "auditor")  // scope patterns work too
s.Unbind("bob", "projects/42", "editor")      // remove one role
s.Unbind("dave", "projects/*/docs")           // remove every role on the scope
```

## PolicyProvider

```go
type PolicyProvider interface {
	Policy(ctx context.Context) (*Policy, error)
}
```

It is called on every check that needs the policy, so it must be fast. It must return a policy or an error: a nil policy with a nil error fails the check with `ErrNilPolicy` rather than silently denying everything. An empty policy is `rbac.NewPolicy(nil)`.

- `rbac.WithPolicy(p)` / `rbac.StaticPolicy(p)`: a policy fixed at startup, such as one loaded from a file.
- `rbac.PolicyProviderFunc`: adapt a function.
- `rbac.NewCachedPolicyProvider(load, ttl, opts...)`: wrap a slow loader.

### Policies in a database

```sql
CREATE TABLE roles (
    name TEXT PRIMARY KEY
);
CREATE TABLE role_permissions (
    role       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
);
CREATE TABLE role_inherits (
    role   TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    parent TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (role, parent)
);
```

```go
func loadPolicy(ctx context.Context, db *sql.DB) (*rbac.Policy, error) {
	defs := map[string]rbac.RoleDefinition{}
	// SELECT name FROM roles                          -> defs[name] = RoleDefinition{}
	// SELECT role, permission FROM role_permissions   -> append to defs[role].Permissions
	// SELECT role, parent FROM role_inherits          -> append to defs[role].Inherits
	return rbac.NewPolicy(defs)
}

cached := rbac.NewCachedPolicyProvider(func(ctx context.Context) (*rbac.Policy, error) {
	return loadPolicy(ctx, db)
}, time.Minute,
	rbac.WithLoadTimeout(5*time.Second), // default 30s
	rbac.WithStaleGrace(5*time.Minute),  // optional, see below
)

e, err := rbac.New(rbac.WithRoleStore(store), rbac.WithPolicyProvider(cached))

// After editing the tables in this process:
cached.Invalidate()
```

`CachedPolicyProvider` loads at most once per TTL. When the cache is stale, one load runs and every caller arriving while it is in progress shares its result, **including a failure**, so a slow or failing database costs one query rather than one per waiting request. Each caller stops waiting with `ctx.Err()` when its own context ends.

The load itself is not cancelled when the request that started it goes away (it runs with `context.WithoutCancel`), so one impatient client can't fail the load for everyone. Instead each load is bounded by a timeout: `rbac.DefaultLoadTimeout` (30 seconds), or whatever `rbac.WithLoadTimeout` sets. When it expires the loader's context is cancelled and the load fails with `context.DeadlineExceeded`, even if the loader ignores its context, so a hung database connection can't block the cache. `WithLoadTimeout(0)` disables it, which is only safe if your loader always returns.

### Serving a stale policy (opt-in)

By default an expired policy is never used: once the TTL passes, callers wait for a reload, and if it fails, their checks fail. `rbac.WithStaleGrace(d)` trades that for availability. For up to `d` after the TTL expires, callers get the previous policy immediately while a reload runs in the background, and a failed reload leaves the previous policy in use, so a brief database outage doesn't fail every check. After the grace period, callers wait for a load as usual. `Invalidate` discards the policy at once, grace or not, so explicit edits are never masked.

Use it when your policy changes rarely and availability matters more than picking up a change a few minutes sooner. A policy change can then take up to TTL + grace to apply.

### Failures and invalidation

A failed load, or one returning a nil policy (`ErrNilPolicy`), is not cached, so the next call retries and checks fail closed instead of using a policy that could not be loaded. A TTL of zero or less disables caching: every call loads, concurrently, with the caller's context. If `Invalidate` is called while a load is in progress, callers already waiting get that load's result, but it is not cached. Later callers share one follow-up load, which starts when the running one finishes, so at most one load runs at a time however often you invalidate. A panic in the loader is returned to the waiting callers as an error instead of crashing the program. Validate policy edits with `rbac.NewPolicy` before committing them, since an invalid policy (such as a cycle) makes every load fail.
