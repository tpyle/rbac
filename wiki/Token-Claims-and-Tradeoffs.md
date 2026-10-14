# Token Claims and Trade-offs

## What gets embedded

`Enforcer.ClaimsProvider` is an `auth.ClaimsProvider`. auth calls it on every `Login` and every `Refresh` and adds what it returns to the access token:

```json
{
  "sub": "alice",
  "roles": ["editor", "viewer"],
  "perms": ["comments:read", "posts:*"],
  "...": "..."
}
```

- `roles` holds the **effective** roles: assigned roles plus everything they inherit. Services that check roles from the token therefore don't need the policy.
- `perms` holds the effective grants, including wildcards as written in the policy. Grants already covered by another grant are left out (an editor with `posts:*` doesn't also carry `posts:read`), which keeps tokens small without changing what they allow.
- Both are always arrays. A user with no roles gets `[]`, never a missing claim.
- Refresh tokens carry no RBAC claims.

## How checks are resolved

**`HasRole` / `HasAnyRole`**

1. If `EmbedRoles` is set and the token has the roles claim, use it.
2. Otherwise read the user's roles from the `RoleStore`.

Either way, if a policy is configured the roles are expanded through it, so inheritance added after the token was issued counts for role checks just as it does for permission checks. Without a policy, embedded roles are used as they are (they already include what they inherited when the token was issued). If the policy can't be loaded, the check returns the error.

**`Can` / `CanAll` / `CanAny`**

1. If `EmbedPermissions` is set and the token has the permissions claim, use it.
2. Otherwise, if `EmbedRoles` is set, the token has the roles claim and a policy is configured, look the roles up in the policy.
3. Otherwise read the user's roles from the `RoleStore` and look them up in the policy.

Rules that apply throughout:

- A claim counts as **present** if its key exists. `"roles": []` means "no roles", not "look it up".
- A present but **malformed** claim (not an array, non-string items, invalid names) returns `ErrMalformedClaim`. It does not fall back to the database: the issuer meant the claim to be authoritative, so a bad one indicates a bug or misconfiguration.
- **Disabled claims are ignored.** If `EmbedPermissions` is false, a `perms` claim in the token is not read, even if present.

## Choosing what to embed

| | Nothing | Roles | Permissions | Both |
|---|---|---|---|---|
| Role check needs | DB + policy | token (+ policy for inherited roles) | DB + policy | token (+ policy for inherited roles) |
| Permission check needs | DB + policy | token + policy | token | token |
| User role changes take effect | immediately | on refresh | role checks immediately, permission checks on refresh | on refresh |
| Policy changes reach permission checks | immediately* | immediately*, except removed inheritance (on refresh) | on refresh | on refresh |
| Token size | smallest | small | grows with grants | largest |

\* As soon as the `PolicyProvider` returns the new policy. With `StaticPolicy` that means a restart; with `NewCachedPolicyProvider`, within the cache TTL.

Embedded roles include inherited ones (an admin's token lists `admin` and `editor`), so services with no policy can still check inherited roles. In a service with a policy, the token's roles are expanded through the current policy, so **added** inheritance applies immediately. **Removed** inheritance does not affect tokens with embedded roles until they are refreshed, for role and permission checks alike: if you stop `admin` inheriting `editor`, an admin's existing token still lists `editor`, and `editor`'s grants still apply. To revoke faster, see [Staleness](#staleness).

If the token lists a requested role directly, a role check doesn't load the policy at all, so it still succeeds when the `PolicyProvider` is failing. Checks for inherited roles and permission checks need the policy.

### Staleness

Embedded claims are as old as the access token: at most auth's `AccessTokenTTL` (15 minutes by default). Removing a role from a user, or a permission from a role, does not affect tokens already issued. If you need faster revocation:

- shorten `AccessTokenTTL`;
- embed less (permission checks against the policy pick up policy changes immediately);
- call `auth.Authorizer.RevokeAllSessions` for the user so they cannot refresh, and accept the remaining access-token lifetime;
- for critical actions, call `SubjectCan` / `SubjectHasRole`, which always go to the `RoleStore`.

### Token size

Each grant adds its length plus a few bytes. Tokens travel in every request header, and many servers and proxies limit headers to 8 KB. Prefer wildcards (`posts:*`, or `posts:**` for nested permissions) over long lists of concrete permissions, and embed roles instead of permissions if a role has hundreds of grants.

### Scoped bindings

Roles bound on resources (see [Scoped Permissions](Scoped-Permissions.md)) are never embedded: their number is unbounded, and they are always read from the `ScopedRoleStore`, so binding changes take effect immediately. Scoped checks use whatever global claims are embedded first, and only query the store when those don't answer the check. Embedding global roles therefore still saves lookups for users whose global roles suffice, such as admins.

### Changing the configuration

Tokens issued before a change keep their old claims until they expire. When you enable a claim, older tokens without it fall back to the `RoleStore`, so keep the store configured for at least one access-token lifetime. When you disable a claim, it is ignored immediately.
