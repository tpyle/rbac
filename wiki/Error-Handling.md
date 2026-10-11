# Error Handling

Errors may be wrapped; compare them with `errors.Is`.

| Error | Returned by | Meaning | Typical handling |
|---|---|---|---|
| `ErrNoClaims` | context checks, middleware | No `auth.Claims` in the context: the request is not authenticated, or rbac's middleware runs outside auth's. | 401 |
| `ErrForbidden` | middleware (to the `ErrorHandler`) | The user lacks the required roles or permissions. Checks return `false, nil` instead. | 403 |
| `ErrMalformedClaim` | checks | The token has a roles or permissions claim that is not an array of valid names. | 500; the issuer and checker disagree on claim format or names |
| `ErrInvalidPermission` | checks, `ValidatePermission`, `ValidateGrant`, `NewPolicy` | A malformed permission, a wildcard in a checked permission, or no permissions passed to `CanAll`/`CanAny`. | Programming error; fix the call or policy |
| `ErrInvalidRole` | checks, `NewPolicy`, `RoleStore` results | An empty role name, or one containing whitespace, or no roles passed to `HasAnyRole`. | Programming error or bad data |
| `ErrUnknownRole` | `NewPolicy` | A role inherits a role that is not defined. | Fix the policy |
| `ErrRoleCycle` | `NewPolicy` | Role inheritance contains a cycle; the message shows it. | Fix the policy |
| `ErrInvalidPolicy` | `ParsePolicyJSON`, `LoadPolicyJSON`, `rbacyaml` | The policy file could not be decoded: syntax errors, unknown fields, wrong types, empty input, a missing `roles` key or trailing data. | Fix the file |
| `ErrNilPolicy` | checks, the claims provider, `CachedPolicyProvider` | A `PolicyProvider` returned a nil policy and no error. | Fix the provider; return `rbac.NewPolicy(nil)` for an empty policy |
| `ErrNotConfigured` | `New`, checks, the claims provider | A `RoleStore` or policy is needed but was not supplied. | Configuration error; see [Configuration](Configuration.md#what-new-requires) |

Errors from your `RoleStore` or `PolicyProvider` are wrapped (`rbac: loading roles: ...`, `rbac: loading policy: ...`) and can be matched with `errors.Is` against your own errors.

Arguments are validated before anything else, so a malformed role or permission is reported as such even when the context has no claims.

## Checks fail closed

A check that returns an error also returns `false`. Always handle the error, but if you ignore it you still deny access:

```go
if ok, _ := e.Can(ctx, "posts:delete"); ok {
	// only reached when the check succeeded and allowed access
}
```

## Login and refresh

When the claims provider fails (for example the `RoleStore` is down), auth's `Login` and `Refresh` return the error and issue no tokens. auth looks up claims before consuming the refresh token, so the client can retry the refresh.
