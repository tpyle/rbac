// Package rbac adds role-based access control to services authenticated
// with [github.com/tpyle/auth/v2].
//
// A [Policy] maps roles to permission grants. Roles can inherit other roles,
// and grants can use wildcards ("posts:*"). Policies are built in code with
// [NewPolicy] or loaded from JSON with [ParsePolicyJSON] (YAML is supported
// by the rbacyaml subpackage).
//
// An [Enforcer] connects the policy to tokens:
//
//   - [Enforcer.ClaimsProvider] plugs into [auth.WithClaimsProvider] and
//     embeds the user's roles and/or permissions in access tokens, as chosen
//     by [Config].
//   - [Enforcer.HasRole], [Enforcer.Can] and related methods answer checks
//     for the user authenticated in a context. They use the token's claims
//     when present and otherwise look the user up in a [RoleStore] (usually a
//     database), so every combination of embedded claims works.
//   - [Enforcer.RequireAnyRole], [Enforcer.RequireAllPermissions] and
//     [Enforcer.RequireAnyPermission] are net/http middleware built on those
//     checks.
//
// Embedding claims trades freshness for speed: a change to a user's roles or
// to the policy reaches embedded claims only when the access token is
// refreshed.
package rbac
