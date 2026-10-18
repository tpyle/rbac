// Package rbac adds role-based access control to services that
// authenticate users with signed tokens such as JWTs. It works with any
// authentication library: rbac does not issue or verify tokens, it only
// computes the claims to embed in them and reads those claims back.
// github.com/tpyle/rbac/authrbac connects it to github.com/tpyle/auth/v2.
//
// A [Policy] maps roles to permission grants. Roles can inherit other roles,
// and grants can use wildcards: "*" matches one segment ("posts:*") and "**"
// any number ("posts:**"). A role can also except permissions from its
// grants (see [RoleDefinition.Except]). Policies are built in code with
// [NewPolicy] or loaded from JSON with [ParsePolicyJSON] (YAML is supported
// by the rbacyaml subpackage).
//
// An [Enforcer] connects the policy to tokens:
//
//   - [Enforcer.ClaimsProvider] computes the user's roles and/or
//     permissions for the token issuer to embed in access tokens, as chosen
//     by [Config].
//   - [Enforcer.HasRole], [Enforcer.Can] and related methods answer checks
//     for the user authenticated in a context, whose verified [Claims] the
//     authentication middleware stores there (see [ContextWithClaims] and
//     [WithClaimsSource]). They use the token's claims
//     when present and otherwise look the user up in a [RoleStore] (usually a
//     database), so every combination of embedded claims works.
//   - [Enforcer.RequireAnyRole], [Enforcer.RequireAllPermissions] and
//     [Enforcer.RequireAnyPermission] are net/http middleware built on those
//     checks.
//
// Roles can also be granted on individual resources or groups of resources
// through a [ScopedRoleStore]: "editor of projects/42", or with a wildcard
// scope, "auditor of projects/*/docs". [Enforcer.CanOn], [Enforcer.HasRoleOn]
// and the middleware [Enforcer.RequireAllPermissionsOn] and its siblings
// check them, combined with the user's global grants. A [ScopeResolver]
// decides which scopes apply to a resource; the default, [PathScopes], makes
// a binding cover everything beneath its scope. Scoped bindings are never
// embedded in tokens. With [Config.ScopedRolesOnly], a service ignores
// global roles and relies on bindings alone.
//
// Embedding claims trades freshness for speed: a change to a user's roles or
// to the policy reaches embedded claims only when the access token is
// refreshed.
package rbac
