// Package authrbac connects [github.com/tpyle/rbac] to
// [github.com/tpyle/auth/v2]. It is a separate module, so that rbac itself
// does not depend on auth.
//
// The token issuer embeds rbac's claims through auth's claims provider, and
// every service checking tokens builds its enforcer with [Option], so that
// checks and middleware read the claims auth verified:
//
//	enforcer, err := rbac.New(authrbac.Option(), rbac.WithPolicy(policy), rbac.WithRoleStore(roles))
//	a, err := auth.New(ctx,
//		auth.WithUserStore(users),
//		auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
//	)
//	handler := a.RequireAuthHandler(enforcer.RequireAllPermissions("posts:write")(h))
package authrbac

import (
	"context"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

// Option configures an [rbac.Enforcer] for tokens issued and verified by
// auth: checks read the claims stored by [auth.Authorizer.AuthHandler],
// [auth.Authorizer.RequireAuthHandler] and [auth.ContextWithClaims] (see
// [ClaimsFromContext]), and [rbac.New] rejects claim names that auth
// manages itself (see [auth.IsReservedClaim]). Options passed to [rbac.New]
// after it override it.
func Option() rbac.Option {
	return rbac.WithOptions(
		rbac.WithClaimsSource(ClaimsFromContext),
		rbac.WithReservedClaims(auth.IsReservedClaim),
	)
}

// ClaimsFromContext returns the auth claims in ctx (see
// [auth.ClaimsFromContext]) as [rbac.Claims]. It is an [rbac.ClaimsSource].
func ClaimsFromContext(ctx context.Context) (*rbac.Claims, bool) {
	c, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return nil, false
	}
	return Claims(c), true
}

// Claims converts verified auth claims to [rbac.Claims], for the checks
// that take claims explicitly, such as [rbac.Enforcer.ClaimsCanAll]. The
// result shares c's Extra map. It returns nil if c is nil, which those
// checks reject with [rbac.ErrNoClaims].
func Claims(c *auth.Claims) *rbac.Claims {
	if c == nil {
		return nil
	}
	return &rbac.Claims{Subject: c.Subject, Values: c.Extra}
}
