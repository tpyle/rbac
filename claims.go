package rbac

import "context"

// Claims is the part of a verified access token that an [Enforcer] reads.
// rbac does not verify tokens: whatever authenticates requests fills Claims
// from a token it has already verified, and hands it to the enforcer either
// in the request context (see [ContextWithClaims] and [WithClaimsSource]) or
// directly, as with [Enforcer.ClaimsCanAll].
type Claims struct {
	// Subject identifies the user (the JWT "sub" claim). It is the key
	// passed to the [RoleStore] and [ScopedRoleStore].
	Subject string
	// Values holds the token's other claims by name. The enforcer reads
	// only [Config.RolesClaim] and [Config.PermissionsClaim], each of which
	// must be a []string or, as decoded from JSON, a []any of strings.
	// A nil map is a token with no such claims.
	Values map[string]any
}

// ClaimsSource returns the verified claims of the user authenticated in
// ctx, and false if there is none. Context-based checks such as
// [Enforcer.Can] and the middleware use it to find the caller; see
// [WithClaimsSource].
type ClaimsSource func(ctx context.Context) (*Claims, bool)

type claimsKey struct{}

// ContextWithClaims returns a copy of ctx carrying c, for [ClaimsFromContext]
// to find. Authentication middleware calls it after verifying a token, and
// tests can call it directly. It is only consulted by enforcers using the
// default [ClaimsSource].
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// ClaimsFromContext returns the claims stored by [ContextWithClaims], if
// any. It is the default [ClaimsSource].
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, _ := ctx.Value(claimsKey{}).(*Claims)
	return c, c != nil
}

// registeredClaims are the claim names registered by RFC 7519. They have
// meanings of their own, so rbac never embeds roles or permissions under
// them.
var registeredClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true,
	"nbf": true, "iat": true, "jti": true,
}
