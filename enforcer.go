package rbac

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/tpyle/auth/v2"
)

// Enforcer issues RBAC claims and answers role and permission checks. It is
// created with [New] and is safe for concurrent use.
//
// Checks prefer the claims in the access token and fall back to the
// [RoleStore] when the token does not carry them. Permission checks resolve,
// in order:
//
//  1. the permissions claim, if embedding permissions is enabled and the
//     token has it;
//  2. the roles claim through the [Policy], if embedding roles is enabled
//     and the token has it;
//  3. the subject's roles from the [RoleStore] through the [Policy].
//
// Role checks use the roles claim if enabled and present, and otherwise the
// [RoleStore]. Either way, roles are expanded through the policy if one is
// configured, so inheritance added since the token was issued is seen by
// role checks just as it is by permission checks. If the token lists a
// requested role directly, the policy is not loaded, so such checks succeed
// even when the [PolicyProvider] is failing.
//
// Inheritance removed since a token was issued still applies to it, for
// role and permission checks alike, until the token is refreshed: the token
// lists the roles that were inherited when it was issued, and each of them
// keeps its own grants.
//
// A claim counts as present if its key exists, so an empty array means "no
// roles" rather than "look it up". A present but malformed claim is an error
// wrapping [ErrMalformedClaim].
//
// # Scoped checks
//
// [Enforcer.CanOn], [Enforcer.HasRoleOn] and related methods ask about a
// specific resource. A user's grants on a resource are the union of:
//
//   - their global grants, resolved exactly as for [Enforcer.Can] and
//     [Enforcer.HasRole], which apply to every resource; and
//   - the grants of the roles bound to them in the [ScopedRoleStore] on any
//     scope the [ScopeResolver] lists for the resource.
//
// Global grants are consulted first, and the resolver and store are only
// called for what they leave unanswered, so users with broad global roles
// are checked from the token alone. Scoped bindings are never embedded in
// tokens. Bound roles are expanded through the policy: a binding of
// "editor" also grants what "editor" inherits.
//
// If no [RoleStore] is configured and the token carries none of the enabled
// claims, the user has no global grants in scoped checks (where global
// checks report [ErrNotConfigured]), so a service can rely on bindings
// alone. With [Config.ScopedRolesOnly], global grants are never consulted:
// only bindings count, and global checks fail with [ErrNotConfigured].
//
// Scoped checks need a [ScopedRoleStore], and scoped permission checks a
// policy; without them they fail with [ErrNotConfigured] even for users
// whose global grants would answer.
type Enforcer struct {
	s *settings
}

// New returns an [Enforcer]. Without options it embeds roles (see
// [DefaultConfig]) and needs a policy. It fails with [ErrNotConfigured] if
// no check of some kind could ever be answered: a policy is required unless
// permissions are embedded, and a [RoleStore] is required unless roles or
// permissions are embedded.
//
// Other gaps are allowed, because a service may never make the checks
// affected. Those checks fail with [ErrNotConfigured] when called, and
// middleware for them panics when built. For example, with only permissions
// embedded and no [RoleStore], permission checks work but role checks do
// not, since the token carries no roles. The
// service that issues tokens always needs a [RoleStore] (and a policy, to
// embed permissions).
func New(opts ...Option) (*Enforcer, error) {
	s, err := buildSettings(opts)
	if err != nil {
		return nil, err
	}
	return &Enforcer{s: s}, nil
}

// Config returns the enforcer's plain-data settings.
func (e *Enforcer) Config() Config {
	return e.s.Config
}

// ClaimsProvider returns an [auth.ClaimsProvider] that adds the configured
// RBAC claims to access tokens, for use with [auth.WithClaimsProvider]. The
// auth package calls it on every login and refresh, so embedded claims are
// at most one access-token lifetime out of date.
//
// Claims from base, if not nil, are included too. base must not set the
// names of the claims rbac embeds; the name of a disabled claim is free for
// base to use. With nothing embedded, only base's claims are returned.
func (e *Enforcer) ClaimsProvider(base auth.ClaimsProvider) auth.ClaimsProvider {
	return func(ctx context.Context, subject string) (map[string]any, error) {
		claims := map[string]any{}
		if base != nil {
			extra, err := base(ctx, subject)
			if err != nil {
				return nil, err
			}
			maps.Copy(claims, extra)
		}
		for _, name := range e.embeddedClaims() {
			if _, ok := claims[name]; ok {
				return nil, fmt.Errorf("rbac: base claims provider set claim %q, which is managed by rbac", name)
			}
		}
		if !e.s.EmbedRoles && !e.s.EmbedPermissions {
			return claims, nil
		}

		assigned, err := e.assignedRoles(ctx, subject)
		if err != nil {
			return nil, err
		}
		var policy *Policy
		if e.s.policy != nil {
			if policy, err = e.loadPolicy(ctx); err != nil {
				return nil, err
			}
		}
		if e.s.EmbedRoles {
			claims[e.s.RolesClaim] = policy.EffectiveRoles(assigned...)
		}
		if e.s.EmbedPermissions {
			if policy == nil {
				return nil, fmt.Errorf("%w: embedding permissions requires a policy", ErrNotConfigured)
			}
			claims[e.s.PermissionsClaim] = minimalGrants(policy.Permissions(assigned...))
		}
		return claims, nil
	}
}

// embeddedClaims returns the names of the claims the enforcer embeds.
func (e *Enforcer) embeddedClaims() []string {
	var names []string
	if e.s.EmbedRoles {
		names = append(names, e.s.RolesClaim)
	}
	if e.s.EmbedPermissions {
		names = append(names, e.s.PermissionsClaim)
	}
	return names
}

// EffectiveRoles returns subject's roles from the [RoleStore], plus the
// roles they inherit if a policy is configured. It ignores tokens.
func (e *Enforcer) EffectiveRoles(ctx context.Context, subject string) ([]string, error) {
	assigned, err := e.assignedRoles(ctx, subject)
	if err != nil {
		return nil, err
	}
	if e.s.policy == nil {
		return sortedUnique(slices.Clone(assigned)), nil
	}
	policy, err := e.loadPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return policy.EffectiveRoles(assigned...), nil
}

// Permissions returns the grants subject holds through the roles in the
// [RoleStore] and the policy. It ignores tokens.
func (e *Enforcer) Permissions(ctx context.Context, subject string) ([]string, error) {
	assigned, err := e.assignedRoles(ctx, subject)
	if err != nil {
		return nil, err
	}
	policy, err := e.requirePolicy(ctx)
	if err != nil {
		return nil, err
	}
	return policy.Permissions(assigned...), nil
}

// HasRole reports whether the user authenticated in ctx (see
// [auth.ClaimsFromContext]) has role, directly or through inheritance. It
// returns [ErrInvalidRole] if role is invalid and [ErrNoClaims] if ctx has
// no claims.
func (e *Enforcer) HasRole(ctx context.Context, role string) (bool, error) {
	return e.HasAnyRole(ctx, role)
}

// HasAnyRole reports whether the user authenticated in ctx has at least one
// of roles. Arguments are validated before the context is consulted: it
// returns [ErrInvalidRole] if roles is empty or contains an invalid name,
// then [ErrNotConfigured] if the enforcer has neither a [RoleStore] nor
// embedded roles, then [ErrNoClaims] if ctx has no claims.
func (e *Enforcer) HasAnyRole(ctx context.Context, roles ...string) (bool, error) {
	if err := firstErr(checkRoles(roles), e.s.caps.roles); err != nil {
		return false, err
	}
	c, err := claimsFromContext(ctx)
	if err != nil {
		return false, err
	}
	return e.hasAnyRole(ctx, c, roles)
}

// Can reports whether the user authenticated in ctx holds the concrete
// permission perm. It returns [ErrInvalidPermission] if perm is not concrete
// and [ErrNoClaims] if ctx has no claims.
func (e *Enforcer) Can(ctx context.Context, perm string) (bool, error) {
	return e.CanAll(ctx, perm)
}

// CanAll reports whether the user authenticated in ctx holds every one of
// perms. Arguments are validated before the context is consulted: it
// returns [ErrInvalidPermission] if perms is empty or contains a permission
// that is not concrete, then [ErrNotConfigured] if the enforcer has neither
// a [RoleStore] nor embedded claims, then [ErrNoClaims] if ctx has no
// claims.
func (e *Enforcer) CanAll(ctx context.Context, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.permissions); err != nil {
		return false, err
	}
	c, err := claimsFromContext(ctx)
	if err != nil {
		return false, err
	}
	return e.canAll(ctx, c, perms)
}

// CanAny reports whether the user authenticated in ctx holds at least one of
// perms. Errors are as for [Enforcer.CanAll].
func (e *Enforcer) CanAny(ctx context.Context, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.permissions); err != nil {
		return false, err
	}
	c, err := claimsFromContext(ctx)
	if err != nil {
		return false, err
	}
	return e.canAny(ctx, c, perms)
}

// ClaimsHaveAnyRole is like [Enforcer.HasAnyRole] for explicitly supplied
// claims, such as those returned by [auth.Authorizer.VerifyAccessToken].
func (e *Enforcer) ClaimsHaveAnyRole(ctx context.Context, c *auth.Claims, roles ...string) (bool, error) {
	if err := firstErr(checkRoles(roles), e.s.caps.roles); err != nil {
		return false, err
	}
	return e.hasAnyRole(ctx, c, roles)
}

// ClaimsCanAll is like [Enforcer.CanAll] for explicitly supplied claims.
func (e *Enforcer) ClaimsCanAll(ctx context.Context, c *auth.Claims, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.permissions); err != nil {
		return false, err
	}
	return e.canAll(ctx, c, perms)
}

// ClaimsCanAny is like [Enforcer.CanAny] for explicitly supplied claims.
func (e *Enforcer) ClaimsCanAny(ctx context.Context, c *auth.Claims, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.permissions); err != nil {
		return false, err
	}
	return e.canAny(ctx, c, perms)
}

// SubjectHasRole reports whether subject has role according to the
// [RoleStore] and policy, ignoring tokens.
func (e *Enforcer) SubjectHasRole(ctx context.Context, subject, role string) (bool, error) {
	if err := validateRole(role); err != nil {
		return false, err
	}
	have, err := e.EffectiveRoles(ctx, subject)
	if err != nil {
		return false, err
	}
	return slices.Contains(have, role), nil
}

// SubjectCan reports whether subject holds the concrete permission perm
// according to the [RoleStore] and policy, ignoring tokens.
func (e *Enforcer) SubjectCan(ctx context.Context, subject, perm string) (bool, error) {
	if err := ValidatePermission(perm); err != nil {
		return false, err
	}
	allows, err := e.subjectGrants(ctx, subject)
	if err != nil {
		return false, err
	}
	return allows(perm), nil
}

// hasAnyRole, canAll and canAny implement the checks for arguments that have
// already been validated.

func (e *Enforcer) hasAnyRole(ctx context.Context, c *auth.Claims, roles []string) (bool, error) {
	have, err := e.rolesFromClaims(ctx, c, roles)
	if err != nil {
		return false, err
	}
	return containsAny(have, roles), nil
}

func containsAny(have, want []string) bool {
	return slices.ContainsFunc(want, func(r string) bool { return slices.Contains(have, r) })
}

func (e *Enforcer) canAll(ctx context.Context, c *auth.Claims, perms []string) (bool, error) {
	allows, err := e.grantsFromClaims(ctx, c)
	if err != nil {
		return false, err
	}
	return !slices.ContainsFunc(perms, func(p string) bool { return !allows(p) }), nil
}

func (e *Enforcer) canAny(ctx context.Context, c *auth.Claims, perms []string) (bool, error) {
	allows, err := e.grantsFromClaims(ctx, c)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(perms, allows), nil
}

func claimsFromContext(ctx context.Context) (*auth.Claims, error) {
	c, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		return nil, ErrNoClaims
	}
	return c, nil
}

// firstErr returns the first non-nil error in errs. Checks list their
// argument, configuration and resource errors in the order they report them.
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func checkRoles(roles []string) error {
	if len(roles) == 0 {
		return fmt.Errorf("%w: no roles given", ErrInvalidRole)
	}
	for _, r := range roles {
		if err := validateRole(r); err != nil {
			return err
		}
	}
	return nil
}

func checkPermissions(perms []string) error {
	if len(perms) == 0 {
		return fmt.Errorf("%w: no permissions given", ErrInvalidPermission)
	}
	for _, p := range perms {
		if err := ValidatePermission(p); err != nil {
			return err
		}
	}
	return nil
}

// rolesFromClaims returns the effective roles for c, from the token if
// possible and otherwise from the store, expanded through the policy if one
// is configured. If the token lists any of want directly, or no roles at
// all, its roles are returned as they are, so that the check does not depend
// on loading the policy.
func (e *Enforcer) rolesFromClaims(ctx context.Context, c *auth.Claims, want []string) ([]string, error) {
	if c == nil {
		return nil, ErrNoClaims
	}
	if e.s.EmbedRoles {
		roles, ok, err := e.readClaim(c, e.s.RolesClaim, validateRole)
		if err != nil {
			return nil, err
		}
		if ok {
			if e.s.policy == nil || len(roles) == 0 || containsAny(roles, want) {
				return roles, nil
			}
			policy, err := e.loadPolicy(ctx)
			if err != nil {
				return nil, err
			}
			return policy.EffectiveRoles(roles...), nil
		}
	}
	return e.EffectiveRoles(ctx, c.Subject)
}

// grantsFromClaims returns a matcher for the grants of c, following the
// order documented on [Enforcer].
func (e *Enforcer) grantsFromClaims(ctx context.Context, c *auth.Claims) (func(perm string) bool, error) {
	if c == nil {
		return nil, ErrNoClaims
	}
	if e.s.EmbedPermissions {
		grants, ok, err := e.readClaim(c, e.s.PermissionsClaim, validateGrantExpr)
		if err != nil {
			return nil, err
		}
		if ok {
			// Tokens hold few grants and are checked against one or two
			// permissions, so a scan beats building a lookup map.
			return func(perm string) bool {
				return slices.ContainsFunc(grants, func(g string) bool { return Grants(g, perm) })
			}, nil
		}
	}
	roles, ok, err := e.readRolesForPolicy(c)
	if err != nil {
		return nil, err
	}
	if !ok {
		return e.subjectGrants(ctx, c.Subject)
	}
	if len(roles) == 0 {
		return noGrants, nil
	}
	policy, err := e.requirePolicy(ctx)
	if err != nil {
		return nil, err
	}
	return func(perm string) bool { return policy.allows(roles, perm) }, nil
}

// subjectGrants returns a matcher for the grants subject holds according to
// the [RoleStore] and policy.
func (e *Enforcer) subjectGrants(ctx context.Context, subject string) (func(perm string) bool, error) {
	assigned, err := e.assignedRoles(ctx, subject)
	if err != nil {
		return nil, err
	}
	policy, err := e.requirePolicy(ctx)
	if err != nil {
		return nil, err
	}
	return func(perm string) bool { return policy.allows(assigned, perm) }, nil
}

// readRolesForPolicy returns the token's roles claim if roles are embedded
// and a policy is available to turn them into permissions.
func (e *Enforcer) readRolesForPolicy(c *auth.Claims) ([]string, bool, error) {
	if !e.s.EmbedRoles || e.s.policy == nil {
		return nil, false, nil
	}
	return e.readClaim(c, e.s.RolesClaim, validateRole)
}

// readClaim decodes the string-array claim name from c, validating each
// element. ok is false if the claim is absent.
func (e *Enforcer) readClaim(c *auth.Claims, name string, validate func(string) error) (values []string, ok bool, err error) {
	raw, present := c.Extra[name]
	if !present {
		return nil, false, nil
	}
	malformed := func(why string) ([]string, bool, error) {
		return nil, false, fmt.Errorf("%w: %q %s", ErrMalformedClaim, name, why)
	}
	switch v := raw.(type) {
	case []string:
		values = slices.Clone(v)
	case []any:
		values = make([]string, 0, len(v))
		for _, item := range v {
			s, isString := item.(string)
			if !isString {
				return malformed("contains a non-string value")
			}
			values = append(values, s)
		}
	default:
		return malformed("is not an array")
	}
	for _, s := range values {
		if err := validate(s); err != nil {
			return nil, false, fmt.Errorf("%w: %q: %w", ErrMalformedClaim, name, err)
		}
	}
	return values, true, nil
}

// errNoRoleStore is returned when a check needs the [RoleStore] and none is
// configured. Scoped checks take it to mean the user has no global grants.
var errNoRoleStore = fmt.Errorf("%w: no role store", ErrNotConfigured)

func (e *Enforcer) assignedRoles(ctx context.Context, subject string) ([]string, error) {
	if e.s.roleStore == nil {
		return nil, errNoRoleStore
	}
	roles, err := e.s.roleStore.Roles(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("rbac: loading roles: %w", err)
	}
	for _, r := range roles {
		if err := validateRole(r); err != nil {
			return nil, fmt.Errorf("rbac: role store returned an invalid role for %q: %w", subject, err)
		}
	}
	return roles, nil
}

func (e *Enforcer) loadPolicy(ctx context.Context) (*Policy, error) {
	p, err := e.s.policy.Policy(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: loading policy: %w", err)
	}
	if p == nil {
		return nil, ErrNilPolicy
	}
	return p, nil
}

func (e *Enforcer) requirePolicy(ctx context.Context) (*Policy, error) {
	if e.s.policy == nil {
		return nil, fmt.Errorf("%w: no policy", ErrNotConfigured)
	}
	return e.loadPolicy(ctx)
}
