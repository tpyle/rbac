package rbac

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// Config holds the plain-data settings of an [Enforcer]. Start from
// [DefaultConfig], override fields, and pass it to [New] with [WithConfig].
//
// The embed settings are a contract between the service issuing tokens and
// every service checking them, so all of them should use the same values.
// An enforcer only reads the claims it is configured to embed: a token
// carrying a disabled claim is treated as not having it.
//
// The mapstructure tags let Config be filled by configuration libraries such
// as Viper without this package depending on them.
type Config struct {
	// EmbedRoles adds the user's effective roles (assigned plus inherited)
	// to access tokens, so role checks need no database lookup.
	EmbedRoles bool `mapstructure:"embed_roles"`
	// EmbedPermissions adds the user's effective permission grants to
	// access tokens, so permission checks need neither a database lookup
	// nor the policy. Tokens grow with the number of grants.
	EmbedPermissions bool `mapstructure:"embed_permissions"`
	// RolesClaim is the JWT claim holding roles.
	RolesClaim string `mapstructure:"roles_claim"`
	// PermissionsClaim is the JWT claim holding permission grants.
	PermissionsClaim string `mapstructure:"permissions_claim"`
	// ScopedRolesOnly disables global roles, so that only roles bound in
	// the [ScopedRoleStore] grant anything. Scoped checks then ignore the
	// token's claims and the [RoleStore], and global checks such as
	// [Enforcer.Can] and [Enforcer.SubjectCan] fail with
	// [ErrNotConfigured]. [Enforcer.EffectiveRoles] and
	// [Enforcer.Permissions] still report the RoleStore's contents if one
	// is configured. It requires a
	// [ScopedRoleStore] and cannot be combined with EmbedRoles or
	// EmbedPermissions.
	ScopedRolesOnly bool `mapstructure:"scoped_roles_only"`
}

// DefaultConfig returns the configuration used when no options are given:
// roles are embedded under "roles", permissions are not embedded (they are
// resolved from the roles through the policy), and the permissions claim is
// named "perms".
func DefaultConfig() Config {
	return Config{
		EmbedRoles:       true,
		EmbedPermissions: false,
		RolesClaim:       "roles",
		PermissionsClaim: "perms",
	}
}

// Validate reports whether c can be used. Claim names must be non-empty,
// distinct and not one of the claims registered by RFC 7519 ("iss", "sub",
// "aud", "exp", "nbf", "iat" and "jti"), and ScopedRolesOnly excludes
// embedding. [New] also rejects names reserved with [WithReservedClaims].
func (c Config) Validate() error {
	var errs []error
	for _, f := range c.claimFields() {
		if f.name == "" {
			errs = append(errs, fmt.Errorf("rbac: %s must not be empty", f.field))
		}
	}
	errs = append(errs, c.reservedClaimErrors(func(name string) bool { return registeredClaims[name] }, "is a registered JWT claim"))
	if c.RolesClaim != "" && c.RolesClaim == c.PermissionsClaim {
		errs = append(errs, errors.New("rbac: RolesClaim and PermissionsClaim must differ"))
	}
	if c.ScopedRolesOnly && (c.EmbedRoles || c.EmbedPermissions) {
		errs = append(errs, errors.New("rbac: ScopedRolesOnly disables global roles, so they must not be embedded"))
	}
	return errors.Join(errs...)
}

// ErrorHandler writes the response when middleware rejects a request. err
// wraps [ErrNoClaims] when the request is not authenticated, [ErrForbidden]
// when it lacks the required access, [ErrInvalidScope] when scoped
// middleware finds no valid resource in the request, and anything else for
// internal failures such as an unreachable [RoleStore].
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// settings is the full internal configuration assembled from options.
type settings struct {
	Config
	roleStore     RoleStore
	scopedStore   ScopedRoleStore
	scopeResolver ScopeResolver
	policy        PolicyProvider
	claimsSource  ClaimsSource
	reserved      func(name string) bool
	errorHandler  ErrorHandler
	logger        *slog.Logger
	caps          capabilities
}

// capabilities records which kinds of check the configuration can answer.
// A non-nil field is the [ErrNotConfigured] error that every check of that
// kind returns, and that middleware for it panics with when built. Checks of
// an answerable kind can still fail for a particular token, such as one
// lacking the claims a service without a [RoleStore] relies on.
type capabilities struct {
	roles, permissions, scopedRoles, scopedPermissions error
	// subject is for checks that read the [RoleStore] directly, such as
	// [Enforcer.SubjectCan]; they still need a store when it is nil.
	subject error
	// context is for checks and middleware that find the user's claims in
	// a context, which need a [ClaimsSource].
	context error
}

func (s *settings) capabilities() capabilities {
	var c capabilities
	switch {
	case s.ScopedRolesOnly:
		c.roles = fmt.Errorf("%w: global checks are disabled by ScopedRolesOnly", ErrNotConfigured)
		c.permissions = c.roles
		c.subject = c.roles
	case s.roleStore == nil && !s.EmbedRoles:
		c.roles = fmt.Errorf("%w: role checks need a role store or embedded roles", ErrNotConfigured)
		// Embedded permissions answer permission checks; embedded roles
		// would too, since buildSettings requires a policy unless
		// permissions are embedded.
		if !s.EmbedPermissions {
			c.permissions = fmt.Errorf("%w: permission checks need a role store or embedded claims", ErrNotConfigured)
		}
	}
	if s.claimsSource == nil {
		c.context = fmt.Errorf("%w: context checks and middleware need a claims source (see WithClaimsSource)", ErrNotConfigured)
	}
	if s.scopedStore == nil {
		c.scopedRoles = fmt.Errorf("%w: scoped checks need a scoped role store", ErrNotConfigured)
		c.scopedPermissions = c.scopedRoles
	} else if s.policy == nil {
		// Only the policy turns bound roles into permissions.
		c.scopedPermissions = fmt.Errorf("%w: scoped permission checks need a policy", ErrNotConfigured)
	}
	return c
}

// Option configures an [Enforcer].
type Option func(*settings)

// WithConfig replaces all plain-data settings with cfg. Options applied after
// it override individual fields.
func WithConfig(cfg Config) Option {
	return func(s *settings) { s.Config = cfg }
}

// WithEmbedRoles sets [Config.EmbedRoles].
func WithEmbedRoles(embed bool) Option {
	return func(s *settings) { s.EmbedRoles = embed }
}

// WithEmbedPermissions sets [Config.EmbedPermissions].
func WithEmbedPermissions(embed bool) Option {
	return func(s *settings) { s.EmbedPermissions = embed }
}

// WithRolesClaim sets [Config.RolesClaim].
func WithRolesClaim(name string) Option {
	return func(s *settings) { s.RolesClaim = name }
}

// WithPermissionsClaim sets [Config.PermissionsClaim].
func WithPermissionsClaim(name string) Option {
	return func(s *settings) { s.PermissionsClaim = name }
}

// WithScopedRolesOnly sets [Config.ScopedRolesOnly] and turns off
// embedding, which it excludes.
func WithScopedRolesOnly() Option {
	return func(s *settings) {
		s.ScopedRolesOnly = true
		s.EmbedRoles = false
		s.EmbedPermissions = false
	}
}

// WithRoleStore sets where users' role assignments are read from. It is
// required to issue claims and to check tokens that lack them.
func WithRoleStore(store RoleStore) Option {
	return func(s *settings) { s.roleStore = store }
}

// WithScopedRoleStore sets where users' roles on individual resources and
// groups of resources are read from. It is required for scoped checks such
// as [Enforcer.CanOn] that the user's global grants do not answer.
func WithScopedRoleStore(store ScopedRoleStore) Option {
	return func(s *settings) { s.scopedStore = store }
}

// WithScopeResolver sets how scoped checks find the scopes that apply to a
// resource. The default, also used when r is nil, is [PathScopes].
func WithScopeResolver(r ScopeResolver) Option {
	return func(s *settings) { s.scopeResolver = r }
}

// WithPolicy sets a fixed role-to-permission policy. It is shorthand for
// WithPolicyProvider(StaticPolicy(p)); a nil p removes the policy.
func WithPolicy(p *Policy) Option {
	return func(s *settings) {
		s.policy = nil
		if p != nil {
			s.policy = StaticPolicy(p)
		}
	}
}

// WithPolicyProvider sets where the role-to-permission policy is read from,
// for policies that can change at runtime (see [NewCachedPolicyProvider]).
func WithPolicyProvider(p PolicyProvider) Option {
	return func(s *settings) { s.policy = p }
}

// WithClaimsSource sets where context-based checks such as [Enforcer.Can]
// and the middleware find the claims of the authenticated user. Pass
// [ClaimsFromContext] if your authentication middleware stores claims with
// [ContextWithClaims], or a function that reads and converts the claims your
// authentication library stores. There is no default, so that a service
// that forgets to set one fails loudly rather than rejecting every request
// as unauthenticated: without a source (or with a nil src), those checks
// fail with [ErrNotConfigured] and the middleware panics when built. Checks
// on explicit claims, such as [Enforcer.ClaimsCanAll], and on subjects, such
// as [Enforcer.SubjectCan], don't need one.
func WithClaimsSource(src ClaimsSource) Option {
	return func(s *settings) { s.claimsSource = src }
}

// WithReservedClaims makes [New] reject a [Config.RolesClaim] or
// [Config.PermissionsClaim] for which reserved returns true, in addition to
// the registered claims [Config.Validate] rejects. Use it with the token
// issuer's own list of claims it manages, so that a clash is reported when
// the enforcer is built rather than when the first token is issued. A nil
// reserved reserves nothing more.
func WithReservedClaims(reserved func(name string) bool) Option {
	return func(s *settings) { s.reserved = reserved }
}

// WithOptions applies opts in order, so that a set of options can be passed
// around as one, for example by a package integrating rbac with an
// authentication library.
func WithOptions(opts ...Option) Option {
	return func(s *settings) {
		for _, opt := range opts {
			opt(s)
		}
	}
}

// WithErrorHandler replaces the default middleware error responses (a JSON
// 401, 403 or 500).
func WithErrorHandler(h ErrorHandler) Option {
	return func(s *settings) { s.errorHandler = h }
}

// WithLogger sets the logger for internal errors in middleware. The default
// is [slog.Default].
func WithLogger(l *slog.Logger) Option {
	return func(s *settings) { s.logger = l }
}

func buildSettings(opts []Option) (*settings, error) {
	s := &settings{Config: DefaultConfig()}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.reserved != nil {
		if err := s.reservedClaimErrors(s.reserved, "is reserved by the token issuer"); err != nil {
			return nil, err
		}
	}
	if s.ScopedRolesOnly && s.scopedStore == nil {
		return nil, fmt.Errorf("%w: ScopedRolesOnly requires a scoped role store", ErrNotConfigured)
	}
	// Without embedded permissions, every permission check goes through
	// the policy; without any embedded claims, every check needs the store.
	if !s.EmbedPermissions && s.policy == nil {
		return nil, fmt.Errorf("%w: a policy is required unless permissions are embedded", ErrNotConfigured)
	}
	s.caps = s.capabilities()
	if s.caps.permissions != nil && s.caps.scopedRoles != nil {
		return nil, fmt.Errorf("%w: a role store or scoped role store is required unless roles or permissions are embedded", ErrNotConfigured)
	}
	if s.scopeResolver == nil {
		s.scopeResolver = PathScopes()
	}
	if s.errorHandler == nil {
		s.errorHandler = defaultErrorHandler
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

// claimField is a claim name setting of a [Config], for error messages.
type claimField struct{ field, name string }

// claimFields returns every claim name setting of c.
func (c Config) claimFields() []claimField {
	return []claimField{
		{"RolesClaim", c.RolesClaim},
		{"PermissionsClaim", c.PermissionsClaim},
	}
}

// reservedClaimErrors returns an error for each claim name of c that
// reserved reports as reserved, saying why.
func (c Config) reservedClaimErrors(reserved func(name string) bool, why string) error {
	var errs []error
	for _, f := range c.claimFields() {
		if reserved(f.name) {
			errs = append(errs, fmt.Errorf("rbac: %s %q %s", f.field, f.name, why))
		}
	}
	return errors.Join(errs...)
}
