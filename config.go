package rbac

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tpyle/auth/v2"
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
// distinct and not reserved by the auth package (see [auth.IsReservedClaim]).
func (c Config) Validate() error {
	var errs []error
	for _, f := range []struct{ field, name string }{
		{"RolesClaim", c.RolesClaim},
		{"PermissionsClaim", c.PermissionsClaim},
	} {
		switch {
		case f.name == "":
			errs = append(errs, fmt.Errorf("rbac: %s must not be empty", f.field))
		case auth.IsReservedClaim(f.name):
			errs = append(errs, fmt.Errorf("rbac: %s %q is reserved by the auth package", f.field, f.name))
		}
	}
	if c.RolesClaim != "" && c.RolesClaim == c.PermissionsClaim {
		errs = append(errs, errors.New("rbac: RolesClaim and PermissionsClaim must differ"))
	}
	return errors.Join(errs...)
}

// ErrorHandler writes the response when middleware rejects a request. err
// wraps [ErrNoClaims] when the request is not authenticated, [ErrForbidden]
// when it lacks the required access, and anything else for internal failures
// such as an unreachable [RoleStore].
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// settings is the full internal configuration assembled from options.
type settings struct {
	Config
	roleStore    RoleStore
	policy       PolicyProvider
	errorHandler ErrorHandler
	logger       *slog.Logger
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

// WithRoleStore sets where users' role assignments are read from. It is
// required to issue claims and to check tokens that lack them.
func WithRoleStore(store RoleStore) Option {
	return func(s *settings) { s.roleStore = store }
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
	// Without embedded permissions, every permission check goes through
	// the policy; without any embedded claims, every check needs the store.
	if !s.EmbedPermissions && s.policy == nil {
		return nil, fmt.Errorf("%w: a policy is required unless permissions are embedded", ErrNotConfigured)
	}
	if !s.EmbedRoles && !s.EmbedPermissions && s.roleStore == nil {
		return nil, fmt.Errorf("%w: a role store is required unless roles or permissions are embedded", ErrNotConfigured)
	}
	if s.errorHandler == nil {
		s.errorHandler = defaultErrorHandler
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}
