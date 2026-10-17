package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/tpyle/auth/v2"
)

// HasRoleOn reports whether the user authenticated in ctx has role on
// resource, globally or through a binding. It returns [ErrInvalidRole] if
// role is invalid, [ErrNotConfigured] if no [ScopedRoleStore] is configured,
// [ErrInvalidScope] if resource is not a concrete scope and [ErrNoClaims] if
// ctx has no claims, in that order.
func (e *Enforcer) HasRoleOn(ctx context.Context, resource, role string) (bool, error) {
	return e.HasAnyRoleOn(ctx, resource, role)
}

// HasAnyRoleOn reports whether the user authenticated in ctx has at least
// one of roles on resource. Arguments are validated before the context is
// consulted, as for [Enforcer.HasRoleOn].
func (e *Enforcer) HasAnyRoleOn(ctx context.Context, resource string, roles ...string) (bool, error) {
	if err := firstErr(checkRoles(roles), e.s.caps.scopedRoles, ValidateScope(resource)); err != nil {
		return false, err
	}
	c, err := claimsFromContext(ctx)
	if err != nil {
		return false, err
	}
	return e.hasAnyRoleOn(ctx, c, resource, roles)
}

// CanOn reports whether the user authenticated in ctx holds the concrete
// permission perm on resource. It returns [ErrInvalidPermission] if perm is
// not concrete, [ErrNotConfigured] if no [ScopedRoleStore] or policy is
// configured, [ErrInvalidScope] if resource is not a concrete scope and
// [ErrNoClaims] if ctx has no claims, in that order.
func (e *Enforcer) CanOn(ctx context.Context, resource, perm string) (bool, error) {
	return e.CanAllOn(ctx, resource, perm)
}

// CanAllOn reports whether the user authenticated in ctx holds every one of
// perms on resource. Each permission may come from a different source: one
// from a global role and another from a binding. Arguments are validated
// before the context is consulted, as for [Enforcer.CanOn].
func (e *Enforcer) CanAllOn(ctx context.Context, resource string, perms ...string) (bool, error) {
	return e.canOnFromContext(ctx, resource, perms, true)
}

// CanAnyOn reports whether the user authenticated in ctx holds at least one
// of perms on resource. Errors are as for [Enforcer.CanAllOn].
func (e *Enforcer) CanAnyOn(ctx context.Context, resource string, perms ...string) (bool, error) {
	return e.canOnFromContext(ctx, resource, perms, false)
}

// ClaimsHaveAnyRoleOn is like [Enforcer.HasAnyRoleOn] for explicitly
// supplied claims, such as those returned by
// [auth.Authorizer.VerifyAccessToken].
func (e *Enforcer) ClaimsHaveAnyRoleOn(ctx context.Context, c *auth.Claims, resource string, roles ...string) (bool, error) {
	if err := firstErr(checkRoles(roles), e.s.caps.scopedRoles, ValidateScope(resource)); err != nil {
		return false, err
	}
	return e.hasAnyRoleOn(ctx, c, resource, roles)
}

// ClaimsCanAllOn is like [Enforcer.CanAllOn] for explicitly supplied claims.
func (e *Enforcer) ClaimsCanAllOn(ctx context.Context, c *auth.Claims, resource string, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.scopedPermissions, ValidateScope(resource)); err != nil {
		return false, err
	}
	return e.canOn(ctx, c, resource, perms, true)
}

// ClaimsCanAnyOn is like [Enforcer.CanAnyOn] for explicitly supplied claims.
func (e *Enforcer) ClaimsCanAnyOn(ctx context.Context, c *auth.Claims, resource string, perms ...string) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.scopedPermissions, ValidateScope(resource)); err != nil {
		return false, err
	}
	return e.canOn(ctx, c, resource, perms, false)
}

// SubjectHasRoleOn reports whether subject has role on resource according
// to the [RoleStore], [ScopedRoleStore] and policy, ignoring tokens. With
// [Config.ScopedRolesOnly], the [RoleStore] is not consulted.
func (e *Enforcer) SubjectHasRoleOn(ctx context.Context, subject, resource, role string) (bool, error) {
	roles := []string{role}
	if err := firstErr(checkRoles(roles), e.s.caps.scopedRoles, ValidateScope(resource)); err != nil {
		return false, err
	}
	if !e.s.ScopedRolesOnly {
		have, err := e.EffectiveRoles(ctx, subject)
		if err = ignoreNoRoleStore(err); err != nil {
			return false, err
		}
		if slices.Contains(have, role) {
			return true, nil
		}
	}
	return e.boundHasAnyRole(ctx, subject, resource, roles)
}

// SubjectCanOn reports whether subject holds the concrete permission perm on
// resource according to the [RoleStore], [ScopedRoleStore] and policy,
// ignoring tokens. With [Config.ScopedRolesOnly], the [RoleStore] is not
// consulted.
func (e *Enforcer) SubjectCanOn(ctx context.Context, subject, resource, perm string) (bool, error) {
	perms := []string{perm}
	if err := firstErr(checkPermissions(perms), e.s.caps.scopedPermissions, ValidateScope(resource)); err != nil {
		return false, err
	}
	global := noGrants
	if !e.s.ScopedRolesOnly {
		var err error
		if global, err = e.subjectGrants(ctx, subject); err != nil {
			if err = ignoreNoRoleStore(err); err != nil {
				return false, err
			}
			global = noGrants
		}
	}
	return e.scopedCan(ctx, subject, resource, perms, true, global)
}

func noGrants(string) bool { return false }

// ignoreNoRoleStore returns err unless it reports that no [RoleStore] is
// configured. Scoped checks treat that as having no global roles, so that a
// service can rely on bindings alone.
func ignoreNoRoleStore(err error) error {
	if errors.Is(err, errNoRoleStore) {
		return nil
	}
	return err
}

func (e *Enforcer) canOnFromContext(ctx context.Context, resource string, perms []string, all bool) (bool, error) {
	if err := firstErr(checkPermissions(perms), e.s.caps.scopedPermissions, ValidateScope(resource)); err != nil {
		return false, err
	}
	c, err := claimsFromContext(ctx)
	if err != nil {
		return false, err
	}
	return e.canOn(ctx, c, resource, perms, all)
}

// hasAnyRoleOn and canOn implement the scoped checks for arguments that have
// already been validated.

func (e *Enforcer) hasAnyRoleOn(ctx context.Context, c *auth.Claims, resource string, roles []string) (bool, error) {
	if c == nil {
		return false, ErrNoClaims
	}
	if !e.s.ScopedRolesOnly {
		ok, err := e.hasAnyRole(ctx, c, roles)
		if err = ignoreNoRoleStore(err); err != nil || ok {
			return ok, err
		}
	}
	return e.boundHasAnyRole(ctx, c.Subject, resource, roles)
}

func (e *Enforcer) canOn(ctx context.Context, c *auth.Claims, resource string, perms []string, all bool) (bool, error) {
	if c == nil {
		return false, ErrNoClaims
	}
	global := noGrants
	if !e.s.ScopedRolesOnly {
		var err error
		if global, err = e.grantsFromClaims(ctx, c); err != nil {
			if err = ignoreNoRoleStore(err); err != nil {
				return false, err
			}
			global = noGrants
		}
	}
	return e.scopedCan(ctx, c.Subject, resource, perms, all, global)
}

// scopedCan checks perms against the global grants first, and looks up
// subject's bindings on resource only for what they leave unanswered.
func (e *Enforcer) scopedCan(ctx context.Context, subject, resource string, perms []string, all bool, global func(string) bool) (bool, error) {
	remaining := slices.DeleteFunc(slices.Clone(perms), global)
	if len(remaining) == 0 || (!all && len(remaining) < len(perms)) {
		return true, nil
	}
	bound, err := e.boundRoles(ctx, subject, resource)
	if err != nil || len(bound) == 0 {
		return false, err
	}
	policy, err := e.loadPolicy(ctx) // configured, or the check was rejected
	if err != nil {
		return false, err
	}
	allows := func(perm string) bool { return policy.allows(bound, perm) }
	if all {
		return !slices.ContainsFunc(remaining, func(p string) bool { return !allows(p) }), nil
	}
	return slices.ContainsFunc(remaining, allows), nil
}

// boundHasAnyRole reports whether subject's bindings on resource give it any
// of roles, directly or, if a policy is configured, through inheritance.
func (e *Enforcer) boundHasAnyRole(ctx context.Context, subject, resource string, roles []string) (bool, error) {
	bound, err := e.boundRoles(ctx, subject, resource)
	if err != nil || len(bound) == 0 {
		return false, err
	}
	if containsAny(bound, roles) {
		return true, nil
	}
	if e.s.policy == nil {
		return false, nil
	}
	policy, err := e.loadPolicy(ctx)
	if err != nil {
		return false, err
	}
	return containsAny(policy.EffectiveRoles(bound...), roles), nil
}

// boundRoles returns the roles bound to subject on any scope that applies to
// resource, not expanded through the policy. Invalid scopes from the
// resolver, invalid bindings from the store and store errors wrapping
// [ErrInvalidScope] are internal errors, so they are reported without
// wrapping it.
func (e *Enforcer) boundRoles(ctx context.Context, subject, resource string) ([]string, error) {
	scopes, err := e.s.scopeResolver.Scopes(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("rbac: resolving scopes of %q: %w", resource, err)
	}
	for _, s := range scopes {
		if err := ValidateScope(s); err != nil {
			return nil, fmt.Errorf("rbac: scope resolver returned an invalid scope for %q: %v", resource, err)
		}
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	bindings, err := e.s.scopedStore.Bindings(ctx, subject, slices.Clone(scopes))
	if errors.Is(err, ErrInvalidScope) {
		// The resource was already validated, so this is the store's fault.
		return nil, fmt.Errorf("rbac: loading bindings: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: loading bindings: %w", err)
	}
	for _, b := range bindings {
		if err := validateBinding(b); err != nil {
			return nil, fmt.Errorf("rbac: scoped role store returned an invalid binding for %q: %v", subject, err)
		}
	}
	return scopeRoles(bindings, scopes), nil
}
