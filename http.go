package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/tpyle/auth/v2"
)

// Middleware wraps an [http.Handler].
type Middleware func(http.Handler) http.Handler

// RequireAnyRole returns middleware that only admits requests whose user has
// at least one of roles (see [Enforcer.HasAnyRole]). It panics if roles is
// empty or contains an invalid name, or if the enforcer has neither a
// [RoleStore] nor embedded roles to answer it, since those are programming
// errors.
//
// Mount it inside [auth.Authorizer.RequireAuthHandler] or
// [auth.Authorizer.AuthHandler], which put the verified claims in the
// request context. Rejected requests go to the [ErrorHandler].
func (e *Enforcer) RequireAnyRole(roles ...string) Middleware {
	roles = slices.Clone(roles)
	mustValid(firstErr(checkRoles(roles), e.s.caps.roles))
	return e.require(func(r *http.Request, c *auth.Claims) (bool, error) {
		return e.hasAnyRole(r.Context(), c, roles)
	})
}

// RequireAllPermissions returns middleware that only admits requests whose
// user holds every one of perms (see [Enforcer.CanAll]). It panics if perms
// is empty or contains a permission that is not concrete, or if the enforcer
// has neither a [RoleStore] nor embedded claims to answer it. See
// [Enforcer.RequireAnyRole] for where to mount it.
func (e *Enforcer) RequireAllPermissions(perms ...string) Middleware {
	perms = slices.Clone(perms)
	mustValid(firstErr(checkPermissions(perms), e.s.caps.permissions))
	return e.require(func(r *http.Request, c *auth.Claims) (bool, error) {
		return e.canAll(r.Context(), c, perms)
	})
}

// RequireAnyPermission returns middleware that only admits requests whose
// user holds at least one of perms (see [Enforcer.CanAny]). It panics as
// [Enforcer.RequireAllPermissions] does. See [Enforcer.RequireAnyRole] for
// where to mount it.
func (e *Enforcer) RequireAnyPermission(perms ...string) Middleware {
	perms = slices.Clone(perms)
	mustValid(firstErr(checkPermissions(perms), e.s.caps.permissions))
	return e.require(func(r *http.Request, c *auth.Claims) (bool, error) {
		return e.canAny(r.Context(), c, perms)
	})
}

// ResourceFunc extracts the resource a request acts on, for scoped
// middleware such as [Enforcer.RequireAllPermissionsOn]. An error wrapping
// [ErrInvalidScope] is answered with 400 by the default [ErrorHandler];
// other errors with 500. See [PathResource] for the common case.
type ResourceFunc func(r *http.Request) (string, error)

// RequireAnyRoleOn returns middleware that only admits requests whose user
// has at least one of roles on the resource named by resource (see
// [Enforcer.HasAnyRoleOn]). It panics if no [ScopedRoleStore] is
// configured, if resource is nil, or if roles is empty or contains an
// invalid name. See [Enforcer.RequireAnyRole] for where to mount it.
func (e *Enforcer) RequireAnyRoleOn(resource ResourceFunc, roles ...string) Middleware {
	roles = slices.Clone(roles)
	mustValid(firstErr(checkRoles(roles), e.s.caps.scopedRoles))
	return e.requireOn(resource, func(ctx context.Context, c *auth.Claims, res string) (bool, error) {
		return e.hasAnyRoleOn(ctx, c, res, roles)
	})
}

// RequireAllPermissionsOn returns middleware that only admits requests
// whose user holds every one of perms on the resource named by resource (see
// [Enforcer.CanAllOn]). It panics if no [ScopedRoleStore] or policy is
// configured, if resource is nil, or if perms is empty or contains a
// permission that is not concrete. See [Enforcer.RequireAnyRole] for where to mount it.
func (e *Enforcer) RequireAllPermissionsOn(resource ResourceFunc, perms ...string) Middleware {
	return e.requirePermissionsOn(resource, perms, true)
}

// RequireAnyPermissionOn returns middleware that only admits requests whose
// user holds at least one of perms on the resource named by resource (see
// [Enforcer.CanAnyOn]). It panics as [Enforcer.RequireAllPermissionsOn]
// does.
func (e *Enforcer) RequireAnyPermissionOn(resource ResourceFunc, perms ...string) Middleware {
	return e.requirePermissionsOn(resource, perms, false)
}

func (e *Enforcer) requirePermissionsOn(resource ResourceFunc, perms []string, all bool) Middleware {
	perms = slices.Clone(perms)
	mustValid(firstErr(checkPermissions(perms), e.s.caps.scopedPermissions))
	return e.requireOn(resource, func(ctx context.Context, c *auth.Claims, res string) (bool, error) {
		return e.canOn(ctx, c, res, perms, all)
	})
}

// requireOn builds scoped middleware around a check of the resource named
// by resource. It panics if resource is nil.
func (e *Enforcer) requireOn(resource ResourceFunc, check func(ctx context.Context, c *auth.Claims, res string) (bool, error)) Middleware {
	if resource == nil {
		panic("rbac: nil ResourceFunc")
	}
	return e.require(func(r *http.Request, c *auth.Claims) (bool, error) {
		res, err := requestResource(r, resource)
		if err != nil {
			return false, err
		}
		return check(r.Context(), c, res)
	})
}

// requestResource calls f and checks that its result is a concrete scope.
func requestResource(r *http.Request, f ResourceFunc) (string, error) {
	res, err := f(r)
	if err != nil {
		return "", fmt.Errorf("rbac: identifying resource: %w", err)
	}
	if err := ValidateScope(res); err != nil {
		return "", err
	}
	return res, nil
}

// PathResource returns a [ResourceFunc] that builds the resource from
// pattern, replacing each "{name}" with the request's path value name (see
// [http.Request.PathValue]). It pairs with [http.ServeMux] patterns:
//
//	mux.Handle("PUT /projects/{project}/docs/{doc}",
//		e.RequireAllPermissionsOn(rbac.PathResource("projects/{project}/docs/{doc}"), "docs:write")(h))
//
// Path values are unescaped, so a request for "/projects/42%2Fdocs/docs/1"
// has the project value "42/docs". A value for "{name}" containing
// [ScopeSeparator] is therefore rejected, since it would change which scopes
// are the resource's ancestors. Write "{name...}" to allow several segments,
// as for a ServeMux "{name...}" wildcard.
//
// Each placeholder must be a whole segment of pattern, and a "{name...}"
// placeholder must end it, so that different requests can't build the same
// resource ("{org}{team}" would make org 4, team 27 and org 42, team 7 the
// same). Placeholder names follow ServeMux's rules.
//
// A request whose path value is empty, contains a separator where not
// allowed, or yields an invalid scope (see [ValidateScope]) is rejected with
// [ErrInvalidScope]. PathResource panics if pattern has unbalanced braces,
// breaks the placeholder rules above, or would not be a valid scope with
// its placeholders filled in, since that is a programming error.
func PathResource(pattern string) ResourceFunc {
	// The resource is literals[0] + holders[0] + literals[1] + ... + the
	// last literal.
	type placeholder struct {
		name  string
		multi bool // may span several segments
	}
	var literals []string
	var holders []placeholder
	rest := pattern
	for {
		open := strings.IndexAny(rest, "{}")
		if open < 0 {
			literals = append(literals, rest)
			break
		}
		if rest[open] == '}' {
			panic(fmt.Sprintf("rbac: PathResource(%q): unbalanced braces", pattern))
		}
		end := strings.IndexAny(rest[open+1:], "{}")
		if end < 0 || rest[open+1+end] == '{' {
			panic(fmt.Sprintf("rbac: PathResource(%q): unbalanced braces", pattern))
		}
		name, multi := strings.CutSuffix(rest[open+1:open+1+end], "...")
		if !isWildcardName(name) {
			panic(fmt.Sprintf("rbac: PathResource(%q): invalid placeholder name %q", pattern, name))
		}
		literals = append(literals, rest[:open])
		holders = append(holders, placeholder{name, multi})
		rest = rest[open+1+end+1:]
	}
	// Each placeholder must be a whole segment, and only the last may span
	// several, or different requests could build the same resource:
	// "{a}{b}" or "{a}-{b}" are ambiguous whatever the separator.
	for i, h := range holders {
		before, after := literals[i], literals[i+1]
		last := i == len(holders)-1
		// Only the pattern's start and end may be empty: elsewhere, an empty
		// literal means two placeholders are adjacent.
		startsSegment := i == 0 && before == "" || strings.HasSuffix(before, ScopeSeparator)
		endsSegment := last && after == "" || strings.HasPrefix(after, ScopeSeparator)
		if !startsSegment || !endsSegment {
			panic(fmt.Sprintf("rbac: PathResource(%q): placeholder %q is not a whole segment", pattern, h.name))
		}
		if h.multi && (!last || after != "") {
			panic(fmt.Sprintf("rbac: PathResource(%q): placeholder %q... must end the pattern", pattern, h.name))
		}
	}
	fill := func(value func(placeholder) string) string {
		var b strings.Builder
		for i, lit := range literals {
			b.WriteString(lit)
			if i < len(holders) {
				b.WriteString(value(holders[i]))
			}
		}
		return b.String()
	}
	if err := ValidateScope(fill(func(placeholder) string { return "x" })); err != nil {
		panic(fmt.Sprintf("rbac: PathResource(%q): %v", pattern, err))
	}
	return func(r *http.Request) (string, error) {
		var bad error
		res := fill(func(p placeholder) string {
			v := r.PathValue(p.name)
			switch {
			case bad != nil:
			case v == "":
				bad = fmt.Errorf("%w: path value %q is empty", ErrInvalidScope, p.name)
			case !p.multi && strings.Contains(v, ScopeSeparator):
				bad = fmt.Errorf("%w: path value %q contains %q", ErrInvalidScope, p.name, ScopeSeparator)
			}
			return v
		})
		if bad != nil {
			return "", bad
		}
		return res, nil
	}
}

// isWildcardName reports whether name is valid as a ServeMux wildcard name:
// a Go identifier, which excludes the "{$}" end-of-path marker.
func isWildcardName(name string) bool {
	for i, r := range name {
		if r != '_' && !unicode.IsLetter(r) && (i == 0 || !unicode.IsDigit(r)) {
			return false
		}
	}
	return name != ""
}

func mustValid(err error) {
	if err != nil {
		panic(err)
	}
}

// require builds middleware around a check whose static arguments were
// validated when the middleware was created.
func (e *Enforcer) require(check func(*http.Request, *auth.Claims) (bool, error)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok := false
			c, err := claimsFromContext(r.Context())
			if err == nil {
				ok, err = check(r, c)
			}
			if err == nil && !ok {
				err = ErrForbidden
			}
			if err != nil {
				e.logCheckError(r, err)
				e.s.errorHandler(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// logCheckError logs err if it is an internal error. A check abandoned
// because the client went away is not one, so it is logged at debug level.
func (e *Enforcer) logCheckError(r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNoClaims), errors.Is(err, ErrForbidden), errors.Is(err, ErrInvalidScope):
	case errors.Is(err, context.Canceled) && errors.Is(r.Context().Err(), context.Canceled):
		e.s.logger.DebugContext(r.Context(), "rbac: request cancelled during access check", "error", err)
	default:
		e.s.logger.ErrorContext(r.Context(), "rbac: checking access", "error", err)
	}
}

// defaultErrorHandler writes a JSON 401 for unauthenticated requests, 403
// for denied ones, 400 for requests naming an invalid resource and 500 for
// internal errors, without exposing details.
func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	switch {
	case errors.Is(err, ErrNoClaims):
		status, code = http.StatusUnauthorized, "unauthorized"
		w.Header().Set("WWW-Authenticate", "Bearer")
	case errors.Is(err, ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrInvalidScope):
		status, code = http.StatusBadRequest, "bad_request"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", code)
}
