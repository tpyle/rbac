package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/tpyle/auth/v2"
)

// Middleware wraps an [http.Handler].
type Middleware func(http.Handler) http.Handler

// RequireAnyRole returns middleware that only admits requests whose user has
// at least one of roles (see [Enforcer.HasAnyRole]). It panics if roles is
// empty or contains an invalid name, since that is a programming error.
//
// Mount it inside [auth.Authorizer.RequireAuthHandler] or
// [auth.Authorizer.AuthHandler], which put the verified claims in the
// request context. Rejected requests go to the [ErrorHandler].
func (e *Enforcer) RequireAnyRole(roles ...string) Middleware {
	roles = slices.Clone(roles)
	mustValid(checkRoles(roles))
	return e.require(func(ctx context.Context, c *auth.Claims) (bool, error) {
		return e.hasAnyRole(ctx, c, roles)
	})
}

// RequireAllPermissions returns middleware that only admits requests whose
// user holds every one of perms (see [Enforcer.CanAll]). It panics if perms
// is empty or contains a permission that is not concrete. See
// [Enforcer.RequireAnyRole] for where to mount it.
func (e *Enforcer) RequireAllPermissions(perms ...string) Middleware {
	perms = slices.Clone(perms)
	mustValid(checkPermissions(perms))
	return e.require(func(ctx context.Context, c *auth.Claims) (bool, error) {
		return e.canAll(ctx, c, perms)
	})
}

// RequireAnyPermission returns middleware that only admits requests whose
// user holds at least one of perms (see [Enforcer.CanAny]). It panics if
// perms is empty or contains a permission that is not concrete. See
// [Enforcer.RequireAnyRole] for where to mount it.
func (e *Enforcer) RequireAnyPermission(perms ...string) Middleware {
	perms = slices.Clone(perms)
	mustValid(checkPermissions(perms))
	return e.require(func(ctx context.Context, c *auth.Claims) (bool, error) {
		return e.canAny(ctx, c, perms)
	})
}

func mustValid(err error) {
	if err != nil {
		panic(err)
	}
}

// require builds middleware around a check whose arguments were validated
// when the middleware was created.
func (e *Enforcer) require(check func(context.Context, *auth.Claims) (bool, error)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok := false
			c, err := claimsFromContext(r.Context())
			if err == nil {
				ok, err = check(r.Context(), c)
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
	case errors.Is(err, ErrNoClaims), errors.Is(err, ErrForbidden):
	case errors.Is(err, context.Canceled) && errors.Is(r.Context().Err(), context.Canceled):
		e.s.logger.DebugContext(r.Context(), "rbac: request cancelled during access check", "error", err)
	default:
		e.s.logger.ErrorContext(r.Context(), "rbac: checking access", "error", err)
	}
}

// defaultErrorHandler writes a JSON 401 for unauthenticated requests, 403
// for denied ones and 500 for internal errors, without exposing details.
func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	switch {
	case errors.Is(err, ErrNoClaims):
		status, code = http.StatusUnauthorized, "unauthorized"
		w.Header().Set("WWW-Authenticate", "Bearer")
	case errors.Is(err, ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", code)
}
