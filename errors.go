package rbac

import "errors"

// Errors returned by the package. They may be wrapped, so compare them with
// [errors.Is].
var (
	// ErrNoClaims means no [Claims] were found: the [ClaimsSource] found
	// none in the context, usually because the request was not
	// authenticated, or nil claims were passed to a check.
	ErrNoClaims = errors.New("rbac: no claims in context")

	// ErrForbidden is passed to the [ErrorHandler] when an authenticated
	// request lacks the required roles or permissions.
	ErrForbidden = errors.New("rbac: forbidden")

	// ErrMalformedClaim means a token carries a roles or permissions claim
	// that is not an array of valid names. The token is not trusted to fall
	// back to the [RoleStore], because the claim being present means the
	// issuer intended it to be authoritative.
	ErrMalformedClaim = errors.New("rbac: malformed claim")

	// ErrInvalidPermission means a permission string is malformed (see
	// [ValidatePermission] and [ValidateGrant]).
	ErrInvalidPermission = errors.New("rbac: invalid permission")

	// ErrInvalidRole means a role name is empty or contains whitespace.
	ErrInvalidRole = errors.New("rbac: invalid role")

	// ErrInvalidScope means a resource or scope is malformed (see
	// [ValidateScope] and [ValidateScopePattern]). The default
	// [ErrorHandler] answers it with 400, since it usually means a request
	// named a resource that cannot exist.
	ErrInvalidScope = errors.New("rbac: invalid scope")

	// ErrUnknownRole means a role definition inherits from a role that is
	// not defined in the policy.
	ErrUnknownRole = errors.New("rbac: unknown role")

	// ErrRoleCycle means role inheritance contains a cycle.
	ErrRoleCycle = errors.New("rbac: role inheritance cycle")

	// ErrInvalidPolicy means a policy file could not be decoded.
	ErrInvalidPolicy = errors.New("rbac: invalid policy")

	// ErrNotConfigured means a check needs a [RoleStore], [ScopedRoleStore]
	// or [Policy] that was not supplied to [New], for example because a
	// token lacked the claims that would have made the lookup unnecessary.
	ErrNotConfigured = errors.New("rbac: not configured")

	// ErrNilPolicy means a [PolicyProvider] returned no policy and no error.
	// Checks fail rather than treating the missing policy as granting
	// nothing, which would deny every request without explanation.
	ErrNilPolicy = errors.New("rbac: policy provider returned a nil policy")
)
