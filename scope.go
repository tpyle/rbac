package rbac

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ScopeSeparator separates the segments of a scope, as in
// "projects/42/docs/7". Scope patterns use the same [Wildcard] and
// [MultiWildcard] segments as permission grants.
const ScopeSeparator = "/"

// ValidateScope reports whether s is a valid concrete scope: one or more
// non-empty segments separated by [ScopeSeparator], with no whitespace, no
// wildcards and no "." or ".." segments. Resources passed to scoped checks
// such as [Enforcer.CanOn], and scopes returned by a [ScopeResolver], must
// be concrete. Errors wrap [ErrInvalidScope].
//
// Dot segments are rejected because a resource such as
// "projects/42/../43" has "projects/42" as an ancestor for [PathScopes]
// while an application resolving the path would act on project 43.
func ValidateScope(s string) error {
	return validateScope(s, false)
}

// ValidateScopePattern reports whether s is a valid scope pattern, as used
// in a [Binding]: like a concrete scope (see [ValidateScope]), except that
// any segment may be exactly [Wildcard] or [MultiWildcard]. Two
// [MultiWildcard] segments in a row are rejected as redundant.
func ValidateScopePattern(s string) error {
	return validateScope(s, true)
}

func validateScope(s string, allowWildcards bool) error {
	if err := validatePattern(s, ScopeSeparator, allowWildcards, ErrInvalidScope); err != nil {
		return err
	}
	for seg := range strings.SplitSeq(s, ScopeSeparator) {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q has a %q segment", ErrInvalidScope, s, seg)
		}
	}
	return nil
}

// MatchScope reports whether the scope pattern matches the concrete scope.
// It follows the same rules as [Grants], with [ScopeSeparator] between
// segments:
//
//	MatchScope("projects/*/docs", "projects/42/docs")                 // true
//	MatchScope("projects/*", "projects/42/docs")                      // false
//	MatchScope("projects/**/comments", "projects/comments")           // true
//	MatchScope("projects/**/comments", "projects/42/docs/7/comments") // true
//
// A pattern matches a scope, not the scope's descendants. Bindings still
// cover descendants because [PathScopes] lists a resource's ancestors as
// scopes too: a binding on "projects/*/docs" applies to "projects/42/docs/7"
// because it matches the ancestor "projects/42/docs".
func MatchScope(pattern, scope string) bool {
	return matchSegments(pattern, scope, ScopeSeparator)
}

// Binding grants Role to a subject on every scope matching Scope, a scope
// pattern (see [ValidateScopePattern]).
type Binding struct {
	Scope string `json:"scope" yaml:"scope"`
	Role  string `json:"role" yaml:"role"`
}

// ScopedRoleStore is the source of truth for the roles users hold on
// individual resources or groups of resources, typically a database table of
// (subject, scope, role) rows. Scoped bindings are never embedded in tokens,
// so scoped checks that global grants do not answer call it every time.
type ScopedRoleStore interface {
	// Bindings returns subject's bindings that may apply to scopes. It must
	// return at least every binding of subject whose scope is one of scopes
	// or contains a wildcard. It may return more: every result is matched
	// against scopes with [MatchScope], so returning all of subject's
	// bindings is a correct, if slower, implementation. An unknown subject
	// has no bindings and should return an empty slice and a nil error.
	Bindings(ctx context.Context, subject string, scopes []string) ([]Binding, error)
}

// ScopedRoleStoreFunc adapts a function to a [ScopedRoleStore].
type ScopedRoleStoreFunc func(ctx context.Context, subject string, scopes []string) ([]Binding, error)

// Bindings implements [ScopedRoleStore].
func (f ScopedRoleStoreFunc) Bindings(ctx context.Context, subject string, scopes []string) ([]Binding, error) {
	return f(ctx, subject, scopes)
}

// ScopeResolver lists the scopes whose bindings apply to a resource: the
// resource itself and every group it belongs to, such as a parent folder, a
// project or a tag. The default is [PathScopes].
//
// Returned scopes must be concrete (see [ValidateScope]). An error wrapping
// [ErrInvalidScope] tells middleware the request named a bad resource (400);
// other errors are internal (500).
type ScopeResolver interface {
	Scopes(ctx context.Context, resource string) ([]string, error)
}

// ScopeResolverFunc adapts a function to a [ScopeResolver].
type ScopeResolverFunc func(ctx context.Context, resource string) ([]string, error)

// Scopes implements [ScopeResolver].
func (f ScopeResolverFunc) Scopes(ctx context.Context, resource string) ([]string, error) {
	return f(ctx, resource)
}

type pathScopes struct{}

// PathScopes returns a [ScopeResolver] for hierarchical resource names. It
// returns the resource followed by each of its ancestors, so that a binding
// on a scope applies to everything beneath it:
//
//	"projects/42/docs/7" -> ["projects/42/docs/7", "projects/42/docs", "projects/42", "projects"]
//
// Resources that are not concrete scopes are rejected with
// [ErrInvalidScope].
func PathScopes() ScopeResolver {
	return pathScopes{}
}

func (pathScopes) Scopes(_ context.Context, resource string) ([]string, error) {
	if err := ValidateScope(resource); err != nil {
		return nil, err
	}
	scopes := []string{resource}
	for i := strings.LastIndex(resource, ScopeSeparator); i >= 0; i = strings.LastIndex(resource, ScopeSeparator) {
		resource = resource[:i]
		scopes = append(scopes, resource)
	}
	return scopes, nil
}

// scopeRoles returns the roles of the bindings whose scope pattern matches
// any of scopes, sorted and without duplicates.
func scopeRoles(bindings []Binding, scopes []string) []string {
	var roles []string
	for _, b := range bindings {
		var applies bool
		if strings.Contains(b.Scope, Wildcard) {
			applies = slices.ContainsFunc(scopes, func(s string) bool { return MatchScope(b.Scope, s) })
		} else {
			applies = slices.Contains(scopes, b.Scope)
		}
		if applies {
			roles = append(roles, b.Role)
		}
	}
	return sortedUnique(roles)
}

// validateBinding reports whether b has a valid scope pattern and role.
func validateBinding(b Binding) error {
	if err := ValidateScopePattern(b.Scope); err != nil {
		return err
	}
	if err := validateRole(b.Role); err != nil {
		return fmt.Errorf("scope %q: %w", b.Scope, err)
	}
	return nil
}
