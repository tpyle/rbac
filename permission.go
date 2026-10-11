package rbac

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Permission syntax.
const (
	// PermissionSeparator separates the segments of a permission, as in
	// "posts:comments:delete".
	PermissionSeparator = ":"
	// Wildcard, used as a whole segment of a grant, matches any segment. As
	// the last segment it matches one or more remaining segments.
	Wildcard = "*"
)

// ValidatePermission reports whether perm is a valid concrete permission:
// one or more non-empty segments separated by [PermissionSeparator], with no
// whitespace and no [Wildcard]. Permissions passed to checks such as
// [Enforcer.Can] must be concrete.
func ValidatePermission(perm string) error {
	return validatePermission(perm, false)
}

// ValidateGrant reports whether grant is a valid permission grant: like a
// concrete permission (see [ValidatePermission]), except that any segment
// may be exactly [Wildcard]. Grants are what roles hold and what tokens
// carry.
func ValidateGrant(grant string) error {
	return validatePermission(grant, true)
}

func validatePermission(p string, allowWildcard bool) error {
	if p == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPermission)
	}
	if strings.ContainsFunc(p, unicode.IsSpace) {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidPermission, p)
	}
	for seg := range strings.SplitSeq(p, PermissionSeparator) {
		switch {
		case seg == "":
			return fmt.Errorf("%w: %q has an empty segment", ErrInvalidPermission, p)
		case seg == Wildcard && !allowWildcard:
			return fmt.Errorf("%w: %q must not contain wildcards", ErrInvalidPermission, p)
		case seg != Wildcard && strings.Contains(seg, Wildcard):
			return fmt.Errorf("%w: %q: wildcards must be whole segments", ErrInvalidPermission, p)
		}
	}
	return nil
}

// Grants reports whether grant permits the concrete permission perm. Both
// should be valid (see [ValidateGrant] and [ValidatePermission]); input with
// an empty segment, including the empty string, is never granted. Other
// invalid input is not detected.
//
// A [Wildcard] segment matches any one segment, except in last position,
// where it matches one or more segments:
//
//	Grants("posts:*", "posts:read")              // true
//	Grants("posts:*", "posts:comments:delete")   // true
//	Grants("posts:*", "posts")                   // false
//	Grants("posts:*:read", "posts:drafts:read")  // true
//	Grants("*", "anything:at:all")               // true
func Grants(grant, perm string) bool {
	// Walk both strings segment by segment without allocating, since this
	// runs on every check.
	for {
		g, gRest, gMore := strings.Cut(grant, PermissionSeparator)
		if g == Wildcard && !gMore {
			return perm != ""
		}
		p, pRest, pMore := strings.Cut(perm, PermissionSeparator)
		if g == "" || p == "" {
			return false
		}
		if g != Wildcard && g != p {
			return false
		}
		if !gMore || !pMore {
			return gMore == pMore
		}
		grant, perm = gRest, pRest
	}
}

// minimalGrants returns grants without those another grant already covers,
// such as "posts:read" alongside "posts:*", keeping embedded claims small.
// grants must be valid, sorted and free of duplicates. Treating a grant as a
// permission, Grants(h, g) reports whether h permits everything g does: a
// wildcard in g only matches a wildcard in h, and a trailing wildcard in g
// is only matched by one at the same or an earlier position in h.
//
// Only a grant with a wildcard can cover a different grant, so each grant is
// compared against those alone.
func minimalGrants(grants []string) []string {
	var patterns []string
	for _, g := range grants {
		if strings.Contains(g, Wildcard) {
			patterns = append(patterns, g)
		}
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		covered := slices.ContainsFunc(patterns, func(h string) bool { return h != g && Grants(h, g) })
		if !covered {
			out = append(out, g)
		}
	}
	return out
}

// grantSet is a set of grants optimized for checking concrete permissions.
type grantSet struct {
	exact    map[string]bool
	patterns []string
}

func newGrantSet(grants []string) grantSet {
	s := grantSet{exact: make(map[string]bool, len(grants))}
	for _, g := range grants {
		if strings.Contains(g, Wildcard) {
			s.patterns = append(s.patterns, g)
		} else {
			s.exact[g] = true
		}
	}
	return s
}

// allows reports whether the set permits the concrete permission perm.
func (s grantSet) allows(perm string) bool {
	if s.exact[perm] {
		return true
	}
	for _, g := range s.patterns {
		if Grants(g, perm) {
			return true
		}
	}
	return false
}

// validateRole reports whether name is a valid role name.
func validateRole(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrInvalidRole)
	}
	if strings.ContainsFunc(name, unicode.IsSpace) {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidRole, name)
	}
	return nil
}
