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
	// Wildcard, used as a whole segment of a grant or scope pattern, matches
	// exactly one segment.
	Wildcard = "*"
	// MultiWildcard, used as a whole segment of a grant or scope pattern,
	// matches zero or more segments.
	MultiWildcard = "**"
)

// ValidatePermission reports whether perm is a valid concrete permission:
// one or more non-empty segments separated by [PermissionSeparator], with no
// whitespace and no wildcards. Permissions passed to checks such as
// [Enforcer.Can] must be concrete.
func ValidatePermission(perm string) error {
	return validatePattern(perm, PermissionSeparator, false, ErrInvalidPermission)
}

// ValidateGrant reports whether grant is a valid permission grant: like a
// concrete permission (see [ValidatePermission]), except that any segment
// may be exactly [Wildcard] or [MultiWildcard]. Two [MultiWildcard] segments
// in a row are rejected as redundant. Grants are what roles hold and what
// tokens carry.
func ValidateGrant(grant string) error {
	return validatePattern(grant, PermissionSeparator, true, ErrInvalidPermission)
}

// validatePattern checks the syntax shared by permissions and scopes, which
// differ only in their separator. Errors wrap errInvalid.
func validatePattern(s, sep string, allowWildcards bool, errInvalid error) error {
	if s == "" {
		return fmt.Errorf("%w: empty", errInvalid)
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return fmt.Errorf("%w: %q contains whitespace", errInvalid, s)
	}
	prevMulti := false
	for seg := range strings.SplitSeq(s, sep) {
		wild := seg == Wildcard || seg == MultiWildcard
		switch {
		case seg == "":
			return fmt.Errorf("%w: %q has an empty segment", errInvalid, s)
		case wild && !allowWildcards:
			return fmt.Errorf("%w: %q must not contain wildcards", errInvalid, s)
		case !wild && strings.Contains(seg, Wildcard):
			return fmt.Errorf("%w: %q: wildcards must be whole segments", errInvalid, s)
		case seg == MultiWildcard && prevMulti:
			return fmt.Errorf("%w: %q has consecutive %q segments", errInvalid, s, MultiWildcard)
		}
		prevMulti = seg == MultiWildcard
	}
	return nil
}

// Grants reports whether grant permits the concrete permission perm. Both
// should be valid (see [ValidateGrant] and [ValidatePermission]); input with
// an empty segment, including the empty string, is never granted. Other
// invalid input is not detected.
//
// A [Wildcard] segment matches exactly one segment and a [MultiWildcard]
// segment matches zero or more, in any position:
//
//	Grants("posts:*", "posts:read")              // true
//	Grants("posts:*", "posts:comments:delete")   // false
//	Grants("posts:**", "posts:comments:delete")  // true
//	Grants("posts:**", "posts")                  // true
//	Grants("posts:*:read", "posts:drafts:read")  // true
//	Grants("**:read", "posts:drafts:read")       // true
//	Grants("**", "anything:at:all")              // true
func Grants(grant, perm string) bool {
	return matchSegments(grant, perm, PermissionSeparator)
}

// matchSegments reports whether pattern matches value, both split into
// segments by sep. It is a glob match over segments: [Wildcard] matches one
// segment and [MultiWildcard] any run of segments. On a mismatch it
// backtracks to the most recent [MultiWildcard] and lets it absorb one more
// segment, which is enough because earlier ones can only absorb less. It
// does not allocate, since it runs on every check.
//
// A [Wildcard] in pattern does not match a [MultiWildcard] in value, so
// passing a pattern as value asks whether pattern covers everything it
// matches (see [minimalGrants]).
func matchSegments(pattern, value, sep string) bool {
	pi, vi := 0, 0
	// Where the pattern resumes after its last MultiWildcard, and the value
	// position that MultiWildcard has absorbed up to. starPi < 0 means none.
	starPi, starVi := -1, 0
	for vi <= len(value) {
		vseg, vnext := segmentAt(value, vi, sep)
		if vseg == "" {
			return false
		}
		if pi <= len(pattern) {
			pseg, pnext := segmentAt(pattern, pi, sep)
			if pseg == MultiWildcard {
				starPi, starVi = pnext, vi
				pi = pnext
				continue
			}
			if pseg != "" && (pseg == vseg || (pseg == Wildcard && vseg != MultiWildcard)) {
				pi, vi = pnext, vnext
				continue
			}
		}
		if starPi < 0 {
			return false
		}
		_, starVi = segmentAt(value, starVi, sep)
		pi, vi = starPi, starVi
	}
	// The value is used up, so the rest of the pattern must match nothing.
	for pi <= len(pattern) {
		pseg, pnext := segmentAt(pattern, pi, sep)
		if pseg != MultiWildcard {
			return false
		}
		pi = pnext
	}
	return true
}

// segmentAt returns the segment of s starting at byte offset i and the
// offset of the next one. Offsets past len(s) mean s is used up, so "a:"
// has the segments "a" and "".
func segmentAt(s string, i int, sep string) (seg string, next int) {
	end := strings.Index(s[i:], sep)
	if end < 0 {
		return s[i:], len(s) + 1
	}
	return s[i : i+end], i + end + len(sep)
}

// minimalGrants returns grants without those another grant already covers,
// such as "posts:read" alongside "posts:*", keeping embedded claims small.
// grants must be valid, sorted and free of duplicates. Treating a grant as a
// permission, Grants(h, g) reports whether h permits everything g does: a
// wildcard in g is only matched by the same wildcard or a [MultiWildcard] in
// h. The test is conservative: it may keep a redundant grant, such as
// "*:**" beside "**:*", but never drops a needed one.
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
