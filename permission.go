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
//
// grant may also carry exceptions, in the form [Policy.Permissions] returns
// and permission claims hold: the grant followed by space-separated
// patterns, each prefixed with "-". It then permits what the grant matches
// and no exception does:
//
//	Grants("files:* -files:delete", "files:read")    // true
//	Grants("files:* -files:delete", "files:delete")  // false
//
// A grant whose exceptions are malformed permits nothing.
func Grants(grant, perm string) bool {
	pattern, excepts, hasExcepts := strings.Cut(grant, exceptSeparator)
	if !matchSegments(pattern, perm, PermissionSeparator) {
		return false
	}
	for hasExcepts {
		var item string
		item, excepts, hasExcepts = strings.Cut(excepts, exceptSeparator)
		except, ok := strings.CutPrefix(item, exceptPrefix)
		if !ok || except == "" || matchSegments(except, perm, PermissionSeparator) {
			return false
		}
	}
	return true
}

// The syntax of a grant with exceptions, "files:* -files:delete".
const (
	exceptSeparator = " "
	exceptPrefix    = "-"
)

// validateGrantExpr reports whether s is a valid grant with optional
// exceptions (see [Grants]), as held by permission claims. The grant and
// each exception must be valid grants (see [ValidateGrant]), separated by
// single spaces.
func validateGrantExpr(s string) error {
	grant, excepts, hasExcepts := strings.Cut(s, exceptSeparator)
	if err := ValidateGrant(grant); err != nil {
		return err
	}
	for hasExcepts {
		var item string
		item, excepts, hasExcepts = strings.Cut(excepts, exceptSeparator)
		except, ok := strings.CutPrefix(item, exceptPrefix)
		if !ok {
			return fmt.Errorf("%w: %q: exceptions must start with %q", ErrInvalidPermission, s, exceptPrefix)
		}
		if err := ValidateGrant(except); err != nil {
			return fmt.Errorf("%w: in %q", err, s)
		}
	}
	return nil
}

// term is a grant with the exceptions that apply to it, the flattened form
// of a role's permissions.
type term struct {
	grant   string
	excepts []string
}

// simplify returns t without exceptions that cannot affect it, and false if
// an exception covers the whole grant so t permits nothing. Like
// [minimalGrants] it is conservative: it may keep an exception that
// matches nothing the grant does, but never drops one that does.
func (t term) simplify() (term, bool) {
	grantWild := strings.Contains(t.grant, Wildcard)
	var kept []string
	for _, e := range t.excepts {
		// With t.grant as the value, this asks whether e covers it (see
		// matchSegments).
		if matchSegments(e, t.grant, PermissionSeparator) {
			return term{}, false
		}
		switch {
		case !grantWild:
			// A concrete grant is either covered, above, or untouched.
		case !strings.Contains(e, Wildcard):
			if matchSegments(t.grant, e, PermissionSeparator) {
				kept = append(kept, e)
			}
		default:
			kept = append(kept, e)
		}
	}
	return term{grant: t.grant, excepts: minimalGrants(sortedUnique(kept))}, true
}

// String renders t in the form [Grants] accepts.
func (t term) String() string {
	var b strings.Builder
	b.WriteString(t.grant)
	for _, e := range t.excepts {
		b.WriteString(exceptSeparator + exceptPrefix + e)
	}
	return b.String()
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
// permission, matchSegments(h, g) reports whether h permits everything g
// does: a wildcard in g is only matched by the same wildcard or a
// [MultiWildcard] in h. The test is conservative: it may keep a redundant
// grant, such as "*:**" beside "**:*", but never drops a needed one.
//
// grants may carry exceptions (see [Grants]). Such a grant permits a subset
// of its grant part, so it is dropped when a plain grant covers that part.
// It covers a concrete grant it permits, which [Grants] decides exactly, but
// is not taken to cover patterns.
//
// Only a grant with a wildcard can cover a different grant, so each grant is
// compared against those alone.
func minimalGrants(grants []string) []string {
	var patterns, excepted []string
	for _, g := range grants {
		switch {
		case strings.Contains(g, exceptSeparator):
			excepted = append(excepted, g)
		case strings.Contains(g, Wildcard):
			patterns = append(patterns, g)
		}
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		part, _, _ := strings.Cut(g, exceptSeparator)
		concrete := part == g && !strings.Contains(g, Wildcard)
		covered := slices.ContainsFunc(patterns, func(h string) bool {
			return h != g && matchSegments(h, part, PermissionSeparator)
		}) || concrete && slices.ContainsFunc(excepted, func(h string) bool { return Grants(h, g) })
		if !covered {
			out = append(out, g)
		}
	}
	return out
}

// grantSet is a set of grants optimized for checking concrete permissions.
// Plain concrete grants are looked up in a map; patterns and grants with
// exceptions are matched one by one.
type grantSet struct {
	exact    map[string]bool
	patterns []string
}

func newGrantSet(grants []string) grantSet {
	s := grantSet{exact: make(map[string]bool, len(grants))}
	for _, g := range grants {
		if strings.ContainsAny(g, Wildcard+exceptSeparator) {
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
