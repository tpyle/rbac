package rbac

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestValidatePermission(t *testing.T) {
	tests := []struct {
		perm      string
		concrete  bool
		grantable bool
	}{
		{"posts", true, true},
		{"posts:read", true, true},
		{"posts:comments:delete", true, true},
		{"a-b_c.d:e/f", true, true},
		{"*", false, true},
		{"posts:*", false, true},
		{"*:read", false, true},
		{"posts:*:read", false, true},
		{"**", false, true},
		{"posts:**", false, true},
		{"**:read", false, true},
		{"posts:**:read", false, true},
		{"**:*", false, true},
		{"*:**", false, true},
		{"**:a:**", false, true},
		{"", false, false},
		{":", false, false},
		{"posts:", false, false},
		{":read", false, false},
		{"posts::read", false, false},
		{"posts:re*d", false, false},
		{"posts:***", false, false},
		{"posts:p**", false, false},
		{"**:**", false, false},
		{"posts:**:**:read", false, false},
		{"posts: read", false, false},
		{"posts:read\n", false, false},
		{"\tposts", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.perm, func(t *testing.T) {
			err := ValidatePermission(tt.perm)
			if (err == nil) != tt.concrete {
				t.Errorf("ValidatePermission(%q) = %v, want valid=%v", tt.perm, err, tt.concrete)
			}
			if err != nil && !errors.Is(err, ErrInvalidPermission) {
				t.Errorf("ValidatePermission(%q) = %v, want ErrInvalidPermission", tt.perm, err)
			}
			err = ValidateGrant(tt.perm)
			if (err == nil) != tt.grantable {
				t.Errorf("ValidateGrant(%q) = %v, want valid=%v", tt.perm, err, tt.grantable)
			}
			if err != nil && !errors.Is(err, ErrInvalidPermission) {
				t.Errorf("ValidateGrant(%q) = %v, want ErrInvalidPermission", tt.perm, err)
			}
		})
	}
}

func TestGrants(t *testing.T) {
	tests := []struct {
		grant, perm string
		want        bool
	}{
		{"posts:read", "posts:read", true},
		{"posts:read", "posts:write", false},
		{"posts:read", "posts", false},
		{"posts", "posts:read", false},
		{"posts:read", "posts:read:own", false},
		// "*" is exactly one segment, wherever it is.
		{"*", "posts", true},
		{"*", "posts:read", false},
		{"posts:*", "posts:read", true},
		{"posts:*", "posts:comments:delete", false},
		{"posts:*", "posts", false},
		{"posts:*", "users:read", false},
		{"*:read", "posts:read", true},
		{"*:read", "users:read", true},
		{"*:read", "posts:write", false},
		{"*:read", "read", false},
		{"*:read", "posts:drafts:read", false},
		{"posts:*:read", "posts:drafts:read", true},
		{"posts:*:read", "posts:drafts:write", false},
		{"posts:*:read", "posts:read", false},
		{"posts:*:*", "posts:a:b", true},
		{"posts:*:*", "posts:a:b:c", false},
		{"posts:*:*", "posts:a", false},
		// "**" is zero or more segments, wherever it is.
		{"**", "posts", true},
		{"**", "a:b:c:d", true},
		{"posts:**", "posts", true},
		{"posts:**", "posts:read", true},
		{"posts:**", "posts:comments:delete", true},
		{"posts:**", "users:read", false},
		{"posts:**", "postsx", false},
		{"**:read", "read", true},
		{"**:read", "posts:read", true},
		{"**:read", "posts:drafts:read", true},
		{"**:read", "posts:read:own", false},
		{"posts:**:read", "posts:read", true},
		{"posts:**:read", "posts:a:b:c:read", true},
		{"posts:**:read", "posts:a:b:c:write", false},
		{"posts:**:read", "users:read", false},
		{"**:*", "a", true},
		{"**:*", "a:b:c", true},
		{"*:**", "a", true},
		{"*:**:*", "a", false},
		{"*:**:*", "a:b", true},
		{"*:**:*", "a:b:c:d", true},
		{"a:**:b:**:c", "a:b:c", true},
		{"a:**:b:**:c", "a:x:b:y:z:c", true},
		{"a:**:b:**:c", "a:x:y:c", false},
		// Backtracking past an early partial match.
		{"**:a:b", "a:a:b", true},
		{"**:a:b", "a:a:a:b", true},
		{"**:a:b", "a:b:a", false},
		{"**:a:*:c", "a:a:x:a:y:c", true},
		{"**", "", false},
		{"*", "", false},
		{"posts", "", false},
		// Invalid input fails closed.
		{"", "", false},
		{"posts:", "posts:", false},
		{":read", ":read", false},
		{"posts::read", "posts::read", false},
		{"*:read", ":read", false},
		{"posts:*", "posts:", false},
		{"posts:**", "posts::x", false},
		{"**", "a::b", false},
		{"**:", "a", false},
	}
	for _, tt := range tests {
		if got := Grants(tt.grant, tt.perm); got != tt.want {
			t.Errorf("Grants(%q, %q) = %v, want %v", tt.grant, tt.perm, got, tt.want)
		}
	}
}

// refMatch is a slow, obviously correct reference for matchSegments.
func refMatch(pattern, value []string) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	switch pattern[0] {
	case MultiWildcard:
		for i := 0; i <= len(value); i++ {
			if refMatch(pattern[1:], value[i:]) {
				return true
			}
		}
		return false
	case Wildcard:
		return len(value) > 0 && value[0] != MultiWildcard && refMatch(pattern[1:], value[1:])
	default:
		return len(value) > 0 && value[0] == pattern[0] && refMatch(pattern[1:], value[1:])
	}
}

func refGrants(pattern, value, sep string) bool {
	p, v := strings.Split(pattern, sep), strings.Split(value, sep)
	if slices.Contains(p, "") || slices.Contains(v, "") {
		return false
	}
	return refMatch(p, v)
}

func FuzzMatchSegments(f *testing.F) {
	for _, seed := range [][2]string{
		{"posts:*", "posts:read"},
		{"**:a:b", "a:a:b"},
		{"a:**:b:**:c", "a:x:b:y:z:c"},
		{"*:**:*", "a"},
		{"**", ""},
		{"posts::read", "posts::read"},
		{"*:**", "**:*"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		for _, sep := range []string{PermissionSeparator, ScopeSeparator} {
			if got, want := matchSegments(pattern, value, sep), refGrants(pattern, value, sep); got != want {
				t.Fatalf("matchSegments(%q, %q, %q) = %v, reference says %v", pattern, value, sep, got, want)
			}
		}
	})
}

func TestGrantSet(t *testing.T) {
	s := newGrantSet([]string{"posts:read", "users:*", "*:audit", "billing:**:export"})
	tests := []struct {
		perm string
		want bool
	}{
		{"posts:read", true},
		{"posts:write", false},
		{"users:delete", true},
		{"users", false},
		{"billing:audit", true},
		{"billing:read", false},
		{"billing:export", true},
		{"billing:2026:q1:export", true},
		{"users:a:b", false},
	}
	for _, tt := range tests {
		if got := s.allows(tt.perm); got != tt.want {
			t.Errorf("allows(%q) = %v, want %v", tt.perm, got, tt.want)
		}
	}
	if newGrantSet(nil).allows("posts:read") {
		t.Error("empty set allows posts:read")
	}
}

func TestValidateRole(t *testing.T) {
	for _, name := range []string{"admin", "org:admin", "Editor-2"} {
		if err := validateRole(name); err != nil {
			t.Errorf("validateRole(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "super admin", "admin\n"} {
		if err := validateRole(name); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("validateRole(%q) = %v, want ErrInvalidRole", name, err)
		}
	}
}

func TestGrantsDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		Grants("posts:*:read", "posts:drafts:read")
		Grants("posts:**", "posts:comments:delete")
		Grants("**:a:*:c", "a:a:x:a:y:c")
	})
	if allocs != 0 {
		t.Errorf("Grants allocates %v times per run", allocs)
	}
}

func TestMinimalGrants(t *testing.T) {
	tests := []struct {
		in, want []string
	}{
		{[]string{}, []string{}},
		{[]string{"posts:read"}, []string{"posts:read"}},
		{[]string{"posts:*", "posts:read", "posts:comments:delete"}, []string{"posts:*", "posts:comments:delete"}},
		{[]string{"posts:**", "posts:read", "posts:comments:delete", "posts:*"}, []string{"posts:**"}},
		{[]string{"**", "*:read", "posts:**", "users:read", "*"}, []string{"**"}},
		{[]string{"*", "*:read", "posts:*", "users"}, []string{"*", "*:read", "posts:*"}},
		{[]string{"*:read", "posts:read", "posts:write"}, []string{"*:read", "posts:write"}},
		{[]string{"posts:**", "posts:*:read"}, []string{"posts:**"}},
		{[]string{"posts:*", "posts:*:read"}, []string{"posts:*", "posts:*:read"}},
		{[]string{"posts:*:read", "posts:drafts:*"}, []string{"posts:*:read", "posts:drafts:*"}},
		{[]string{"posts:*:*", "posts:*"}, []string{"posts:*", "posts:*:*"}},
		{[]string{"posts", "posts:*"}, []string{"posts", "posts:*"}},
		{[]string{"posts", "posts:**"}, []string{"posts:**"}},
		// "*" covers "*" but not "**".
		{[]string{"posts:*", "posts:**"}, []string{"posts:**"}},
		{[]string{"*:**", "posts:**"}, []string{"*:**"}},
		{[]string{"**:read", "posts:**:read", "*:read"}, []string{"**:read"}},
		// Equivalent patterns the syntactic test cannot relate are both kept.
		{[]string{"*:**", "**:*"}, []string{"*:**", "**:*"}},
	}
	for _, tt := range tests {
		in := sortedUnique(slices.Clone(tt.in))
		got := minimalGrants(in)
		if !slices.Equal(got, sortedUnique(slices.Clone(tt.want))) {
			t.Errorf("minimalGrants(%v) = %v, want %v", tt.in, got, tt.want)
		}
		// Pruning must never change what is granted.
		for _, perm := range []string{"posts", "posts:read", "posts:write", "posts:drafts:read",
			"posts:drafts:write", "posts:a:b:c", "users", "users:read", "x", "a:b:read"} {
			if a, b := newGrantSet(in).allows(perm), newGrantSet(got).allows(perm); a != b {
				t.Errorf("minimalGrants(%v) changed %q: %v -> %v", tt.in, perm, a, b)
			}
		}
	}
}

// FuzzMinimalGrants checks that pruning never changes what a grant set
// allows. Grants and permissions are built from a small alphabet so that
// overlaps are common.
func FuzzMinimalGrants(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{3, 4, 1, 0, 9, 9, 2, 3, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		segs := []string{"a", "b", Wildcard, MultiWildcard}
		var grants []string
		var cur []string
		for _, b := range data {
			if b%5 == 4 || len(cur) == 4 {
				if g := strings.Join(cur, PermissionSeparator); ValidateGrant(g) == nil {
					grants = append(grants, g)
				}
				cur = cur[:0]
				continue
			}
			cur = append(cur, segs[b%4])
		}
		grants = sortedUnique(grants)
		pruned := minimalGrants(slices.Clone(grants))
		before, after := newGrantSet(grants), newGrantSet(pruned)
		// Every concrete permission of up to four segments over {a, b, c}.
		var perms []string
		var gen func(prefix string, depth int)
		gen = func(prefix string, depth int) {
			for _, s := range []string{"a", "b", "c"} {
				p := s
				if prefix != "" {
					p = prefix + PermissionSeparator + s
				}
				perms = append(perms, p)
				if depth < 4 {
					gen(p, depth+1)
				}
			}
		}
		gen("", 1)
		for _, p := range perms {
			if before.allows(p) != after.allows(p) {
				t.Fatalf("minimalGrants(%v) = %v changed %q", grants, pruned, p)
			}
		}
	})
}
