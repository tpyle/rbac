package rbac

import (
	"errors"
	"slices"
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
		{"", false, false},
		{":", false, false},
		{"posts:", false, false},
		{":read", false, false},
		{"posts::read", false, false},
		{"posts:re*d", false, false},
		{"posts:**", false, false},
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
		{"*", "posts", true},
		{"*", "posts:read", true},
		{"*", "a:b:c:d", true},
		{"posts:*", "posts:read", true},
		{"posts:*", "posts:comments:delete", true},
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
		{"posts:*:*", "posts:a:b:c", true},
		{"posts:*:*", "posts:a", false},
		{"*", "", false},
		{"posts", "", false},
		// Invalid input fails closed.
		{"", "", false},
		{"posts:", "posts:", false},
		{":read", ":read", false},
		{"posts::read", "posts::read", false},
		{"*:read", ":read", false},
		{"posts:*", "posts:", false},
	}
	for _, tt := range tests {
		if got := Grants(tt.grant, tt.perm); got != tt.want {
			t.Errorf("Grants(%q, %q) = %v, want %v", tt.grant, tt.perm, got, tt.want)
		}
	}
}

func TestGrantSet(t *testing.T) {
	s := newGrantSet([]string{"posts:read", "users:*", "*:audit"})
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
		Grants("posts:*", "posts:comments:delete")
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
		{[]string{"posts:*", "posts:read", "posts:comments:delete"}, []string{"posts:*"}},
		{[]string{"*", "*:read", "posts:*", "users:read"}, []string{"*"}},
		{[]string{"*:read", "posts:read", "posts:write"}, []string{"*:read", "posts:write"}},
		// A trailing wildcard covers more than a middle one, not the reverse.
		{[]string{"posts:*", "posts:*:read"}, []string{"posts:*"}},
		{[]string{"posts:*:read", "posts:drafts:*"}, []string{"posts:*:read", "posts:drafts:*"}},
		{[]string{"posts:*:*", "posts:*"}, []string{"posts:*"}},
		{[]string{"posts", "posts:*"}, []string{"posts", "posts:*"}},
	}
	for _, tt := range tests {
		in := sortedUnique(slices.Clone(tt.in))
		got := minimalGrants(in)
		if !slices.Equal(got, sortedUnique(slices.Clone(tt.want))) {
			t.Errorf("minimalGrants(%v) = %v, want %v", tt.in, got, tt.want)
		}
		// Pruning must never change what is granted.
		for _, perm := range []string{"posts", "posts:read", "posts:write", "posts:drafts:read",
			"posts:drafts:write", "posts:a:b:c", "users:read", "x"} {
			if a, b := newGrantSet(in).allows(perm), newGrantSet(got).allows(perm); a != b {
				t.Errorf("minimalGrants(%v) changed %q: %v -> %v", tt.in, perm, a, b)
			}
		}
	}
}
