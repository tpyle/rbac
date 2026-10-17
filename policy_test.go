package rbac

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// testDefs is a small hierarchy used throughout the tests:
//
//	admin -> editor -> viewer
//	admin -> auditor
var testDefs = map[string]RoleDefinition{
	"viewer":  {Permissions: []string{"posts:read", "comments:read"}},
	"editor":  {Inherits: []string{"viewer"}, Permissions: []string{"posts:write", "posts:read"}},
	"auditor": {Permissions: []string{"*:audit"}},
	"admin":   {Inherits: []string{"editor", "auditor"}, Permissions: []string{"users:*"}},
	"empty":   {},
}

func mustPolicy(t *testing.T, defs map[string]RoleDefinition) *Policy {
	t.Helper()
	p, err := NewPolicy(defs)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func TestNewPolicyErrors(t *testing.T) {
	tests := []struct {
		name    string
		defs    map[string]RoleDefinition
		wantErr error
		wantMsg string
	}{
		{"empty role name", map[string]RoleDefinition{"": {}}, ErrInvalidRole, ""},
		{"space in role name", map[string]RoleDefinition{"a b": {}}, ErrInvalidRole, ""},
		{"bad grant", map[string]RoleDefinition{"a": {Permissions: []string{"posts:"}}}, ErrInvalidPermission, `role "a"`},
		{"unknown parent", map[string]RoleDefinition{"a": {Inherits: []string{"ghost"}}}, ErrUnknownRole, "ghost"},
		{"self cycle", map[string]RoleDefinition{"a": {Inherits: []string{"a"}}}, ErrRoleCycle, "a -> a"},
		{"long cycle", map[string]RoleDefinition{
			"a": {Inherits: []string{"b"}},
			"b": {Inherits: []string{"c"}},
			"c": {Inherits: []string{"a"}},
		}, ErrRoleCycle, "a -> b -> c -> a"},
		{"cycle below root", map[string]RoleDefinition{
			"a": {Inherits: []string{"b"}},
			"b": {Inherits: []string{"c"}},
			"c": {Inherits: []string{"b"}},
		}, ErrRoleCycle, "b -> c -> b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPolicy(tt.defs)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestNewPolicyEmpty(t *testing.T) {
	for _, defs := range []map[string]RoleDefinition{nil, {}} {
		p := mustPolicy(t, defs)
		if got := p.Roles(); len(got) != 0 {
			t.Errorf("Roles() = %v", got)
		}
	}
}

func TestPolicyDiamondInheritance(t *testing.T) {
	p := mustPolicy(t, map[string]RoleDefinition{
		"base":  {Permissions: []string{"a"}},
		"left":  {Inherits: []string{"base"}, Permissions: []string{"b"}},
		"right": {Inherits: []string{"base"}, Permissions: []string{"c"}},
		"top":   {Inherits: []string{"left", "right"}},
	})
	if got, want := p.EffectiveRoles("top"), []string{"base", "left", "right", "top"}; !slices.Equal(got, want) {
		t.Errorf("EffectiveRoles = %v, want %v", got, want)
	}
	if got, want := p.Permissions("top"), []string{"a", "b", "c"}; !slices.Equal(got, want) {
		t.Errorf("Permissions = %v, want %v", got, want)
	}
}

func TestPolicyEffectiveRoles(t *testing.T) {
	p := mustPolicy(t, testDefs)
	tests := []struct {
		assigned []string
		want     []string
	}{
		{nil, []string{}},
		{[]string{"viewer"}, []string{"viewer"}},
		{[]string{"editor"}, []string{"editor", "viewer"}},
		{[]string{"admin"}, []string{"admin", "auditor", "editor", "viewer"}},
		{[]string{"viewer", "editor", "viewer"}, []string{"editor", "viewer"}},
		{[]string{"ghost", "viewer"}, []string{"ghost", "viewer"}},
	}
	for _, tt := range tests {
		if got := p.EffectiveRoles(tt.assigned...); !slices.Equal(got, tt.want) {
			t.Errorf("EffectiveRoles(%v) = %v, want %v", tt.assigned, got, tt.want)
		}
	}
}

func TestPolicyPermissions(t *testing.T) {
	p := mustPolicy(t, testDefs)
	tests := []struct {
		roles []string
		want  []string
	}{
		{nil, []string{}},
		{[]string{"ghost"}, []string{}},
		{[]string{"empty"}, []string{}},
		{[]string{"viewer"}, []string{"comments:read", "posts:read"}},
		{[]string{"editor"}, []string{"comments:read", "posts:read", "posts:write"}},
		{[]string{"admin"}, []string{"*:audit", "comments:read", "posts:read", "posts:write", "users:*"}},
		{[]string{"viewer", "auditor"}, []string{"*:audit", "comments:read", "posts:read"}},
	}
	for _, tt := range tests {
		if got := p.Permissions(tt.roles...); !slices.Equal(got, tt.want) {
			t.Errorf("Permissions(%v) = %v, want %v", tt.roles, got, tt.want)
		}
	}
}

func TestPolicyCan(t *testing.T) {
	p := mustPolicy(t, testDefs)
	tests := []struct {
		roles []string
		perm  string
		want  bool
	}{
		{[]string{"viewer"}, "posts:read", true},
		{[]string{"viewer"}, "posts:write", false},
		{[]string{"editor"}, "posts:write", true},
		{[]string{"admin"}, "users:delete", true},
		{[]string{"admin"}, "billing:audit", true},
		{[]string{"editor"}, "billing:audit", false},
		{nil, "posts:read", false},
		{[]string{"ghost"}, "posts:read", false},
	}
	for _, tt := range tests {
		got, err := p.Can(tt.roles, tt.perm)
		if err != nil || got != tt.want {
			t.Errorf("Can(%v, %q) = %v, %v; want %v", tt.roles, tt.perm, got, err, tt.want)
		}
	}
	if _, err := p.Can([]string{"admin"}, "users:*"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("Can with wildcard: err = %v, want ErrInvalidPermission", err)
	}
}

func TestPolicyIsImmutable(t *testing.T) {
	defs := map[string]RoleDefinition{
		"a": {Permissions: []string{"x"}, Inherits: []string{"b"}},
		"b": {Permissions: []string{"y"}},
	}
	p := mustPolicy(t, defs)
	defs["a"].Permissions[0] = "changed"
	defs["c"] = RoleDefinition{}

	got := p.Definitions()
	if got["a"].Permissions[0] != "x" || p.HasRole("c") {
		t.Fatalf("policy changed with its input: %v", got)
	}
	got["a"].Permissions[0] = "changed"
	if p.Definitions()["a"].Permissions[0] != "x" {
		t.Fatal("policy changed with Definitions result")
	}
	perms := p.Permissions("a")
	perms[0] = "changed"
	if p.Permissions("a")[0] != "x" {
		t.Fatal("policy changed with Permissions result")
	}
	roles := p.EffectiveRoles("a")
	roles[0] = "changed"
	if p.EffectiveRoles("a")[0] != "a" {
		t.Fatal("policy changed with EffectiveRoles result")
	}
}

func TestPolicyAccessors(t *testing.T) {
	p := mustPolicy(t, testDefs)
	if got, want := p.Roles(), []string{"admin", "auditor", "editor", "empty", "viewer"}; !slices.Equal(got, want) {
		t.Errorf("Roles() = %v, want %v", got, want)
	}
	if !p.HasRole("admin") || p.HasRole("ghost") {
		t.Error("HasRole wrong")
	}
	if got := p.Definitions(); len(got) != len(testDefs) || !slices.Equal(got["admin"].Inherits, testDefs["admin"].Inherits) {
		t.Errorf("Definitions() = %v", got)
	}
}

func TestNilPolicy(t *testing.T) {
	var p *Policy
	if len(p.Roles()) != 0 || len(p.Definitions()) != 0 || p.HasRole("a") {
		t.Error("nil policy defines roles")
	}
	if got := p.EffectiveRoles("b", "a", "a"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("EffectiveRoles = %v", got)
	}
	if got := p.Permissions("a"); got == nil || len(got) != 0 {
		t.Errorf("Permissions = %#v, want empty non-nil", got)
	}
	if ok, err := p.Can([]string{"a"}, "x"); ok || err != nil {
		t.Errorf("Can = %v, %v", ok, err)
	}
}

func TestPolicyAllowsMatchesPermissions(t *testing.T) {
	// The precomputed per-role sets must agree with matching against the
	// flattened grant list.
	p := mustPolicy(t, testDefs)
	perms := []string{"posts:read", "posts:write", "posts:delete", "comments:read",
		"users:delete", "billing:audit", "audit", "users"}
	roleSets := [][]string{nil, {"ghost"}, {"viewer"}, {"editor"}, {"admin"}, {"viewer", "auditor"}, {"empty", "ghost"}}
	for _, roles := range roleSets {
		flat := newGrantSet(p.Permissions(roles...))
		for _, perm := range perms {
			if got, want := p.allows(roles, perm), flat.allows(perm); got != want {
				t.Errorf("allows(%v, %q) = %v, want %v", roles, perm, got, want)
			}
		}
	}
}

func TestNewPolicyErrorIsDeterministic(t *testing.T) {
	defs := map[string]RoleDefinition{
		"a": {Permissions: []string{"bad::grant"}},
		"b": {Inherits: []string{"ghost"}},
		"c": {Inherits: []string{"ghost2"}},
	}
	for range 20 {
		if _, err := NewPolicy(defs); !errors.Is(err, ErrInvalidPermission) {
			t.Fatalf("err = %v, want the error for role a", err)
		}
	}
}

func TestPolicyExceptions(t *testing.T) {
	p := mustPolicy(t, map[string]RoleDefinition{
		"viewer":  {Permissions: []string{"files:read", "comments:read"}},
		"editor":  {Inherits: []string{"viewer"}, Permissions: []string{"files:*"}, Except: []string{"files:delete"}},
		"admin":   {Inherits: []string{"editor"}, Permissions: []string{"files:delete"}},
		"auditor": {Permissions: []string{"**"}, Except: []string{"secrets:**", "*:delete"}},
		"narrow":  {Inherits: []string{"viewer"}, Permissions: []string{"files:*"}, Except: []string{"files:read"}},
		"blocked": {Inherits: []string{"viewer"}, Except: []string{"**"}},
	})
	tests := []struct {
		roles []string
		perm  string
		want  bool
	}{
		{[]string{"editor"}, "files:write", true},
		{[]string{"editor"}, "files:read", true},
		{[]string{"editor"}, "files:delete", false},
		{[]string{"editor"}, "comments:read", true},
		// A parent's exception doesn't block a child's own grant.
		{[]string{"admin"}, "files:delete", true},
		// Another role granting the permission is enough.
		{[]string{"editor", "admin"}, "files:delete", true},
		{[]string{"auditor"}, "posts:read", true},
		{[]string{"auditor"}, "posts:delete", false},
		{[]string{"auditor"}, "secrets:read", false},
		{[]string{"auditor"}, "secrets", false},
		// Exceptions don't reach inherited permissions.
		{[]string{"narrow"}, "files:read", true},
		{[]string{"narrow"}, "files:write", true},
		{[]string{"blocked"}, "files:read", true},
		{[]string{"blocked"}, "files:write", false},
	}
	for _, tt := range tests {
		if got := p.allows(tt.roles, tt.perm); got != tt.want {
			t.Errorf("allows(%v, %q) = %v, want %v", tt.roles, tt.perm, got, tt.want)
		}
	}

	perms := map[string][]string{
		"editor":  {"comments:read", "files:* -files:delete", "files:read"},
		"admin":   {"comments:read", "files:* -files:delete", "files:delete", "files:read"},
		"auditor": {"** -*:delete -secrets:**"},
		"narrow":  {"comments:read", "files:* -files:read", "files:read"},
		"blocked": {"comments:read", "files:read"},
	}
	for role, want := range perms {
		if got := p.Permissions(role); !slices.Equal(got, want) {
			t.Errorf("Permissions(%s) = %q, want %q", role, got, want)
		}
	}
}

func TestPolicyExceptValidation(t *testing.T) {
	for _, bad := range []string{"", "files:", "p*", "a b", "a -b"} {
		_, err := NewPolicy(map[string]RoleDefinition{"r": {Permissions: []string{"x"}, Except: []string{bad}}})
		if !errors.Is(err, ErrInvalidPermission) {
			t.Errorf("Except %q: err = %v, want ErrInvalidPermission", bad, err)
		}
	}
	// Grants with exceptions are only for flattened output, not definitions.
	if _, err := NewPolicy(map[string]RoleDefinition{"r": {Permissions: []string{"a:* -a:b"}}}); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("inline exception: err = %v, want ErrInvalidPermission", err)
	}
	defs := map[string]RoleDefinition{"r": {Permissions: []string{"a:*"}, Except: []string{"a:b"}}}
	p := mustPolicy(t, defs)
	defs["r"].Except[0] = "changed"
	got := p.Definitions()
	if got["r"].Except[0] != "a:b" {
		t.Fatal("policy changed with its input")
	}
	got["r"].Except[0] = "changed"
	if p.Definitions()["r"].Except[0] != "a:b" {
		t.Fatal("policy changed with Definitions result")
	}
}

// FuzzPolicyExceptions builds small random policies and checks that the
// flattened policy, its effective roles, its Permissions output and that
// output pruned by minimalGrants all agree with a direct evaluation of the
// exception rules.
func FuzzPolicyExceptions(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{0, 9, 3, 3, 7, 1, 1, 4, 2, 8, 6, 5, 0, 0, 3, 2, 9, 9, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		next := func() int {
			if len(data) == 0 {
				return 0
			}
			b := int(data[0])
			data = data[1:]
			return b
		}
		segs := []string{"a", "b", Wildcard, MultiWildcard}
		pattern := func() string {
			n := 1 + next()%3
			parts := make([]string, n)
			for i := range parts {
				parts[i] = segs[next()%4]
			}
			if g := strings.Join(parts, PermissionSeparator); ValidateGrant(g) == nil {
				return g
			}
			return "a"
		}
		names := []string{"r0", "r1", "r2", "r3"}
		defs := map[string]RoleDefinition{}
		for i, name := range names {
			var d RoleDefinition
			for range next() % 3 {
				d.Permissions = append(d.Permissions, pattern())
			}
			for range next() % 3 {
				d.Except = append(d.Except, pattern())
			}
			// Inheriting only later roles keeps the policy acyclic.
			for _, parent := range names[i+1:] {
				if next()%2 == 1 {
					d.Inherits = append(d.Inherits, parent)
				}
			}
			defs[name] = d
		}
		p, err := NewPolicy(defs)
		if err != nil {
			t.Fatal(err)
		}

		matchesAny := func(patterns []string, perm string) bool {
			return slices.ContainsFunc(patterns, func(g string) bool { return Grants(g, perm) })
		}
		var ref func(role, perm string) bool
		ref = func(role, perm string) bool {
			d := defs[role]
			return matchesAny(d.Permissions, perm) && !matchesAny(d.Except, perm) ||
				slices.ContainsFunc(d.Inherits, func(parent string) bool { return ref(parent, perm) })
		}

		var perms []string
		var gen func(prefix string, depth int)
		gen = func(prefix string, depth int) {
			for _, s := range []string{"a", "b", "c"} {
				perm := s
				if prefix != "" {
					perm = prefix + PermissionSeparator + s
				}
				perms = append(perms, perm)
				if depth < 4 {
					gen(perm, depth+1)
				}
			}
		}
		gen("", 1)

		all := p.Permissions(names...)
		for _, g := range all {
			if err := validateGrantExpr(g); err != nil {
				t.Fatalf("Permissions returned an invalid grant: %v", err)
			}
		}
		pruned := newGrantSet(minimalGrants(all))
		for _, perm := range perms {
			anyRef := false
			for _, role := range names {
				want := ref(role, perm)
				anyRef = anyRef || want
				if got := p.allows([]string{role}, perm); got != want {
					t.Fatalf("allows(%s, %q) = %v, want %v\npolicy: %+v\nflattened: %q", role, perm, got, want, defs, p.Permissions(role))
				}
				// Holding the inherited roles directly, as an embedded roles
				// claim lists them, must not change the result.
				if got := p.allows(p.EffectiveRoles(role), perm); got != want {
					t.Fatalf("allows(EffectiveRoles(%s), %q) = %v, want %v", role, perm, got, want)
				}
				if got := newGrantSet(p.Permissions(role)).allows(perm); got != want {
					t.Fatalf("Permissions(%s) = %q allows %q: %v, want %v", role, p.Permissions(role), perm, got, want)
				}
			}
			if got := pruned.allows(perm); got != anyRef {
				t.Fatalf("minimalGrants(%q) allows %q: %v, want %v", all, perm, got, anyRef)
			}
		}
	})
}
