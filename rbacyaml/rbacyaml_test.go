package rbacyaml

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tpyle/rbac"
)

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(`
roles:
  viewer:
    permissions: ["posts:read"]
  editor:
    inherits: [viewer]
    permissions:
      - "posts:write"
      - "posts:*:publish"
  moderator:
    permissions: ["comments:*"]
    except: ["comments:delete"]
  nobody: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.Roles(), []string{"editor", "moderator", "nobody", "viewer"}; !slices.Equal(got, want) {
		t.Errorf("Roles = %v, want %v", got, want)
	}
	if got, want := p.Permissions("editor"), []string{"posts:*:publish", "posts:read", "posts:write"}; !slices.Equal(got, want) {
		t.Errorf("Permissions = %v, want %v", got, want)
	}
	if got, want := p.Permissions("moderator"), []string{"comments:* -comments:delete"}; !slices.Equal(got, want) {
		t.Errorf("Permissions(moderator) = %v, want %v", got, want)
	}
}

func TestLoadPolicyErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", "", rbac.ErrInvalidPolicy},
		{"comment only", "# nothing here\n", rbac.ErrInvalidPolicy},
		{"missing roles", "{}\n", rbac.ErrInvalidPolicy},
		{"null roles", "roles:\n", rbac.ErrInvalidPolicy},
		{"syntax", "roles: [", rbac.ErrInvalidPolicy},
		{"unknown field", "roles: {}\nrolez: {}\n", rbac.ErrInvalidPolicy},
		{"unknown role field", "roles:\n  a:\n    permisions: [x]\n", rbac.ErrInvalidPolicy},
		{"wrong type", "roles:\n  a:\n    permissions: x\n", rbac.ErrInvalidPolicy},
		{"two documents", "roles: {}\n---\nroles: {}\n", rbac.ErrInvalidPolicy},
		{"null second document", "roles: {}\n--- null\n", rbac.ErrInvalidPolicy},
		{"tilde second document", "roles: {}\n---\n~\n", rbac.ErrInvalidPolicy},
		{"scalar second document", "roles: {}\n--- x\n", rbac.ErrInvalidPolicy},
		{"bad second document", "roles: {}\n---\n[\n", rbac.ErrInvalidPolicy},
		{"cycle", "roles:\n  a: {inherits: [b]}\n  b: {inherits: [a]}\n", rbac.ErrRoleCycle},
		{"bad grant", "roles:\n  a: {permissions: ['x::y']}\n", rbac.ErrInvalidPermission},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadPolicy(strings.NewReader(tt.in)); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestYAMLMatchesJSON(t *testing.T) {
	y, err := ParsePolicy([]byte("roles:\n  a: {permissions: [x], inherits: [b]}\n  b: {permissions: ['y:*']}\n"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := rbac.ParsePolicyJSON([]byte(`{"roles":{"a":{"permissions":["x"],"inherits":["b"]},"b":{"permissions":["y:*"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"a", "b"} {
		if !slices.Equal(y.Permissions(role), j.Permissions(role)) || !slices.Equal(y.EffectiveRoles(role), j.EffectiveRoles(role)) {
			t.Errorf("role %q differs between YAML and JSON", role)
		}
	}
}

func TestParsePolicyTrailingEmptyDocuments(t *testing.T) {
	for _, in := range []string{
		"---\nroles: {}\n",
		"roles: {}\n---\n",
		"roles: {}\n---\n# comment\n---\n",
		"roles: {}\n...\n",
		"roles: {}\n---\n...\n",
	} {
		if _, err := ParsePolicy([]byte(in)); err != nil {
			t.Errorf("ParsePolicy(%q) = %v", in, err)
		}
	}
}

func TestParsePolicyEmptyRoles(t *testing.T) {
	p, err := ParsePolicy([]byte("roles: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles()) != 0 {
		t.Errorf("Roles = %v", p.Roles())
	}
}
