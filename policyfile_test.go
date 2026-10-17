package rbac

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParsePolicyJSON(t *testing.T) {
	p, err := ParsePolicyJSON([]byte(`{
		"roles": {
			"viewer": {"permissions": ["posts:read"]},
			"editor": {"inherits": ["viewer"], "permissions": ["posts:write"]},
			"moderator": {"permissions": ["comments:*"], "except": ["comments:delete"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.Permissions("editor"), []string{"posts:read", "posts:write"}; !slices.Equal(got, want) {
		t.Errorf("Permissions = %v, want %v", got, want)
	}
	if got, want := p.Permissions("moderator"), []string{"comments:* -comments:delete"}; !slices.Equal(got, want) {
		t.Errorf("Permissions(moderator) = %v, want %v", got, want)
	}
}

func TestParsePolicyJSONErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", ``, ErrInvalidPolicy},
		{"syntax", `{"roles":`, ErrInvalidPolicy},
		{"unknown top-level field", `{"roles": {}, "rolez": {}}`, ErrInvalidPolicy},
		{"unknown role field", `{"roles": {"a": {"permisions": ["x"]}}}`, ErrInvalidPolicy},
		{"wrong type", `{"roles": {"a": {"permissions": "x"}}}`, ErrInvalidPolicy},
		{"trailing data", `{"roles": {}} {}`, ErrInvalidPolicy},
		{"invalid policy", `{"roles": {"a": {"inherits": ["b"]}}}`, ErrUnknownRole},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePolicyJSON([]byte(tt.in)); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadPolicyJSONEmptyRoles(t *testing.T) {
	p, err := LoadPolicyJSON(strings.NewReader(`{"roles": {}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles()) != 0 {
		t.Errorf("Roles = %v", p.Roles())
	}
}

func TestLoadPolicyJSONMissingRoles(t *testing.T) {
	for _, in := range []string{`{}`, `null`, `{"roles": null}`} {
		if _, err := LoadPolicyJSON(strings.NewReader(in)); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: err = %v, want ErrInvalidPolicy", in, err)
		}
	}
	if _, err := (PolicyFile{}).Policy(); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("zero PolicyFile: err = %v, want ErrInvalidPolicy", err)
	}
}
