package authrbac

import (
	"context"
	"errors"
	"testing"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

func testPolicy(t *testing.T) *rbac.Policy {
	t.Helper()
	p, err := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		"editor": {Permissions: []string{"posts:write"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClaims(t *testing.T) {
	if got := Claims(nil); got != nil {
		t.Errorf("Claims(nil) = %v, want nil", got)
	}
	extra := map[string]any{"roles": []any{"editor"}}
	got := Claims(&auth.Claims{ID: "t1", Subject: "alice", Issuer: "me", Extra: extra})
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
	if len(got.Values) != 1 || got.Values["roles"] == nil {
		t.Errorf("Values = %v, want %v", got.Values, extra)
	}
}

func TestClaimsFromContext(t *testing.T) {
	if c, ok := ClaimsFromContext(context.Background()); ok || c != nil {
		t.Errorf("empty context: got %v, %v; want nil, false", c, ok)
	}
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{Subject: "alice"})
	if c, ok := ClaimsFromContext(ctx); !ok || c.Subject != "alice" {
		t.Errorf("got %v, %v; want alice, true", c, ok)
	}
	// rbac's own context key is not consulted.
	rbacCtx := rbac.ContextWithClaims(context.Background(), &rbac.Claims{Subject: "alice"})
	if _, ok := ClaimsFromContext(rbacCtx); ok {
		t.Error("found claims stored by rbac.ContextWithClaims")
	}
}

func TestOptionReadsAuthContext(t *testing.T) {
	e, err := rbac.New(Option(), rbac.WithPolicy(testPolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{
		Subject: "alice",
		Extra:   map[string]any{"roles": []any{"editor"}},
	})
	if ok, err := e.Can(ctx, "posts:write"); !ok || err != nil {
		t.Errorf("Can() = %v, %v; want true, nil", ok, err)
	}
	if _, err := e.Can(context.Background(), "posts:write"); !errors.Is(err, rbac.ErrNoClaims) {
		t.Errorf("Can() without claims err = %v, want ErrNoClaims", err)
	}
}

func TestOptionReservesAuthClaims(t *testing.T) {
	for _, name := range []string{"typ", "fam", "sub"} {
		if !auth.IsReservedClaim(name) {
			t.Fatalf("auth no longer reserves %q; update this test", name)
		}
		if _, err := rbac.New(Option(), rbac.WithPolicy(testPolicy(t)), rbac.WithRolesClaim(name)); err == nil {
			t.Errorf("RolesClaim %q: New() err = nil, want error", name)
		}
	}
	// Without the option, only registered JWT claims are rejected.
	if _, err := rbac.New(rbac.WithPolicy(testPolicy(t)), rbac.WithRolesClaim("typ")); err != nil {
		t.Errorf("RolesClaim typ without Option: New() err = %v, want nil", err)
	}
}

func TestOptionCanBeOverridden(t *testing.T) {
	src := func(context.Context) (*rbac.Claims, bool) {
		return &rbac.Claims{Subject: "bob", Values: map[string]any{"roles": []any{"editor"}}}, true
	}
	e, err := rbac.New(Option(), rbac.WithClaimsSource(src), rbac.WithPolicy(testPolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Can(context.Background(), "posts:write"); !ok || err != nil {
		t.Errorf("Can() = %v, %v; want true, nil", ok, err)
	}
}

// TestClaimsProviderFitsAuth checks that the enforcer's claims provider is
// interchangeable with auth.ClaimsProvider in both directions.
func TestClaimsProviderFitsAuth(t *testing.T) {
	roles := rbac.NewMemoryRoleStore()
	roles.SetRoles("alice", "editor")
	e, err := rbac.New(Option(), rbac.WithPolicy(testPolicy(t)), rbac.WithRoleStore(roles))
	if err != nil {
		t.Fatal(err)
	}
	var base auth.ClaimsProvider = func(context.Context, string) (map[string]any, error) {
		return map[string]any{"tenant": "acme"}, nil
	}
	var p auth.ClaimsProvider = e.ClaimsProvider(base)
	_ = auth.WithClaimsProvider(p)
	got, err := p(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got["tenant"] != "acme" || got["roles"] == nil {
		t.Errorf("claims = %v, want tenant and roles", got)
	}
}
