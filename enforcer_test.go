package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// countingStore is a RoleStore that records lookups.
type countingStore struct {
	roles map[string][]string
	err   error
	calls int
}

func (s *countingStore) Roles(_ context.Context, subject string) ([]string, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.roles[subject], nil
}

// countingPolicy is a PolicyProvider that records loads.
type countingPolicy struct {
	p     *Policy
	err   error
	calls int
}

func (c *countingPolicy) Policy(context.Context) (*Policy, error) {
	c.calls++
	return c.p, c.err
}

type fixture struct {
	e      *Enforcer
	store  *countingStore
	policy *countingPolicy
}

// newFixture builds an enforcer where alice is an editor (so also a viewer)
// and bob has no roles.
func newFixture(t *testing.T, opts ...Option) *fixture {
	t.Helper()
	f := &fixture{
		store:  &countingStore{roles: map[string][]string{"alice": {"editor"}}},
		policy: &countingPolicy{p: mustPolicy(t, testDefs)},
	}
	base := []Option{WithRoleStore(f.store), WithPolicyProvider(f.policy)}
	e, err := newWithSource(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	f.e = e
	return f
}

func (f *fixture) reset() { f.store.calls, f.policy.calls = 0, 0 }

func claimsCtx(subject string, extra map[string]any) context.Context {
	return ContextWithClaims(context.Background(), &Claims{Subject: subject, Values: extra})
}

// tokenClaims issues claims for subject as a token would carry them after a JSON
// round trip: arrays become []any.
func (f *fixture) tokenClaims(t *testing.T, subject string) map[string]any {
	t.Helper()
	m, err := f.e.ClaimsProvider(nil)(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		if s, ok := v.([]string); ok {
			a := make([]any, len(s))
			for i := range s {
				a[i] = s[i]
			}
			m[k] = a
		}
	}
	return m
}

func TestClaimsProvider(t *testing.T) {
	tests := []struct {
		name      string
		opts      []Option
		subject   string
		wantRoles []string // nil means absent
		wantPerms []string
	}{
		{"roles only", nil, "alice", []string{"editor", "viewer"}, nil},
		{"permissions only", []Option{WithEmbedRoles(false), WithEmbedPermissions(true)}, "alice",
			nil, []string{"comments:read", "posts:read", "posts:write"}},
		{"both", []Option{WithEmbedPermissions(true)}, "alice",
			[]string{"editor", "viewer"}, []string{"comments:read", "posts:read", "posts:write"}},
		{"no roles", []Option{WithEmbedPermissions(true)}, "bob", []string{}, []string{}},
		{"custom names", []Option{WithEmbedPermissions(true), WithRolesClaim("r"), WithPermissionsClaim("p")}, "alice",
			[]string{"editor", "viewer"}, []string{"comments:read", "posts:read", "posts:write"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.opts...)
			cfg := f.e.Config()
			got, err := f.e.ClaimsProvider(nil)(context.Background(), tt.subject)
			if err != nil {
				t.Fatal(err)
			}
			check := func(claim string, want []string) {
				v, ok := got[claim]
				if want == nil {
					if ok {
						t.Errorf("claim %q = %v, want absent", claim, v)
					}
					return
				}
				s, _ := v.([]string)
				// Must be non-nil so it encodes as [] and counts as present.
				if s == nil || !slices.Equal(s, want) {
					t.Errorf("claim %q = %#v, want %v", claim, v, want)
				}
			}
			check(cfg.RolesClaim, tt.wantRoles)
			check(cfg.PermissionsClaim, tt.wantPerms)
		})
	}
}

func TestClaimsProviderBase(t *testing.T) {
	ctx := context.Background()
	base := func(_ context.Context, subject string) (map[string]any, error) {
		return map[string]any{"tenant": "acme-" + subject}, nil
	}
	f := newFixture(t)
	got, err := f.e.ClaimsProvider(base)(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got["tenant"] != "acme-alice" || got["roles"] == nil {
		t.Errorf("claims = %v", got)
	}

	f = newFixture(t, WithEmbedRoles(false))
	got, err = f.e.ClaimsProvider(base)(ctx, "alice")
	if err != nil || len(got) != 1 || f.store.calls != 0 {
		t.Errorf("nothing embedded: claims = %v, err = %v, store calls = %d", got, err, f.store.calls)
	}

	baseErr := errors.New("base failed")
	_, err = newFixture(t).e.ClaimsProvider(func(context.Context, string) (map[string]any, error) {
		return nil, baseErr
	})(ctx, "alice")
	if !errors.Is(err, baseErr) {
		t.Errorf("err = %v, want base error", err)
	}

	// Only the names of embedded claims are reserved.
	tests := []struct {
		name          string
		roles, perms  bool
		claim         string
		wantCollision bool
	}{
		{"roles embedded", true, false, "roles", true},
		{"perms disabled", true, false, "perms", false},
		{"perms embedded", false, true, "perms", true},
		{"roles disabled", false, true, "roles", false},
		{"both embedded", true, true, "perms", true},
		{"nothing embedded", false, false, "roles", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newFixture(t, WithEmbedRoles(tt.roles), WithEmbedPermissions(tt.perms)).e.ClaimsProvider(
				func(context.Context, string) (map[string]any, error) {
					return map[string]any{tt.claim: "x"}, nil
				})(ctx, "alice")
			if tt.wantCollision {
				if err == nil {
					t.Errorf("base setting %q: err = nil", tt.claim)
				}
				return
			}
			if err != nil || got[tt.claim] != "x" {
				t.Errorf("base setting %q: claims = %v, err = %v", tt.claim, got, err)
			}
		})
	}
}

func TestClaimsProviderErrors(t *testing.T) {
	ctx := context.Background()
	storeErr := errors.New("db down")

	f := newFixture(t)
	f.store.err = storeErr
	if _, err := f.e.ClaimsProvider(nil)(ctx, "alice"); !errors.Is(err, storeErr) {
		t.Errorf("store error: err = %v", err)
	}

	f = newFixture(t)
	f.store.roles["alice"] = []string{"bad role"}
	if _, err := f.e.ClaimsProvider(nil)(ctx, "alice"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("invalid stored role: err = %v", err)
	}

	f = newFixture(t)
	f.policy.err = errors.New("policy down")
	if _, err := f.e.ClaimsProvider(nil)(ctx, "alice"); !errors.Is(err, f.policy.err) {
		t.Errorf("policy error: err = %v", err)
	}

	e, err := newWithSource(WithEmbedRoles(false), WithEmbedPermissions(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ClaimsProvider(nil)(ctx, "alice"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no store: err = %v", err)
	}
	e, err = newWithSource(WithEmbedRoles(false), WithEmbedPermissions(true), WithRoleStore(NewMemoryRoleStore()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ClaimsProvider(nil)(ctx, "alice"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no policy: err = %v", err)
	}
}

// TestResolutionOrder checks which source answers each check for every
// combination of configuration and token contents.
func TestResolutionOrder(t *testing.T) {
	configs := []struct {
		name         string
		opts         []Option
		roles, perms bool
	}{
		{"none", []Option{WithEmbedRoles(false)}, false, false},
		{"roles", nil, true, false},
		{"perms", []Option{WithEmbedRoles(false), WithEmbedPermissions(true)}, false, true},
		{"both", []Option{WithEmbedPermissions(true)}, true, true},
	}
	for _, cfg := range configs {
		for _, tokenHasClaims := range []bool{true, false} {
			name := cfg.name + "/token-without-claims"
			if tokenHasClaims {
				name = cfg.name + "/token-with-claims"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t, cfg.opts...)
				extra := map[string]any{}
				if tokenHasClaims {
					extra = f.tokenClaims(t, "alice")
				}
				ctx := claimsCtx("alice", extra)

				f.reset()
				ok, err := f.e.HasRole(ctx, "viewer")
				if err != nil || !ok {
					t.Fatalf("HasRole(viewer) = %v, %v", ok, err)
				}
				wantStore := 0
				if !cfg.roles || !tokenHasClaims {
					wantStore = 1
				}
				if f.store.calls != wantStore {
					t.Errorf("HasRole store calls = %d, want %d", f.store.calls, wantStore)
				}

				f.reset()
				ok, err = f.e.Can(ctx, "posts:write")
				if err != nil || !ok {
					t.Fatalf("Can(posts:write) = %v, %v", ok, err)
				}
				wantStore, wantPolicy := 1, 1
				switch {
				case cfg.perms && tokenHasClaims:
					wantStore, wantPolicy = 0, 0
				case cfg.roles && tokenHasClaims:
					wantStore = 0
				}
				if f.store.calls != wantStore || f.policy.calls != wantPolicy {
					t.Errorf("Can store/policy calls = %d/%d, want %d/%d",
						f.store.calls, f.policy.calls, wantStore, wantPolicy)
				}

				if ok, err := f.e.Can(ctx, "users:delete"); err != nil || ok {
					t.Errorf("Can(users:delete) = %v, %v", ok, err)
				}
				if ok, err := f.e.HasRole(ctx, "admin"); err != nil || ok {
					t.Errorf("HasRole(admin) = %v, %v", ok, err)
				}
			})
		}
	}
}

func TestTokenClaimsAreAuthoritative(t *testing.T) {
	// The store says alice is an editor, but the token wins.
	f := newFixture(t, WithEmbedPermissions(true))
	ctx := claimsCtx("alice", map[string]any{
		"roles": []any{"auditor"},
		"perms": []any{"billing:*"},
	})
	if ok, _ := f.e.HasRole(ctx, "editor"); ok {
		t.Error("HasRole(editor) used the store")
	}
	if ok, _ := f.e.HasRole(ctx, "auditor"); !ok {
		t.Error("HasRole(auditor) ignored the token")
	}
	if ok, _ := f.e.Can(ctx, "posts:write"); ok {
		t.Error("Can(posts:write) used the store")
	}
	if ok, _ := f.e.Can(ctx, "billing:refund"); !ok {
		t.Error("Can(billing:refund) ignored the token")
	}

	// Embedded roles are expanded through the current policy, so role and
	// permission checks agree on inheritance.
	ctx = claimsCtx("alice", map[string]any{"roles": []any{"admin"}})
	if ok, err := f.e.HasRole(ctx, "viewer"); !ok || err != nil {
		t.Errorf("HasRole(viewer) = %v, %v; want embedded roles expanded", ok, err)
	}

	// An empty array means no access, not "look it up".
	ctx = claimsCtx("alice", map[string]any{"roles": []any{}, "perms": []any{}})
	f.reset()
	if ok, err := f.e.HasRole(ctx, "editor"); ok || err != nil {
		t.Errorf("empty roles: HasRole = %v, %v", ok, err)
	}
	if ok, err := f.e.Can(ctx, "posts:read"); ok || err != nil {
		t.Errorf("empty perms: Can = %v, %v", ok, err)
	}
	if f.store.calls != 0 {
		t.Errorf("store calls = %d, want 0", f.store.calls)
	}
}

func TestDisabledClaimsAreIgnored(t *testing.T) {
	f := newFixture(t, WithEmbedRoles(false))
	ctx := claimsCtx("alice", map[string]any{
		"roles": []any{"admin"},
		"perms": []any{"**"},
	})
	if ok, _ := f.e.HasRole(ctx, "admin"); ok {
		t.Error("disabled roles claim was trusted")
	}
	if ok, _ := f.e.Can(ctx, "users:delete"); ok {
		t.Error("disabled perms claim was trusted")
	}
	if f.store.calls != 2 {
		t.Errorf("store calls = %d, want 2", f.store.calls)
	}
}

func TestStringSliceClaims(t *testing.T) {
	f := newFixture(t, WithEmbedPermissions(true))
	ctx := claimsCtx("bob", map[string]any{"roles": []string{"x"}, "perms": []string{"a:b"}})
	if ok, err := f.e.HasRole(ctx, "x"); !ok || err != nil {
		t.Errorf("HasRole = %v, %v", ok, err)
	}
	if ok, err := f.e.Can(ctx, "a:b"); !ok || err != nil {
		t.Errorf("Can = %v, %v", ok, err)
	}
}

func TestMalformedClaims(t *testing.T) {
	bad := []any{
		"admin",
		nil,
		[]any{"admin", 3.0},
		[]any{"bad role"},
		map[string]any{},
	}
	for _, v := range bad {
		f := newFixture(t, WithEmbedPermissions(true))
		ctx := claimsCtx("alice", map[string]any{"roles": v})
		if _, err := f.e.HasRole(ctx, "admin"); !errors.Is(err, ErrMalformedClaim) {
			t.Errorf("roles = %#v: HasRole err = %v", v, err)
		}
		if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, ErrMalformedClaim) {
			t.Errorf("roles = %#v: Can err = %v", v, err)
		}
		if f.store.calls != 0 {
			t.Errorf("roles = %#v: fell back to the store", v)
		}
	}
	f := newFixture(t, WithEmbedPermissions(true))
	for _, v := range []any{[]any{"posts:"}, []any{1.0}, "posts:read", []any{"posts:* posts:read"}, []any{"posts:* -"}} {
		ctx := claimsCtx("alice", map[string]any{"perms": v})
		if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, ErrMalformedClaim) {
			t.Errorf("perms = %#v: Can err = %v", v, err)
		}
	}
}

func TestMultiChecks(t *testing.T) {
	f := newFixture(t)
	ctx := claimsCtx("alice", f.tokenClaims(t, "alice"))
	tests := []struct {
		name string
		fn   func() (bool, error)
		want bool
	}{
		{"HasAnyRole hit", func() (bool, error) { return f.e.HasAnyRole(ctx, "admin", "viewer") }, true},
		{"HasAnyRole miss", func() (bool, error) { return f.e.HasAnyRole(ctx, "admin", "auditor") }, false},
		{"CanAll hit", func() (bool, error) { return f.e.CanAll(ctx, "posts:read", "posts:write") }, true},
		{"CanAll partial", func() (bool, error) { return f.e.CanAll(ctx, "posts:read", "users:delete") }, false},
		{"CanAny hit", func() (bool, error) { return f.e.CanAny(ctx, "users:delete", "posts:write") }, true},
		{"CanAny miss", func() (bool, error) { return f.e.CanAny(ctx, "users:delete", "billing:audit") }, false},
	}
	for _, tt := range tests {
		got, err := tt.fn()
		if err != nil || got != tt.want {
			t.Errorf("%s = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
}

func TestCheckArgumentErrors(t *testing.T) {
	f := newFixture(t)
	ctx := claimsCtx("alice", f.tokenClaims(t, "alice"))
	f.reset()
	tests := []struct {
		name    string
		fn      func() (bool, error)
		wantErr error
	}{
		{"HasAnyRole empty", func() (bool, error) { return f.e.HasAnyRole(ctx) }, ErrInvalidRole},
		{"HasRole invalid", func() (bool, error) { return f.e.HasRole(ctx, "") }, ErrInvalidRole},
		{"Can wildcard", func() (bool, error) { return f.e.Can(ctx, "posts:*") }, ErrInvalidPermission},
		{"CanAll empty", func() (bool, error) { return f.e.CanAll(ctx) }, ErrInvalidPermission},
		{"CanAny empty", func() (bool, error) { return f.e.CanAny(ctx) }, ErrInvalidPermission},
		{"CanAny invalid", func() (bool, error) { return f.e.CanAny(ctx, "a", "b::c") }, ErrInvalidPermission},
		{"SubjectHasRole invalid", func() (bool, error) { return f.e.SubjectHasRole(ctx, "alice", "a b") }, ErrInvalidRole},
		{"SubjectCan invalid", func() (bool, error) { return f.e.SubjectCan(ctx, "alice", "*") }, ErrInvalidPermission},
	}
	for _, tt := range tests {
		if _, err := tt.fn(); !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
	if f.store.calls != 0 || f.policy.calls != 0 {
		t.Error("invalid arguments reached the store or policy")
	}
}

func TestNoClaims(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for name, fn := range map[string]func() (bool, error){
		"HasRole":    func() (bool, error) { return f.e.HasRole(ctx, "a") },
		"HasAnyRole": func() (bool, error) { return f.e.HasAnyRole(ctx, "a") },
		"Can":        func() (bool, error) { return f.e.Can(ctx, "a") },
		"CanAll":     func() (bool, error) { return f.e.CanAll(ctx, "a") },
		"CanAny":     func() (bool, error) { return f.e.CanAny(ctx, "a") },
		"ClaimsHaveAnyRole nil": func() (bool, error) {
			return f.e.ClaimsHaveAnyRole(ctx, nil, "a")
		},
		"ClaimsCanAll nil": func() (bool, error) { return f.e.ClaimsCanAll(ctx, nil, "a") },
		"ClaimsCanAny nil": func() (bool, error) { return f.e.ClaimsCanAny(ctx, nil, "a") },
	} {
		if _, err := fn(); !errors.Is(err, ErrNoClaims) {
			t.Errorf("%s: err = %v, want ErrNoClaims", name, err)
		}
	}
}

func TestBackendErrors(t *testing.T) {
	storeErr := errors.New("db down")
	policyErr := errors.New("policy down")
	ctx := claimsCtx("alice", nil)

	f := newFixture(t, WithEmbedRoles(false))
	f.store.err = storeErr
	if _, err := f.e.HasRole(ctx, "viewer"); !errors.Is(err, storeErr) {
		t.Errorf("HasRole err = %v", err)
	}
	if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, storeErr) {
		t.Errorf("Can err = %v", err)
	}

	f = newFixture(t, WithEmbedRoles(false))
	f.policy.err = policyErr
	if _, err := f.e.HasRole(ctx, "viewer"); !errors.Is(err, policyErr) {
		t.Errorf("HasRole err = %v", err)
	}
	if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, policyErr) {
		t.Errorf("Can err = %v", err)
	}

	// Roles claim present, policy fails.
	f = newFixture(t)
	f.policy.err = policyErr
	ctx = claimsCtx("alice", map[string]any{"roles": []any{"editor"}})
	if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, policyErr) {
		t.Errorf("Can with roles claim err = %v", err)
	}
	if f.store.calls != 0 {
		t.Error("fell back to the store after a policy error")
	}
}

func TestNotConfiguredFallbacks(t *testing.T) {
	// A verifying service with permissions embedded and nothing else.
	e, err := newWithSource(WithEmbedRoles(false), WithEmbedPermissions(true))
	if err != nil {
		t.Fatal(err)
	}
	ctx := claimsCtx("alice", map[string]any{})
	if _, err := e.Can(ctx, "posts:read"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Can err = %v", err)
	}
	if _, err := e.HasRole(ctx, "viewer"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("HasRole err = %v", err)
	}
	// Role checks can never be answered here, so that is reported before
	// the claims are consulted, and after the arguments.
	if _, err := e.HasRole(context.Background(), "viewer"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("HasRole without claims err = %v, want ErrNotConfigured", err)
	}
	if _, err := e.HasRole(ctx, "a b"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("HasRole(invalid) err = %v, want ErrInvalidRole", err)
	}

	// Roles and permissions embedded but no policy: a token with only
	// roles cannot answer permission checks.
	e, err = newWithSource(WithEmbedPermissions(true))
	if err != nil {
		t.Fatal(err)
	}
	ctx = claimsCtx("alice", map[string]any{"roles": []any{"editor"}})
	if _, err := e.Can(ctx, "posts:read"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Can err = %v", err)
	}
	if ok, err := e.HasRole(ctx, "editor"); !ok || err != nil {
		t.Errorf("HasRole = %v, %v", ok, err)
	}

	// Without a policy, store roles are not expanded.
	store := NewMemoryRoleStore()
	store.SetRoles("alice", "editor")
	e, err = newWithSource(WithEmbedRoles(false), WithEmbedPermissions(true), WithRoleStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.EffectiveRoles(context.Background(), "alice"); err != nil || !slices.Equal(got, []string{"editor"}) {
		t.Errorf("EffectiveRoles = %v, %v", got, err)
	}
	if _, err := e.Permissions(context.Background(), "alice"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Permissions err = %v", err)
	}
}

func TestSubjectChecks(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tests := []struct {
		name string
		fn   func() (bool, error)
		want bool
	}{
		{"alice viewer", func() (bool, error) { return f.e.SubjectHasRole(ctx, "alice", "viewer") }, true},
		{"alice admin", func() (bool, error) { return f.e.SubjectHasRole(ctx, "alice", "admin") }, false},
		{"bob viewer", func() (bool, error) { return f.e.SubjectHasRole(ctx, "bob", "viewer") }, false},
		{"alice posts:write", func() (bool, error) { return f.e.SubjectCan(ctx, "alice", "posts:write") }, true},
		{"alice users:read", func() (bool, error) { return f.e.SubjectCan(ctx, "alice", "users:read") }, false},
		{"bob posts:read", func() (bool, error) { return f.e.SubjectCan(ctx, "bob", "posts:read") }, false},
	}
	for _, tt := range tests {
		got, err := tt.fn()
		if err != nil || got != tt.want {
			t.Errorf("%s = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}

	f.store.err = errors.New("db down")
	if _, err := f.e.SubjectHasRole(ctx, "alice", "viewer"); !errors.Is(err, f.store.err) {
		t.Errorf("SubjectHasRole err = %v", err)
	}
	if _, err := f.e.SubjectCan(ctx, "alice", "posts:read"); !errors.Is(err, f.store.err) {
		t.Errorf("SubjectCan err = %v", err)
	}
	f.store.err = nil
	f.policy.err = errors.New("policy down")
	if _, err := f.e.Permissions(ctx, "alice"); !errors.Is(err, f.policy.err) {
		t.Errorf("Permissions err = %v", err)
	}
}

func TestExplicitClaims(t *testing.T) {
	f := newFixture(t)
	c := &Claims{Subject: "alice", Values: map[string]any{"roles": []any{"admin"}}}
	ctx := context.Background()
	if ok, err := f.e.ClaimsHaveAnyRole(ctx, c, "auditor", "admin"); !ok || err != nil {
		t.Errorf("ClaimsHaveAnyRole = %v, %v", ok, err)
	}
	if ok, err := f.e.ClaimsCanAll(ctx, c, "users:delete", "posts:read"); !ok || err != nil {
		t.Errorf("ClaimsCanAll = %v, %v", ok, err)
	}
	if ok, err := f.e.ClaimsCanAny(ctx, c, "billing:refund", "x:audit"); !ok || err != nil {
		t.Errorf("ClaimsCanAny = %v, %v", ok, err)
	}
}

func TestNilPolicyFromProvider(t *testing.T) {
	f := newFixture(t)
	f.policy.p = nil
	ctx := claimsCtx("alice", map[string]any{"roles": []any{"editor"}})
	if _, err := f.e.Can(ctx, "posts:read"); !errors.Is(err, ErrNilPolicy) {
		t.Errorf("Can err = %v, want ErrNilPolicy", err)
	}
	if _, err := f.e.SubjectCan(ctx, "alice", "posts:read"); !errors.Is(err, ErrNilPolicy) {
		t.Errorf("SubjectCan err = %v, want ErrNilPolicy", err)
	}
	if _, err := f.e.ClaimsProvider(nil)(context.Background(), "alice"); !errors.Is(err, ErrNilPolicy) {
		t.Errorf("ClaimsProvider err = %v, want ErrNilPolicy", err)
	}
}

func TestArgumentsValidatedBeforeClaims(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background() // no claims
	tests := []struct {
		name    string
		fn      func() (bool, error)
		wantErr error
	}{
		{"HasAnyRole", func() (bool, error) { return f.e.HasAnyRole(ctx) }, ErrInvalidRole},
		{"HasRole", func() (bool, error) { return f.e.HasRole(ctx, "a b") }, ErrInvalidRole},
		{"Can", func() (bool, error) { return f.e.Can(ctx, "posts:*") }, ErrInvalidPermission},
		{"CanAll", func() (bool, error) { return f.e.CanAll(ctx) }, ErrInvalidPermission},
		{"CanAny", func() (bool, error) { return f.e.CanAny(ctx) }, ErrInvalidPermission},
		{"ClaimsHaveAnyRole", func() (bool, error) { return f.e.ClaimsHaveAnyRole(ctx, nil) }, ErrInvalidRole},
		{"ClaimsCanAll", func() (bool, error) { return f.e.ClaimsCanAll(ctx, nil) }, ErrInvalidPermission},
		{"ClaimsCanAny", func() (bool, error) { return f.e.ClaimsCanAny(ctx, nil) }, ErrInvalidPermission},
	}
	for _, tt := range tests {
		if _, err := tt.fn(); !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestPermissions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	got, err := f.e.Permissions(ctx, "alice")
	if want := []string{"comments:read", "posts:read", "posts:write"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("Permissions = %v, %v; want %v", got, err, want)
	}
	f.store.err = errors.New("db down")
	if _, err := f.e.Permissions(ctx, "alice"); !errors.Is(err, f.store.err) {
		t.Errorf("Permissions err = %v, want store error", err)
	}
}

func TestEmbeddedPermissionsArePruned(t *testing.T) {
	f := newFixture(t, WithEmbedPermissions(true))
	f.store.roles["alice"] = []string{"admin"}
	claims, err := f.e.ClaimsProvider(nil)(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	// None of admin's grants covers another, so all are kept.
	want := []string{"*:audit", "comments:read", "posts:read", "posts:write", "users:*"}
	if got := claims["perms"].([]string); !slices.Equal(got, want) {
		t.Errorf("perms = %v, want %v", got, want)
	}

	f.policy.p = mustPolicy(t, map[string]RoleDefinition{
		"viewer": {Permissions: []string{"posts:read"}},
		"editor": {Inherits: []string{"viewer"}, Permissions: []string{"posts:*"}},
	})
	f.store.roles["alice"] = []string{"editor"}
	claims, err = f.e.ClaimsProvider(nil)(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got := claims["perms"].([]string); !slices.Equal(got, []string{"posts:*"}) {
		t.Errorf("perms = %v, want [posts:*]", got)
	}
}

func TestEmbeddedRolesExpansion(t *testing.T) {
	ctx := claimsCtx("alice", map[string]any{"roles": []any{"admin"}})

	f := newFixture(t)
	f.policy.err = errors.New("policy down")
	// A role the token lists directly needs no policy...
	if ok, err := f.e.HasAnyRole(ctx, "viewer", "admin"); !ok || err != nil {
		t.Errorf("HasAnyRole(viewer, admin) with policy down = %v, %v", ok, err)
	}
	if f.policy.calls != 0 {
		t.Errorf("policy loaded %d times for a role in the token", f.policy.calls)
	}
	// ...but an inherited one does, and the policy's error is returned.
	if _, err := f.e.HasRole(ctx, "viewer"); !errors.Is(err, f.policy.err) {
		t.Errorf("policy error: err = %v, want it returned", err)
	}

	// Without a policy, embedded roles are used as they are.
	e, err := newWithSource(WithEmbedPermissions(true))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.HasRole(ctx, "admin"); !ok || err != nil {
		t.Errorf("HasRole(admin) = %v, %v", ok, err)
	}
	if ok, err := e.HasRole(ctx, "viewer"); ok || err != nil {
		t.Errorf("HasRole(viewer) = %v, %v; want false without a policy", ok, err)
	}
}

func TestEmbeddedExceptions(t *testing.T) {
	p := mustPolicy(t, map[string]RoleDefinition{
		"viewer": {Permissions: []string{"files:read", "comments:read"}},
		"editor": {Inherits: []string{"viewer"}, Permissions: []string{"files:*"}, Except: []string{"files:delete"}},
	})
	for name, opts := range embedConfigs {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, append(opts, WithPolicy(p))...)
			claims := f.tokenClaims(t, "alice")
			if perms, ok := claims["perms"]; ok {
				// files:read, from viewer, is covered by editor's grant.
				want := []any{"comments:read", "files:* -files:delete"}
				if !slices.Equal(perms.([]any), want) {
					t.Errorf("perms claim = %q, want %q", perms, want)
				}
			}
			ctx := claimsCtx("alice", claims)
			for perm, want := range map[string]bool{
				"files:write":   true,
				"files:read":    true,
				"files:delete":  false,
				"comments:read": true,
			} {
				if ok, err := f.e.Can(ctx, perm); ok != want || err != nil {
					t.Errorf("Can(%q) = %v, %v; want %v", perm, ok, err, want)
				}
			}
		})
	}
}
