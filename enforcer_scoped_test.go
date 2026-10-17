package rbac

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tpyle/auth/v2"
)

// countingScopedStore is a ScopedRoleStore over a MemoryScopedRoleStore that
// records lookups.
type countingScopedStore struct {
	*MemoryScopedRoleStore
	err   error
	calls int
}

func (s *countingScopedStore) Bindings(ctx context.Context, subject string, scopes []string) ([]Binding, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.MemoryScopedRoleStore.Bindings(ctx, subject, scopes)
}

// countingResolver is a ScopeResolver over PathScopes that records calls.
type countingResolver struct {
	calls int
}

func (r *countingResolver) Scopes(ctx context.Context, resource string) ([]string, error) {
	r.calls++
	return PathScopes().Scopes(ctx, resource)
}

type scopedFixture struct {
	*fixture
	scoped   *countingScopedStore
	resolver *countingResolver
}

// newScopedFixture extends newFixture (alice is a global editor, bob has no
// roles) with bindings for carol, who has no global roles:
//
//	projects/42             editor
//	projects/*/docs         auditor
//	projects/**/secret      admin
//	projects/99             viewer
//
// and for alice, who is also bound as admin on projects/7.
func newScopedFixture(t *testing.T, opts ...Option) *scopedFixture {
	t.Helper()
	mem := NewMemoryScopedRoleStore()
	mustBind(t, mem, "carol", "projects/42", "editor")
	mustBind(t, mem, "carol", "projects/*/docs", "auditor")
	mustBind(t, mem, "carol", "projects/**/secret", "admin")
	mustBind(t, mem, "carol", "projects/99", "viewer")
	mustBind(t, mem, "alice", "projects/7", "admin")
	sf := &scopedFixture{scoped: &countingScopedStore{MemoryScopedRoleStore: mem}, resolver: &countingResolver{}}
	base := []Option{WithScopedRoleStore(sf.scoped), WithScopeResolver(sf.resolver)}
	sf.fixture = newFixture(t, append(base, opts...)...)
	return sf
}

func (f *scopedFixture) reset() {
	f.fixture.reset()
	f.scoped.calls, f.resolver.calls = 0, 0
}

// embedConfigs are the four combinations of embedded claims.
var embedConfigs = map[string][]Option{
	"nothing":     {WithEmbedRoles(false)},
	"roles":       nil,
	"permissions": {WithEmbedRoles(false), WithEmbedPermissions(true)},
	"both":        {WithEmbedPermissions(true)},
}

func TestCanOn(t *testing.T) {
	tests := []struct {
		name               string
		subject, resource  string
		perm               string
		want               bool
		wantScopedLookups  int
		wantResolverCalled bool
	}{
		{"global grant", "alice", "projects/1", "posts:write", true, 0, false},
		{"global grant misses", "alice", "projects/42", "users:delete", false, 1, true},
		{"binding on resource", "carol", "projects/42", "posts:write", true, 1, true},
		{"binding on ancestor", "carol", "projects/42/docs/7", "posts:write", true, 1, true},
		{"inherited through binding", "carol", "projects/42", "comments:read", true, 1, true},
		{"binding elsewhere", "carol", "projects/43", "posts:read", false, 1, true},
		{"binding on descendant only", "carol", "projects", "posts:read", false, 1, true},
		{"* pattern", "carol", "projects/43/docs", "billing:audit", true, 1, true},
		{"* pattern via ancestor", "carol", "projects/43/docs/9", "billing:audit", true, 1, true},
		{"* pattern does not match parent", "carol", "projects/43", "billing:audit", false, 1, true},
		{"** pattern", "carol", "projects/43/a/b/secret", "users:delete", true, 1, true},
		{"** pattern, zero segments", "carol", "projects/secret", "users:delete", true, 1, true},
		{"** pattern via ancestor", "carol", "projects/43/secret/file", "users:delete", true, 1, true},
		{"** pattern no match", "carol", "projects/43/secrets", "users:delete", false, 1, true},
		{"no grants at all", "bob", "projects/42", "posts:read", false, 1, true},
	}
	for cfgName, cfg := range embedConfigs {
		for _, tt := range tests {
			t.Run(cfgName+"/"+tt.name, func(t *testing.T) {
				f := newScopedFixture(t, cfg...)
				ctx := claimsCtx(tt.subject, f.tokenClaims(t, tt.subject))
				f.reset()
				got, err := f.e.CanOn(ctx, tt.resource, tt.perm)
				if err != nil || got != tt.want {
					t.Fatalf("CanOn(%q, %q) = %v, %v; want %v", tt.resource, tt.perm, got, err, tt.want)
				}
				if f.scoped.calls != tt.wantScopedLookups || (f.resolver.calls > 0) != tt.wantResolverCalled {
					t.Errorf("scoped lookups = %d, resolver calls = %d", f.scoped.calls, f.resolver.calls)
				}
				// The token-free check agrees.
				got, err = f.e.SubjectCanOn(context.Background(), tt.subject, tt.resource, tt.perm)
				if err != nil || got != tt.want {
					t.Errorf("SubjectCanOn = %v, %v; want %v", got, err, tt.want)
				}
			})
		}
	}
}

func TestHasRoleOn(t *testing.T) {
	tests := []struct {
		name              string
		subject, resource string
		role              string
		want              bool
		wantScopedLookups int
	}{
		{"global role", "alice", "projects/1", "editor", true, 0},
		{"global inherited role", "alice", "projects/1", "viewer", true, 0},
		{"bound role", "carol", "projects/42/docs/7", "editor", true, 1},
		{"bound inherited role", "carol", "projects/42", "viewer", true, 1},
		{"bound elsewhere", "carol", "projects/43", "editor", false, 1},
		{"pattern binding", "carol", "projects/43/docs/1", "auditor", true, 1},
		{"bound on resource, global elsewhere", "alice", "projects/7", "admin", true, 1},
		{"not bound", "alice", "projects/8", "admin", false, 1},
		{"nobody", "bob", "projects/42", "viewer", false, 1},
	}
	for cfgName, cfg := range embedConfigs {
		for _, tt := range tests {
			t.Run(cfgName+"/"+tt.name, func(t *testing.T) {
				f := newScopedFixture(t, cfg...)
				ctx := claimsCtx(tt.subject, f.tokenClaims(t, tt.subject))
				f.reset()
				got, err := f.e.HasRoleOn(ctx, tt.resource, tt.role)
				if err != nil || got != tt.want {
					t.Fatalf("HasRoleOn(%q, %q) = %v, %v; want %v", tt.resource, tt.role, got, err, tt.want)
				}
				if f.scoped.calls != tt.wantScopedLookups {
					t.Errorf("scoped lookups = %d, want %d", f.scoped.calls, tt.wantScopedLookups)
				}
				got, err = f.e.SubjectHasRoleOn(context.Background(), tt.subject, tt.resource, tt.role)
				if err != nil || got != tt.want {
					t.Errorf("SubjectHasRoleOn = %v, %v; want %v", got, err, tt.want)
				}
			})
		}
	}
}

func TestScopedMultiChecks(t *testing.T) {
	f := newScopedFixture(t)
	alice := claimsCtx("alice", f.tokenClaims(t, "alice"))
	carol := claimsCtx("carol", f.tokenClaims(t, "carol"))
	tests := []struct {
		name  string
		check func() (bool, error)
		want  bool
		calls int
	}{
		// posts:write is global and users:delete comes from the binding.
		{"all, mixed sources", func() (bool, error) { return f.e.CanAllOn(alice, "projects/7", "posts:write", "users:delete") }, true, 1},
		{"all, binding missing", func() (bool, error) { return f.e.CanAllOn(alice, "projects/8", "posts:write", "users:delete") }, false, 1},
		{"all, global suffices", func() (bool, error) { return f.e.CanAllOn(alice, "projects/8", "posts:write", "posts:read") }, true, 0},
		{"any, global suffices", func() (bool, error) { return f.e.CanAnyOn(alice, "projects/8", "users:delete", "posts:read") }, true, 0},
		{"any, from binding", func() (bool, error) { return f.e.CanAnyOn(carol, "projects/42", "users:delete", "posts:write") }, true, 1},
		{"any, none", func() (bool, error) { return f.e.CanAnyOn(carol, "projects/42", "users:delete", "billing:audit") }, false, 1},
		{"any role", func() (bool, error) { return f.e.HasAnyRoleOn(carol, "projects/42", "admin", "editor") }, true, 1},
		{"any role, none", func() (bool, error) { return f.e.HasAnyRoleOn(carol, "projects/43", "admin", "editor") }, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.reset()
			got, err := tt.check()
			if err != nil || got != tt.want {
				t.Errorf("= %v, %v; want %v", got, err, tt.want)
			}
			if f.scoped.calls != tt.calls {
				t.Errorf("scoped lookups = %d, want %d", f.scoped.calls, tt.calls)
			}
		})
	}
}

func TestScopedExplicitClaims(t *testing.T) {
	f := newScopedFixture(t)
	c := &auth.Claims{Subject: "carol", Extra: f.tokenClaims(t, "carol")}
	ctx := context.Background()
	if ok, err := f.e.ClaimsCanAllOn(ctx, c, "projects/42", "posts:write"); !ok || err != nil {
		t.Errorf("ClaimsCanAllOn = %v, %v", ok, err)
	}
	if ok, err := f.e.ClaimsCanAnyOn(ctx, c, "projects/43", "posts:write", "posts:read"); ok || err != nil {
		t.Errorf("ClaimsCanAnyOn = %v, %v", ok, err)
	}
	if ok, err := f.e.ClaimsHaveAnyRoleOn(ctx, c, "projects/42", "editor"); !ok || err != nil {
		t.Errorf("ClaimsHaveAnyRoleOn = %v, %v", ok, err)
	}
	for name, check := range map[string]func() (bool, error){
		"ClaimsCanAllOn":      func() (bool, error) { return f.e.ClaimsCanAllOn(ctx, nil, "p", "a:b") },
		"ClaimsCanAnyOn":      func() (bool, error) { return f.e.ClaimsCanAnyOn(ctx, nil, "p", "a:b") },
		"ClaimsHaveAnyRoleOn": func() (bool, error) { return f.e.ClaimsHaveAnyRoleOn(ctx, nil, "p", "r") },
	} {
		if _, err := check(); !errors.Is(err, ErrNoClaims) {
			t.Errorf("%s(nil claims) err = %v, want ErrNoClaims", name, err)
		}
	}
}

func TestScopedArgumentErrors(t *testing.T) {
	f := newScopedFixture(t)
	anon := context.Background()
	carol := claimsCtx("carol", nil)
	c := &auth.Claims{Subject: "carol"}
	tests := []struct {
		name  string
		check func() (bool, error)
		want  error
	}{
		// Arguments are validated before the context is consulted.
		{"CanOn bad perm", func() (bool, error) { return f.e.CanOn(anon, "projects/1", "posts:*") }, ErrInvalidPermission},
		{"CanOn bad perm before scope", func() (bool, error) { return f.e.CanOn(anon, "projects/*", "posts:") }, ErrInvalidPermission},
		{"CanOn bad scope", func() (bool, error) { return f.e.CanOn(anon, "projects/*", "posts:read") }, ErrInvalidScope},
		{"CanOn empty scope", func() (bool, error) { return f.e.CanOn(carol, "", "posts:read") }, ErrInvalidScope},
		{"CanOn no claims", func() (bool, error) { return f.e.CanOn(anon, "projects/1", "posts:read") }, ErrNoClaims},
		{"CanAllOn no perms", func() (bool, error) { return f.e.CanAllOn(carol, "projects/1") }, ErrInvalidPermission},
		{"CanAnyOn no perms", func() (bool, error) { return f.e.CanAnyOn(carol, "projects/1") }, ErrInvalidPermission},
		{"CanAnyOn bad scope", func() (bool, error) { return f.e.CanAnyOn(anon, "a//b", "x") }, ErrInvalidScope},
		{"HasRoleOn bad role", func() (bool, error) { return f.e.HasRoleOn(anon, "projects/*", "a b") }, ErrInvalidRole},
		{"HasRoleOn bad scope", func() (bool, error) { return f.e.HasRoleOn(anon, "projects/", "editor") }, ErrInvalidScope},
		{"HasRoleOn no claims", func() (bool, error) { return f.e.HasRoleOn(anon, "projects/1", "editor") }, ErrNoClaims},
		{"HasAnyRoleOn no roles", func() (bool, error) { return f.e.HasAnyRoleOn(carol, "projects/1") }, ErrInvalidRole},
		{"ClaimsCanAllOn bad scope", func() (bool, error) { return f.e.ClaimsCanAllOn(anon, c, "**", "x") }, ErrInvalidScope},
		{"ClaimsCanAnyOn bad perm", func() (bool, error) { return f.e.ClaimsCanAnyOn(anon, c, "p", "**") }, ErrInvalidPermission},
		{"ClaimsHaveAnyRoleOn bad scope", func() (bool, error) { return f.e.ClaimsHaveAnyRoleOn(anon, c, "a b", "r") }, ErrInvalidScope},
		{"SubjectCanOn bad perm", func() (bool, error) { return f.e.SubjectCanOn(anon, "carol", "p", "*") }, ErrInvalidPermission},
		{"SubjectCanOn bad scope", func() (bool, error) { return f.e.SubjectCanOn(anon, "carol", "p/*", "a") }, ErrInvalidScope},
		{"SubjectHasRoleOn bad role", func() (bool, error) { return f.e.SubjectHasRoleOn(anon, "carol", "p", "") }, ErrInvalidRole},
		{"SubjectHasRoleOn bad scope", func() (bool, error) { return f.e.SubjectHasRoleOn(anon, "carol", "/p", "r") }, ErrInvalidScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.reset()
			ok, err := tt.check()
			if ok || !errors.Is(err, tt.want) {
				t.Errorf("= %v, %v; want %v", ok, err, tt.want)
			}
			if f.scoped.calls != 0 || f.resolver.calls != 0 {
				t.Errorf("backends consulted: scoped %d, resolver %d", f.scoped.calls, f.resolver.calls)
			}
		})
	}
}

func TestScopedBackendErrors(t *testing.T) {
	errBackend := errors.New("backend down")
	carolCtx := func(t *testing.T, opts ...Option) (*Enforcer, context.Context) {
		t.Helper()
		f := newScopedFixture(t, opts...)
		return f.e, claimsCtx("carol", f.tokenClaims(t, "carol"))
	}
	resolverReturning := func(scopes []string, err error) Option {
		return WithScopeResolver(ScopeResolverFunc(func(context.Context, string) ([]string, error) { return scopes, err }))
	}
	storeReturning := func(b []Binding, err error) Option {
		return WithScopedRoleStore(ScopedRoleStoreFunc(func(context.Context, string, []string) ([]Binding, error) { return b, err }))
	}
	tests := []struct {
		name        string
		opts        []Option
		want        error // nil means any error
		notScopeErr bool  // the error must not wrap ErrInvalidScope
	}{
		{"resolver error", []Option{resolverReturning(nil, errBackend)}, errBackend, false},
		{"resolver rejects resource", []Option{resolverReturning(nil, ErrInvalidScope)}, ErrInvalidScope, false},
		{"resolver returns invalid scope", []Option{resolverReturning([]string{"projects/*"}, nil)}, nil, true},
		{"store error", []Option{storeReturning(nil, errBackend)}, errBackend, false},
		{"store error wrapping ErrInvalidScope", []Option{storeReturning(nil, fmt.Errorf("bad row: %w", ErrInvalidScope))}, nil, true},
		{"store returns invalid scope", []Option{storeReturning([]Binding{{Scope: "a//b", Role: "editor"}}, nil)}, nil, true},
		{"store returns invalid role", []Option{storeReturning([]Binding{{Scope: "projects/42", Role: ""}}, nil)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ctx := carolCtx(t, tt.opts...)
			checks := map[string]func() (bool, error){
				"CanOn":            func() (bool, error) { return e.CanOn(ctx, "projects/42", "posts:read") },
				"HasRoleOn":        func() (bool, error) { return e.HasRoleOn(ctx, "projects/42", "viewer") },
				"SubjectCanOn":     func() (bool, error) { return e.SubjectCanOn(ctx, "carol", "projects/42", "posts:read") },
				"SubjectHasRoleOn": func() (bool, error) { return e.SubjectHasRoleOn(ctx, "carol", "projects/42", "viewer") },
			}
			for name, check := range checks {
				ok, err := check()
				if ok || err == nil {
					t.Errorf("%s = %v, %v; want an error", name, ok, err)
					continue
				}
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Errorf("%s err = %v, want %v", name, err, tt.want)
				}
				if tt.notScopeErr && errors.Is(err, ErrInvalidScope) {
					t.Errorf("%s err = %v wraps ErrInvalidScope, but it is an internal error", name, err)
				}
			}
		})
	}
}

func TestScopedPolicyErrors(t *testing.T) {
	f := newScopedFixture(t)
	carol := claimsCtx("carol", f.tokenClaims(t, "carol"))
	errPolicy := errors.New("policy down")
	f.policy.err, f.policy.p = errPolicy, nil

	if _, err := f.e.CanOn(carol, "projects/42", "posts:read"); !errors.Is(err, errPolicy) {
		t.Errorf("CanOn err = %v, want policy error", err)
	}
	// A directly bound role needs no policy.
	if ok, err := f.e.HasRoleOn(carol, "projects/42", "editor"); !ok || err != nil {
		t.Errorf("HasRoleOn(editor) = %v, %v", ok, err)
	}
	if _, err := f.e.HasRoleOn(carol, "projects/42", "viewer"); !errors.Is(err, errPolicy) {
		t.Errorf("HasRoleOn(viewer) err = %v, want policy error", err)
	}
	// Without bindings, there is nothing to look up in the policy.
	f.reset()
	if ok, err := f.e.ClaimsCanAllOn(context.Background(), &auth.Claims{Subject: "bob", Extra: map[string]any{"roles": []any{}}}, "projects/42", "posts:read"); ok || err != nil {
		t.Errorf("ClaimsCanAllOn(bob) = %v, %v", ok, err)
	}
	if f.policy.calls != 0 {
		t.Errorf("policy loads = %d, want 0", f.policy.calls)
	}
}

func TestScopedNotConfigured(t *testing.T) {
	// No scoped store: every scoped check fails, even one that global grants
	// would answer, and before the claims are consulted.
	f := newFixture(t)
	alice := claimsCtx("alice", f.tokenClaims(t, "alice"))
	for name, check := range map[string]func() (bool, error){
		"CanOn(global)":     func() (bool, error) { return f.e.CanOn(alice, "projects/1", "posts:write") },
		"HasRoleOn(global)": func() (bool, error) { return f.e.HasRoleOn(alice, "projects/1", "editor") },
		"CanOn":             func() (bool, error) { return f.e.CanOn(alice, "projects/1", "users:delete") },
		"HasRoleOn":         func() (bool, error) { return f.e.HasRoleOn(alice, "projects/1", "admin") },
		"no claims":         func() (bool, error) { return f.e.CanOn(context.Background(), "projects/1", "posts:read") },
		"invalid resource":  func() (bool, error) { return f.e.CanOn(alice, "projects/*", "posts:read") },
		"SubjectCanOn":      func() (bool, error) { return f.e.SubjectCanOn(alice, "alice", "projects/1", "users:delete") },
		"SubjectHasRoleOn":  func() (bool, error) { return f.e.SubjectHasRoleOn(alice, "alice", "projects/1", "admin") },
	} {
		if _, err := check(); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s err = %v, want ErrNotConfigured", name, err)
		}
	}
	if _, err := f.e.CanOn(alice, "projects/1", "posts:*"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("invalid permission err = %v, want ErrInvalidPermission first", err)
	}

	// Permissions embedded and no policy: bound roles cannot become
	// permissions, but direct role checks work.
	mem := NewMemoryScopedRoleStore()
	mustBind(t, mem, "carol", "projects/42", "editor")
	e, err := New(WithEmbedRoles(false), WithEmbedPermissions(true), WithScopedRoleStore(mem))
	if err != nil {
		t.Fatal(err)
	}
	carol := claimsCtx("carol", map[string]any{"perms": []any{}})
	if _, err := e.CanOn(carol, "projects/42", "posts:write"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("CanOn without policy err = %v, want ErrNotConfigured", err)
	}
	if ok, err := e.HasRoleOn(carol, "projects/42", "editor"); !ok || err != nil {
		t.Errorf("HasRoleOn(editor) without policy = %v, %v", ok, err)
	}
	if ok, err := e.HasRoleOn(carol, "projects/42", "viewer"); ok || err != nil {
		t.Errorf("HasRoleOn(viewer) without policy = %v, %v; want false, as nothing says editor inherits it", ok, err)
	}
}

func TestScopedOnlyDeployment(t *testing.T) {
	// No RoleStore: users have no global grants unless the token says so.
	mem := NewMemoryScopedRoleStore()
	mustBind(t, mem, "carol", "projects/42", "editor")
	p := mustPolicy(t, testDefs)
	for name, opts := range map[string][]Option{
		"nothing embedded": {WithEmbedRoles(false)},
		"roles embedded":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			e, err := New(append([]Option{WithPolicy(p), WithScopedRoleStore(mem)}, opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			carol := claimsCtx("carol", map[string]any{})
			if ok, err := e.CanOn(carol, "projects/42/docs/1", "posts:write"); !ok || err != nil {
				t.Errorf("CanOn = %v, %v", ok, err)
			}
			if ok, err := e.CanOn(carol, "projects/43", "posts:write"); ok || err != nil {
				t.Errorf("CanOn(elsewhere) = %v, %v", ok, err)
			}
			if ok, err := e.HasRoleOn(carol, "projects/42", "viewer"); !ok || err != nil {
				t.Errorf("HasRoleOn = %v, %v", ok, err)
			}
			if ok, err := e.SubjectCanOn(context.Background(), "carol", "projects/42", "posts:write"); !ok || err != nil {
				t.Errorf("SubjectCanOn = %v, %v", ok, err)
			}
			if ok, err := e.SubjectHasRoleOn(context.Background(), "carol", "projects/42", "editor"); !ok || err != nil {
				t.Errorf("SubjectHasRoleOn = %v, %v", ok, err)
			}
			// Global checks still need a source of global roles.
			if _, err := e.Can(carol, "posts:write"); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("Can err = %v, want ErrNotConfigured", err)
			}
			// A token that does carry roles still grants globally.
			admin := claimsCtx("carol", map[string]any{"roles": []any{"admin"}})
			if ok, err := e.CanOn(admin, "projects/43", "users:delete"); (name == "roles embedded") != ok || err != nil {
				t.Errorf("CanOn(admin token) = %v, %v", ok, err)
			}
		})
	}
}

func TestScopedOverReturningStore(t *testing.T) {
	// A store may return every binding of the subject; only matching ones
	// count.
	all := []Binding{
		{Scope: "projects/43", Role: "admin"},
		{Scope: "projects/*/docs/*", Role: "admin"},
		{Scope: "users/**", Role: "admin"},
		{Scope: "projects/42", Role: "viewer"},
	}
	var gotScopes []string
	store := ScopedRoleStoreFunc(func(_ context.Context, _ string, scopes []string) ([]Binding, error) {
		gotScopes = scopes
		scopes[0] = "tampered" // must not affect matching
		return all, nil
	})
	e, err := New(WithEmbedRoles(false), WithPolicy(mustPolicy(t, testDefs)), WithScopedRoleStore(store))
	if err != nil {
		t.Fatal(err)
	}
	ctx := claimsCtx("carol", nil)
	if ok, err := e.CanOn(ctx, "projects/42/docs", "users:delete"); ok || err != nil {
		t.Errorf("CanOn(users:delete) = %v, %v; want false", ok, err)
	}
	if ok, err := e.CanOn(ctx, "projects/42/docs", "posts:read"); !ok || err != nil {
		t.Errorf("CanOn(posts:read) = %v, %v; want true", ok, err)
	}
	if ok, err := e.CanOn(ctx, "projects/42/docs/1", "users:delete"); !ok || err != nil {
		t.Errorf("CanOn(docs/1, users:delete) = %v, %v; want true", ok, err)
	}
	if len(gotScopes) != 4 {
		t.Errorf("store got scopes %v", gotScopes)
	}
}

func TestScopedEmptyResolver(t *testing.T) {
	f := newScopedFixture(t, WithScopeResolver(ScopeResolverFunc(func(context.Context, string) ([]string, error) {
		return nil, nil
	})))
	carol := claimsCtx("carol", f.tokenClaims(t, "carol"))
	f.reset()
	if ok, err := f.e.CanOn(carol, "projects/42", "posts:read"); ok || err != nil {
		t.Errorf("CanOn = %v, %v", ok, err)
	}
	if f.scoped.calls != 0 {
		t.Errorf("store called %d times for no scopes", f.scoped.calls)
	}
}

func TestScopedContextPropagates(t *testing.T) {
	store := ScopedRoleStoreFunc(func(ctx context.Context, _ string, _ []string) ([]Binding, error) {
		return nil, ctx.Err()
	})
	e, err := New(WithEmbedRoles(false), WithPolicy(mustPolicy(t, testDefs)), WithScopedRoleStore(store))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(claimsCtx("carol", nil))
	cancel()
	if _, err := e.CanOn(ctx, "projects/1", "posts:read"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestScopedGlobalRoleStoreErrors(t *testing.T) {
	f := newScopedFixture(t, WithEmbedRoles(false))
	f.store.err = errors.New("db down")
	ctx := claimsCtx("carol", map[string]any{})
	for name, check := range map[string]func() (bool, error){
		"CanOn":            func() (bool, error) { return f.e.CanOn(ctx, "projects/42", "posts:read") },
		"HasRoleOn":        func() (bool, error) { return f.e.HasRoleOn(ctx, "projects/42", "editor") },
		"SubjectCanOn":     func() (bool, error) { return f.e.SubjectCanOn(ctx, "carol", "projects/42", "posts:read") },
		"SubjectHasRoleOn": func() (bool, error) { return f.e.SubjectHasRoleOn(ctx, "carol", "projects/42", "editor") },
	} {
		if _, err := check(); !errors.Is(err, f.store.err) {
			t.Errorf("%s err = %v, want the role store error", name, err)
		}
	}
}

func TestScopedRolesOnly(t *testing.T) {
	// alice is a global editor in the RoleStore and bound as admin on
	// projects/7; her token claims to be a global admin.
	f := newScopedFixture(t, WithScopedRolesOnly())
	if cfg := f.e.Config(); !cfg.ScopedRolesOnly || cfg.EmbedRoles || cfg.EmbedPermissions {
		t.Fatalf("Config() = %+v, want ScopedRolesOnly without embedding", cfg)
	}
	alice := claimsCtx("alice", map[string]any{"roles": []any{"admin"}, "perms": []any{"**"}})
	ctx := context.Background()
	checks := []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"CanOn bound", func() (bool, error) { return f.e.CanOn(alice, "projects/7/docs/1", "users:delete") }, true},
		{"CanOn unbound", func() (bool, error) { return f.e.CanOn(alice, "projects/1", "posts:write") }, false},
		{"HasRoleOn bound", func() (bool, error) { return f.e.HasRoleOn(alice, "projects/7", "editor") }, true},
		{"HasRoleOn unbound", func() (bool, error) { return f.e.HasRoleOn(alice, "projects/1", "admin") }, false},
		{"SubjectCanOn bound", func() (bool, error) { return f.e.SubjectCanOn(ctx, "alice", "projects/7", "users:delete") }, true},
		{"SubjectCanOn unbound", func() (bool, error) { return f.e.SubjectCanOn(ctx, "alice", "projects/1", "posts:write") }, false},
		{"SubjectHasRoleOn bound", func() (bool, error) { return f.e.SubjectHasRoleOn(ctx, "alice", "projects/7", "admin") }, true},
		{"SubjectHasRoleOn unbound", func() (bool, error) { return f.e.SubjectHasRoleOn(ctx, "alice", "projects/1", "editor") }, false},
	}
	for _, c := range checks {
		f.reset()
		if ok, err := c.check(); ok != c.want || err != nil {
			t.Errorf("%s = %v, %v; want %v", c.name, ok, err, c.want)
		}
		if f.store.calls != 0 {
			t.Errorf("%s consulted the RoleStore", c.name)
		}
	}
	for name, check := range map[string]func() (bool, error){
		"Can":            func() (bool, error) { return f.e.Can(alice, "posts:read") },
		"HasRole":        func() (bool, error) { return f.e.HasRole(alice, "admin") },
		"CanAny":         func() (bool, error) { return f.e.CanAny(alice, "posts:read") },
		"SubjectCan":     func() (bool, error) { return f.e.SubjectCan(ctx, "alice", "posts:read") },
		"SubjectHasRole": func() (bool, error) { return f.e.SubjectHasRole(ctx, "alice", "editor") },
	} {
		f.reset()
		if _, err := check(); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s err = %v, want ErrNotConfigured", name, err)
		}
		if f.store.calls != 0 {
			t.Errorf("%s consulted the RoleStore", name)
		}
	}
	// Invalid arguments are still reported first.
	if _, err := f.e.SubjectCan(ctx, "alice", "posts:*"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("SubjectCan(wildcard) err = %v, want ErrInvalidPermission", err)
	}
	// Store queries still report the RoleStore's contents.
	if roles, err := f.e.EffectiveRoles(ctx, "alice"); err != nil || len(roles) == 0 {
		t.Errorf("EffectiveRoles = %v, %v; want alice's stored roles", roles, err)
	}
	// Issuing claims embeds nothing.
	if claims := f.tokenClaims(t, "alice"); len(claims) != 0 {
		t.Errorf("claims = %v, want none", claims)
	}
}
