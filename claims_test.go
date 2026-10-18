package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newWithSource is [New] with claims read from [ContextWithClaims], as most
// tests put them there.
func newWithSource(opts ...Option) (*Enforcer, error) {
	return New(append([]Option{WithClaimsSource(ClaimsFromContext)}, opts...)...)
}

func TestClaimsFromContext(t *testing.T) {
	if c, ok := ClaimsFromContext(context.Background()); ok || c != nil {
		t.Errorf("empty context: got %v, %v; want nil, false", c, ok)
	}
	if c, ok := ClaimsFromContext(ContextWithClaims(context.Background(), nil)); ok || c != nil {
		t.Errorf("nil claims: got %v, %v; want nil, false", c, ok)
	}
	want := &Claims{Subject: "alice"}
	if c, ok := ClaimsFromContext(ContextWithClaims(context.Background(), want)); !ok || c != want {
		t.Errorf("got %v, %v; want %v, true", c, ok, want)
	}
}

// otherKey stands in for the context key of an authentication library.
type otherKey struct{}

func otherSource(ctx context.Context) (*Claims, bool) {
	subject, ok := ctx.Value(otherKey{}).(string)
	if !ok {
		return nil, false
	}
	return &Claims{Subject: subject, Values: map[string]any{"roles": []any{"admin"}}}, true
}

func TestWithClaimsSource(t *testing.T) {
	p := mustPolicy(t, testDefs)
	e, err := New(WithPolicy(p), WithClaimsSource(otherSource))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), otherKey{}, "alice")
	if ok, err := e.Can(ctx, "users:delete"); !ok || err != nil {
		t.Errorf("Can() = %v, %v; want true, nil", ok, err)
	}
	// Only the configured source is consulted.
	rbacCtx := ContextWithClaims(context.Background(), &Claims{Subject: "alice", Values: map[string]any{"roles": []any{"admin"}}})
	if _, err := e.Can(rbacCtx, "users:delete"); !errors.Is(err, ErrNoClaims) {
		t.Errorf("Can() with rbac context err = %v, want ErrNoClaims", err)
	}

	h := e.RequireAllPermissions("users:delete")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodDelete, "/users/1", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("middleware status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestNoClaimsSource(t *testing.T) {
	p := mustPolicy(t, testDefs)
	scoped := NewMemoryScopedRoleStore()
	for name, opts := range map[string][]Option{
		"never set":  {WithPolicy(p), WithScopedRoleStore(scoped)},
		"set to nil": {WithPolicy(p), WithScopedRoleStore(scoped), WithClaimsSource(otherSource), WithClaimsSource(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := New(opts...)
			if err != nil {
				t.Fatalf("New() err = %v; a source is not required to build", err)
			}
			ctx := claimsCtx("alice", map[string]any{"roles": []any{"admin"}})
			checks := map[string]func() (bool, error){
				"HasRole":      func() (bool, error) { return e.HasRole(ctx, "admin") },
				"Can":          func() (bool, error) { return e.Can(ctx, "users:delete") },
				"CanAny":       func() (bool, error) { return e.CanAny(ctx, "users:delete") },
				"HasRoleOn":    func() (bool, error) { return e.HasRoleOn(ctx, "projects/1", "admin") },
				"CanOn":        func() (bool, error) { return e.CanOn(ctx, "projects/1", "users:delete") },
				"CanAnyOn":     func() (bool, error) { return e.CanAnyOn(ctx, "projects/1", "users:delete") },
				"HasAnyRoleOn": func() (bool, error) { return e.HasAnyRoleOn(ctx, "projects/1", "admin") },
			}
			for check, f := range checks {
				if _, err := f(); !errors.Is(err, ErrNotConfigured) {
					t.Errorf("%s err = %v, want ErrNotConfigured", check, err)
				}
			}
			// Arguments are still validated first.
			if _, err := e.Can(ctx, "posts:*"); !errors.Is(err, ErrInvalidPermission) {
				t.Errorf("Can(invalid) err = %v, want ErrInvalidPermission", err)
			}
			// Explicit claims need no source.
			c := &Claims{Subject: "alice", Values: map[string]any{"roles": []any{"admin"}}}
			if ok, err := e.ClaimsCanAll(context.Background(), c, "users:delete"); !ok || err != nil {
				t.Errorf("ClaimsCanAll() = %v, %v; want true, nil", ok, err)
			}
			for mw, build := range map[string]func(){
				"RequireAnyRole":          func() { e.RequireAnyRole("admin") },
				"RequireAllPermissions":   func() { e.RequireAllPermissions("users:delete") },
				"RequireAnyPermission":    func() { e.RequireAnyPermission("users:delete") },
				"RequireAnyRoleOn":        func() { e.RequireAnyRoleOn(PathResource("projects/{id}"), "admin") },
				"RequireAllPermissionsOn": func() { e.RequireAllPermissionsOn(PathResource("projects/{id}"), "users:delete") },
				"RequireAnyPermissionOn":  func() { e.RequireAnyPermissionOn(PathResource("projects/{id}"), "users:delete") },
			} {
				t.Run(mw, func(t *testing.T) {
					defer func() {
						err, _ := recover().(error)
						if !errors.Is(err, ErrNotConfigured) {
							t.Errorf("panic = %v, want ErrNotConfigured", err)
						}
					}()
					build()
				})
			}
		})
	}
}

func TestClaimsFromContextSource(t *testing.T) {
	e, err := New(WithPolicy(mustPolicy(t, testDefs)), WithClaimsSource(ClaimsFromContext))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.HasRole(claimsCtx("alice", map[string]any{"roles": []any{"viewer"}}), "viewer"); !ok || err != nil {
		t.Errorf("HasRole() = %v, %v; want true, nil", ok, err)
	}
}

func TestClaimsSourceReturningNil(t *testing.T) {
	src := func(context.Context) (*Claims, bool) { return nil, true }
	e, err := New(WithPolicy(mustPolicy(t, testDefs)), WithClaimsSource(src))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Can(context.Background(), "posts:read"); !errors.Is(err, ErrNoClaims) {
		t.Errorf("Can() err = %v, want ErrNoClaims", err)
	}
}

func TestNilValuesMeansNoClaims(t *testing.T) {
	f := newFixture(t)
	// Without the roles claim, the store is consulted: alice is an editor.
	if ok, err := f.e.Can(claimsCtx("alice", nil), "posts:write"); !ok || err != nil {
		t.Errorf("Can() = %v, %v; want true, nil", ok, err)
	}
	if f.store.calls != 1 {
		t.Errorf("store calls = %d, want 1", f.store.calls)
	}
}

func TestWithReservedClaims(t *testing.T) {
	p := mustPolicy(t, testDefs)
	reserved := func(name string) bool { return name == "typ" }
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{"typ allowed by default", []Option{WithRolesClaim("typ")}, false},
		{"roles claim reserved", []Option{WithReservedClaims(reserved), WithRolesClaim("typ")}, true},
		{"permissions claim reserved", []Option{WithReservedClaims(reserved), WithPermissionsClaim("typ")}, true},
		{"reserved checked even if not embedded", []Option{WithReservedClaims(reserved), WithEmbedPermissions(false), WithPermissionsClaim("typ")}, true},
		{"other names allowed", []Option{WithReservedClaims(reserved)}, false},
		{"nil reserves nothing", []Option{WithReservedClaims(reserved), WithReservedClaims(nil), WithRolesClaim("typ")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(append([]Option{WithPolicy(p)}, tt.opts...)...)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("New() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegisteredClaimsRejected(t *testing.T) {
	for name := range registeredClaims {
		c := DefaultConfig()
		c.RolesClaim = name
		if err := c.Validate(); err == nil {
			t.Errorf("RolesClaim %q: Validate() = nil, want error", name)
		}
	}
}

func TestWithOptions(t *testing.T) {
	p := mustPolicy(t, testDefs)
	e, err := New(
		WithOptions(WithPolicy(p), WithRolesClaim("a"), WithRolesClaim("b")),
		WithOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Config().RolesClaim; got != "b" {
		t.Errorf("RolesClaim = %q, want %q (options applied in order)", got, "b")
	}
	// Options after WithOptions override it.
	e, err = New(WithOptions(WithPolicy(p), WithRolesClaim("a")), WithRolesClaim("c"))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Config().RolesClaim; got != "c" {
		t.Errorf("RolesClaim = %q, want %q", got, "c")
	}
}
