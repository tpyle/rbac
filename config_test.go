package rbac

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"empty roles claim", func(c *Config) { c.RolesClaim = "" }},
		{"empty permissions claim", func(c *Config) { c.PermissionsClaim = "" }},
		{"reserved roles claim", func(c *Config) { c.RolesClaim = "sub" }},
		{"reserved permissions claim", func(c *Config) { c.PermissionsClaim = "jti" }},
		{"same claim", func(c *Config) { c.PermissionsClaim = c.RolesClaim }},
		{"scoped only with roles", func(c *Config) { c.ScopedRolesOnly = true }},
		{"scoped only with permissions", func(c *Config) {
			c.ScopedRolesOnly, c.EmbedRoles, c.EmbedPermissions = true, false, true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.modify(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate() = nil, want error")
			}
		})
	}
}

func TestNewRequirements(t *testing.T) {
	p := mustPolicy(t, testDefs)
	store := NewMemoryRoleStore()
	tests := []struct {
		name    string
		opts    []Option
		wantErr error // nil with wantAny means any error
		wantAny bool
	}{
		{"defaults need a policy", nil, ErrNotConfigured, false},
		{"defaults with policy", []Option{WithPolicy(p)}, nil, false},
		{"nil policy is no policy", []Option{WithPolicy(nil)}, ErrNotConfigured, false},
		{"permissions only, no policy", []Option{WithEmbedRoles(false), WithEmbedPermissions(true)}, nil, false},
		{"nothing embedded needs store", []Option{WithEmbedRoles(false), WithPolicy(p)}, ErrNotConfigured, false},
		{"nothing embedded with store", []Option{WithEmbedRoles(false), WithPolicy(p), WithRoleStore(store)}, nil, false},
		{"nothing embedded with scoped store", []Option{WithEmbedRoles(false), WithPolicy(p), WithScopedRoleStore(NewMemoryScopedRoleStore())}, nil, false},
		{"invalid config", []Option{WithPolicy(p), WithRolesClaim("")}, nil, true},
		{"scoped only needs scoped store", []Option{WithScopedRolesOnly(), WithPolicy(p), WithRoleStore(store)}, ErrNotConfigured, false},
		{"scoped only needs policy", []Option{WithScopedRolesOnly(), WithScopedRoleStore(NewMemoryScopedRoleStore())}, ErrNotConfigured, false},
		{"scoped only", []Option{WithScopedRolesOnly(), WithPolicy(p), WithScopedRoleStore(NewMemoryScopedRoleStore())}, nil, false},
		{"scoped only then embedding", []Option{WithScopedRolesOnly(), WithEmbedRoles(true), WithPolicy(p), WithScopedRoleStore(NewMemoryScopedRoleStore())}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if tt.wantAny {
				if err == nil {
					t.Error("New() err = nil, want an error")
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("New() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	handler := func(http.ResponseWriter, *http.Request, error) {}
	store := NewMemoryRoleStore()
	pp := StaticPolicy(mustPolicy(t, nil))

	cfg := Config{EmbedRoles: false, EmbedPermissions: true, RolesClaim: "r", PermissionsClaim: "p"}
	e, err := New(
		WithConfig(cfg),
		WithRolesClaim("my_roles"),
		WithPermissionsClaim("my_perms"),
		WithEmbedRoles(true),
		WithRoleStore(store),
		WithPolicyProvider(pp),
		WithErrorHandler(handler),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{EmbedRoles: true, EmbedPermissions: true, RolesClaim: "my_roles", PermissionsClaim: "my_perms"}
	if got := e.Config(); got != want {
		t.Errorf("Config() = %+v, want %+v", got, want)
	}
	if e.s.roleStore != store || e.s.policy != pp || e.s.errorHandler == nil || e.s.logger != logger {
		t.Error("options not applied")
	}

	e, err = New(WithPolicy(mustPolicy(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if e.s.logger != slog.Default() || e.s.errorHandler == nil || e.s.scopeResolver != PathScopes() || e.s.scopedStore != nil {
		t.Error("defaults not applied")
	}

	scoped := NewMemoryScopedRoleStore()
	resolver := ScopeResolverFunc(func(context.Context, string) ([]string, error) { return nil, nil })
	e, err = New(WithPolicy(mustPolicy(t, nil)), WithScopedRoleStore(scoped), WithScopeResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if e.s.scopedStore != scoped || e.s.scopeResolver == nil || e.s.scopeResolver == PathScopes() {
		t.Error("scoped options not applied")
	}
	e, err = New(WithPolicy(mustPolicy(t, nil)), WithScopeResolver(nil))
	if err != nil {
		t.Fatal(err)
	}
	if e.s.scopeResolver != PathScopes() {
		t.Error("nil resolver did not fall back to PathScopes")
	}
}
