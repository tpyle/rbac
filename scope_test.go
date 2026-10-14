package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestValidateScope(t *testing.T) {
	tests := []struct {
		scope    string
		concrete bool
		pattern  bool
	}{
		{"projects", true, true},
		{"projects/42", true, true},
		{"projects/42/docs/7", true, true},
		{"tag:finance", true, true},
		{"a-b_c.d/e:f", true, true},
		{"*", false, true},
		{"**", false, true},
		{"projects/*", false, true},
		{"projects/*/docs", false, true},
		{"projects/**/comments", false, true},
		{"**/comments", false, true},
		{"*/**", false, true},
		{"**/*/**", false, true},
		{"", false, false},
		{"/", false, false},
		{"/projects", false, false},
		{"projects/", false, false},
		{"projects//42", false, false},
		{"proj*", false, false},
		{"projects/4*2", false, false},
		{"projects/***", false, false},
		{"**/**", false, false},
		{"a/**/**/b", false, false},
		{"projects/4 2", false, false},
		{"projects\n", false, false},
		{"projects/42/../43", false, false},
		{"projects/./42", false, false},
		{"..", false, false},
		{"projects/*/..", false, false},
		{"projects/...", true, true},
		{"projects/.hidden", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			err := ValidateScope(tt.scope)
			if (err == nil) != tt.concrete {
				t.Errorf("ValidateScope(%q) = %v, want valid=%v", tt.scope, err, tt.concrete)
			}
			if err != nil && !errors.Is(err, ErrInvalidScope) {
				t.Errorf("ValidateScope(%q) = %v, want ErrInvalidScope", tt.scope, err)
			}
			err = ValidateScopePattern(tt.scope)
			if (err == nil) != tt.pattern {
				t.Errorf("ValidateScopePattern(%q) = %v, want valid=%v", tt.scope, err, tt.pattern)
			}
			if err != nil && !errors.Is(err, ErrInvalidScope) {
				t.Errorf("ValidateScopePattern(%q) = %v, want ErrInvalidScope", tt.scope, err)
			}
		})
	}
}

func TestMatchScope(t *testing.T) {
	tests := []struct {
		pattern, scope string
		want           bool
	}{
		{"projects/42", "projects/42", true},
		{"projects/42", "projects/43", false},
		{"projects/*/docs", "projects/42/docs", true},
		{"projects/*/docs", "projects/42/docs/7", false},
		{"projects/*", "projects/42", true},
		// A pattern matches a scope, not its descendants.
		{"projects/*", "projects/42/docs", false},
		{"projects/**", "projects/42/docs", true},
		{"projects/**", "projects", true},
		{"projects/**/comments", "projects/comments", true},
		{"projects/**/comments", "projects/42/docs/7/comments", true},
		{"projects/**/comments", "projects/42/docs/7", false},
		{"**", "anything/at/all", true},
		// ":" is not a separator for scopes.
		{"tag:*", "tag:finance", false},
		{"*", "tag:finance", true},
		{"tag:finance", "tag:finance", true},
		{"projects/*", "projects/", false},
		{"projects/*", "", false},
	}
	for _, tt := range tests {
		if got := MatchScope(tt.pattern, tt.scope); got != tt.want {
			t.Errorf("MatchScope(%q, %q) = %v, want %v", tt.pattern, tt.scope, got, tt.want)
		}
	}
}

func TestPathScopes(t *testing.T) {
	r := PathScopes()
	tests := []struct {
		resource string
		want     []string
	}{
		{"projects", []string{"projects"}},
		{"projects/42", []string{"projects/42", "projects"}},
		{"projects/42/docs/7", []string{"projects/42/docs/7", "projects/42/docs", "projects/42", "projects"}},
		{"tag:finance", []string{"tag:finance"}},
	}
	for _, tt := range tests {
		got, err := r.Scopes(context.Background(), tt.resource)
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("Scopes(%q) = %v, %v; want %v", tt.resource, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "projects/", "/projects", "a//b", "projects/*", "a b", "projects/42/../43"} {
		if _, err := r.Scopes(context.Background(), bad); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("Scopes(%q) err = %v, want ErrInvalidScope", bad, err)
		}
	}
}

func TestScopeRoles(t *testing.T) {
	scopes := []string{"projects/42/docs/7", "projects/42/docs", "projects/42", "projects"}
	bindings := []Binding{
		{Scope: "projects/42/docs/7", Role: "viewer"},
		{Scope: "projects/42", Role: "editor"},
		{Scope: "projects/42", Role: "viewer"},
		{Scope: "projects/43", Role: "admin"},
		{Scope: "projects/*/docs", Role: "auditor"},
		{Scope: "projects/*/docs/*/comments", Role: "moderator"},
		{Scope: "**/7", Role: "seven"},
		{Scope: "users/**", Role: "support"},
	}
	want := []string{"auditor", "editor", "seven", "viewer"}
	if got := scopeRoles(bindings, scopes); !slices.Equal(got, want) {
		t.Errorf("scopeRoles = %v, want %v", got, want)
	}
	if got := scopeRoles(nil, scopes); got == nil || len(got) != 0 {
		t.Errorf("scopeRoles(nil) = %#v, want empty non-nil", got)
	}
}

func TestValidateBinding(t *testing.T) {
	if err := validateBinding(Binding{Scope: "projects/*", Role: "editor"}); err != nil {
		t.Errorf("valid binding: %v", err)
	}
	if err := validateBinding(Binding{Scope: "projects//x", Role: "editor"}); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("bad scope: %v", err)
	}
	if err := validateBinding(Binding{Scope: "projects", Role: "a b"}); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("bad role: %v", err)
	}
}

func TestScopeFuncAdapters(t *testing.T) {
	ctx := context.Background()
	store := ScopedRoleStoreFunc(func(_ context.Context, subject string, scopes []string) ([]Binding, error) {
		return []Binding{{Scope: scopes[0], Role: subject}}, nil
	})
	if got, err := store.Bindings(ctx, "r", []string{"s"}); err != nil || !slices.Equal(got, []Binding{{"s", "r"}}) {
		t.Errorf("ScopedRoleStoreFunc = %v, %v", got, err)
	}
	resolver := ScopeResolverFunc(func(_ context.Context, resource string) ([]string, error) {
		return []string{resource, "all"}, nil
	})
	if got, err := resolver.Scopes(ctx, "x"); err != nil || !slices.Equal(got, []string{"x", "all"}) {
		t.Errorf("ScopeResolverFunc = %v, %v", got, err)
	}
}
