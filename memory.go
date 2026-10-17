package rbac

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
)

// MemoryRoleStore is an in-memory [RoleStore]. It is intended for tests,
// examples and prototypes.
type MemoryRoleStore struct {
	mu    sync.RWMutex
	roles map[string][]string
}

// NewMemoryRoleStore returns an empty [MemoryRoleStore].
func NewMemoryRoleStore() *MemoryRoleStore {
	return &MemoryRoleStore{roles: map[string][]string{}}
}

// SetRoles replaces the roles assigned to subject. With no roles, the
// subject is removed.
func (s *MemoryRoleStore) SetRoles(subject string, roles ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(roles) == 0 {
		delete(s.roles, subject)
		return
	}
	s.roles[subject] = sortedUnique(slices.Clone(roles))
}

// AddRoles assigns additional roles to subject.
func (s *MemoryRoleStore) AddRoles(subject string, roles ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	merged := sortedUnique(append(slices.Clone(s.roles[subject]), roles...))
	if len(merged) == 0 {
		return
	}
	s.roles[subject] = merged
}

// RemoveRoles unassigns roles from subject.
func (s *MemoryRoleStore) RemoveRoles(subject string, roles ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := slices.DeleteFunc(slices.Clone(s.roles[subject]), func(r string) bool {
		return slices.Contains(roles, r)
	})
	if len(kept) == 0 {
		delete(s.roles, subject)
		return
	}
	s.roles[subject] = kept
}

// Roles implements [RoleStore]. It returns a copy.
func (s *MemoryRoleStore) Roles(_ context.Context, subject string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.roles[subject]), nil
}

// MemoryScopedRoleStore is an in-memory [ScopedRoleStore]. It is intended
// for tests, examples and prototypes.
type MemoryScopedRoleStore struct {
	mu sync.RWMutex
	// bindings maps subject to scope pattern to sorted roles.
	bindings map[string]map[string][]string
}

// NewMemoryScopedRoleStore returns an empty [MemoryScopedRoleStore].
func NewMemoryScopedRoleStore() *MemoryScopedRoleStore {
	return &MemoryScopedRoleStore{bindings: map[string]map[string][]string{}}
}

// Bind grants roles to subject on every scope matching the scope pattern
// scope. It returns [ErrInvalidScope] if scope is not a valid pattern (see
// [ValidateScopePattern]) and [ErrInvalidRole] if a role name is invalid, in
// which case nothing is bound.
func (s *MemoryScopedRoleStore) Bind(subject, scope string, roles ...string) error {
	if err := ValidateScopePattern(scope); err != nil {
		return err
	}
	for _, r := range roles {
		if err := validateRole(r); err != nil {
			return err
		}
	}
	if len(roles) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	scopes := s.bindings[subject]
	if scopes == nil {
		scopes = map[string][]string{}
		s.bindings[subject] = scopes
	}
	scopes[scope] = sortedUnique(append(slices.Clone(scopes[scope]), roles...))
	return nil
}

// Unbind removes roles bound to subject on the scope pattern scope. With no
// roles, every role bound on scope is removed.
func (s *MemoryScopedRoleStore) Unbind(subject, scope string, roles ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scopes := s.bindings[subject]
	kept := slices.DeleteFunc(slices.Clone(scopes[scope]), func(r string) bool {
		return len(roles) == 0 || slices.Contains(roles, r)
	})
	if len(kept) > 0 {
		scopes[scope] = kept
		return
	}
	delete(scopes, scope)
	if len(scopes) == 0 {
		delete(s.bindings, subject)
	}
}

// Bindings implements [ScopedRoleStore]. Like a database implementation, it
// returns the bindings on any of scopes plus every binding whose scope
// contains a wildcard, sorted by scope and role.
func (s *MemoryScopedRoleStore) Bindings(_ context.Context, subject string, scopes []string) ([]Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Binding{}
	for scope, roles := range s.bindings[subject] {
		if !slices.Contains(scopes, scope) && !strings.Contains(scope, Wildcard) {
			continue
		}
		for _, role := range roles {
			out = append(out, Binding{Scope: scope, Role: role})
		}
	}
	slices.SortFunc(out, func(a, b Binding) int {
		return cmp.Or(strings.Compare(a.Scope, b.Scope), strings.Compare(a.Role, b.Role))
	})
	return out, nil
}
