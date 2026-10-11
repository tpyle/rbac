package rbac

import (
	"context"
	"slices"
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
