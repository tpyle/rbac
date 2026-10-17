package rbac

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// RoleDefinition describes one role of a [Policy].
type RoleDefinition struct {
	// Permissions are the grants the role holds directly. They may contain
	// wildcards (see [ValidateGrant]).
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	// Inherits names roles whose roles and permissions this role also has.
	// For example an "admin" role inheriting "editor" is also an "editor".
	Inherits []string `json:"inherits,omitempty" yaml:"inherits,omitempty"`
	// Except lists grants carved out of Permissions: the role holds what
	// Permissions match and no exception does, so ["files:*"] except
	// ["files:delete"] grants every files permission but delete. They may
	// contain wildcards.
	//
	// Exceptions narrow only the role's own Permissions. Permissions from
	// inherited roles are unaffected, since a role inheriting "viewer" is a
	// "viewer"; to withhold a permission a parent grants, don't inherit it.
	// Likewise a user holds a permission if any of their roles grants it.
	Except []string `json:"except,omitempty" yaml:"except,omitempty"`
}

// clone returns a deep copy of d.
func (d RoleDefinition) clone() RoleDefinition {
	return RoleDefinition{
		Permissions: slices.Clone(d.Permissions),
		Inherits:    slices.Clone(d.Inherits),
		Except:      slices.Clone(d.Except),
	}
}

// Policy maps roles to permissions. It is created with [NewPolicy] (or
// loaded with [ParsePolicyJSON]), is immutable, and is safe for concurrent
// use. A nil *Policy defines no roles.
type Policy struct {
	defs  map[string]RoleDefinition
	roles map[string]resolvedRole
}

// resolvedRole is a role with its inheritance flattened.
type resolvedRole struct {
	// roles are the role itself and every role it inherits, sorted.
	roles []string
	// terms are the role's direct grants, each with the role's exceptions,
	// and its inherited roles' terms, simplified.
	terms []term
	// grants are terms rendered as in [Grants], sorted.
	grants []string
	// set is grants prepared for matching.
	set grantSet
}

// NewPolicy validates defs and returns a policy. Role names must be
// non-empty without whitespace, grants and exceptions must be valid (see
// [ValidateGrant]), inherited roles must be defined ([ErrUnknownRole]) and
// inheritance must be acyclic ([ErrRoleCycle]). defs is copied.
func NewPolicy(defs map[string]RoleDefinition) (*Policy, error) {
	p := &Policy{
		defs:  make(map[string]RoleDefinition, len(defs)),
		roles: make(map[string]resolvedRole, len(defs)),
	}
	// Sorted, so a policy with several mistakes always reports the same one.
	for _, name := range slices.Sorted(maps.Keys(defs)) {
		def := defs[name]
		if err := validateRole(name); err != nil {
			return nil, err
		}
		for _, g := range slices.Concat(def.Permissions, def.Except) {
			if err := ValidateGrant(g); err != nil {
				return nil, fmt.Errorf("role %q: %w", name, err)
			}
		}
		for _, parent := range def.Inherits {
			if _, ok := defs[parent]; !ok {
				return nil, fmt.Errorf("%w: role %q inherits undefined role %q", ErrUnknownRole, name, parent)
			}
		}
		p.defs[name] = def.clone()
	}

	r := resolver{defs: p.defs, done: p.roles}
	for _, name := range slices.Sorted(maps.Keys(p.defs)) {
		if _, err := r.resolve(name); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// resolver flattens inheritance with a depth-first search, memoizing
// finished roles and tracking the current path to detect cycles.
type resolver struct {
	defs map[string]RoleDefinition
	done map[string]resolvedRole
	path []string // roles being resolved, outermost first
}

func (r *resolver) resolve(name string) (resolvedRole, error) {
	if res, ok := r.done[name]; ok {
		return res, nil
	}
	if start := slices.Index(r.path, name); start >= 0 {
		cycle := append(slices.Clone(r.path[start:]), name)
		return resolvedRole{}, fmt.Errorf("%w: %s", ErrRoleCycle, strings.Join(cycle, " -> "))
	}
	r.path = append(r.path, name)

	def := r.defs[name]
	roles := []string{name}
	var terms []term
	for _, g := range def.Permissions {
		terms = append(terms, term{grant: g, excepts: def.Except})
	}
	for _, parent := range def.Inherits {
		pr, err := r.resolve(parent)
		if err != nil {
			return resolvedRole{}, err
		}
		roles = append(roles, pr.roles...)
		terms = append(terms, pr.terms...)
	}

	r.path = r.path[:len(r.path)-1]
	res := resolvedRole{roles: sortedUnique(roles)}
	// Terms that end up the same are kept once.
	seen := map[string]bool{}
	for _, t := range terms {
		t, ok := t.simplify()
		if s := t.String(); ok && !seen[s] {
			seen[s] = true
			res.terms = append(res.terms, t)
			res.grants = append(res.grants, s)
		}
	}
	res.grants = sortedUnique(res.grants)
	res.set = newGrantSet(res.grants)
	r.done[name] = res
	return res, nil
}

// sortedUnique sorts s in place, removes duplicates and never returns nil,
// so an empty result encodes as a JSON array rather than null.
func sortedUnique(s []string) []string {
	if s == nil {
		return []string{}
	}
	slices.Sort(s)
	return slices.Compact(s)
}

// Roles returns the names of the roles the policy defines, sorted.
func (p *Policy) Roles() []string {
	if p == nil {
		return []string{}
	}
	return slices.Sorted(maps.Keys(p.defs))
}

// Definitions returns a copy of the role definitions the policy was built
// from.
func (p *Policy) Definitions() map[string]RoleDefinition {
	out := map[string]RoleDefinition{}
	if p == nil {
		return out
	}
	for name, def := range p.defs {
		out[name] = def.clone()
	}
	return out
}

// HasRole reports whether the policy defines the role name.
func (p *Policy) HasRole(name string) bool {
	if p == nil {
		return false
	}
	_, ok := p.roles[name]
	return ok
}

// EffectiveRoles returns assigned plus every role they inherit, sorted and
// without duplicates. Roles the policy does not define are kept as they are,
// so a role can be checked with [Enforcer.HasRole] without granting any
// permissions.
func (p *Policy) EffectiveRoles(assigned ...string) []string {
	out := slices.Clone(assigned)
	if p != nil {
		for _, name := range assigned {
			out = append(out, p.roles[name].roles...)
		}
	}
	return sortedUnique(out)
}

// Permissions returns the grants held by the given roles, directly or
// through inheritance, sorted and without duplicates. Undefined roles grant
// nothing. A grant narrowed by a role's exceptions carries them, as in
// "files:* -files:delete" (see [Grants]).
func (p *Policy) Permissions(roles ...string) []string {
	var out []string
	if p != nil {
		for _, name := range roles {
			out = append(out, p.roles[name].grants...)
		}
	}
	return sortedUnique(out)
}

// Can reports whether any of roles grants the concrete permission perm. It
// returns an error wrapping [ErrInvalidPermission] if perm is not concrete.
func (p *Policy) Can(roles []string, perm string) (bool, error) {
	if err := ValidatePermission(perm); err != nil {
		return false, err
	}
	return p.allows(roles, perm), nil
}

// allows reports whether any of roles grants the concrete permission perm,
// using each role's precomputed grant set.
func (p *Policy) allows(roles []string, perm string) bool {
	if p == nil {
		return false
	}
	return slices.ContainsFunc(roles, func(name string) bool {
		r, ok := p.roles[name]
		return ok && r.set.allows(perm)
	})
}
