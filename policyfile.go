package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// PolicyFile is the document format of a policy file:
//
//	{
//	  "roles": {
//	    "viewer": {"permissions": ["posts:read"]},
//	    "editor": {"inherits": ["viewer"], "permissions": ["posts:write"]}
//	  }
//	}
//
// The YAML loader in the rbacyaml subpackage uses the same structure.
type PolicyFile struct {
	Roles map[string]RoleDefinition `json:"roles" yaml:"roles"`
}

// Policy validates the file and builds a [Policy] from it. The roles key
// is required, so an empty or truncated file is rejected with
// [ErrInvalidPolicy] instead of producing a policy that grants nothing; a
// policy that really has no roles must say so with an empty roles object.
func (f PolicyFile) Policy() (*Policy, error) {
	if f.Roles == nil {
		return nil, fmt.Errorf("%w: missing roles", ErrInvalidPolicy)
	}
	return NewPolicy(f.Roles)
}

// ParsePolicyJSON decodes a [PolicyFile] from JSON and builds a [Policy].
// Unknown fields, trailing data and a missing roles key are rejected with
// [ErrInvalidPolicy], so mistakes such as "permisions" or an empty file do
// not silently remove permissions.
func ParsePolicyJSON(data []byte) (*Policy, error) {
	return LoadPolicyJSON(bytes.NewReader(data))
}

// LoadPolicyJSON is like [ParsePolicyJSON] but reads from r.
func LoadPolicyJSON(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var f PolicyFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected data after policy", ErrInvalidPolicy)
	}
	return f.Policy()
}
