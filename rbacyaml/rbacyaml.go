// Package rbacyaml loads [rbac.Policy] values from YAML. It is separate from
// package rbac so that programs using JSON or code-defined policies do not
// compile a YAML parser.
//
// The document has the same structure as [rbac.PolicyFile]:
//
//	roles:
//	  viewer:
//	    permissions: ["posts:read"]
//	  editor:
//	    inherits: [viewer]
//	    permissions: ["posts:write"]
package rbacyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/tpyle/rbac"
	"go.yaml.in/yaml/v3"
)

// ParsePolicy decodes a YAML policy document and builds a [rbac.Policy].
// Unknown fields, empty input and further documents are rejected with
// [rbac.ErrInvalidPolicy], except that empty documents after the policy,
// such as one left by a trailing "---", are ignored. A document holding an
// explicit null ("~" or "null") is not empty and is rejected.
func ParsePolicy(data []byte) (*rbac.Policy, error) {
	return LoadPolicy(bytes.NewReader(data))
}

// LoadPolicy is like [ParsePolicy] but reads from r.
func LoadPolicy(r io.Reader) (*rbac.Policy, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f rbac.PolicyFile
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: empty document", rbac.ErrInvalidPolicy)
		}
		return nil, fmt.Errorf("%w: %w", rbac.ErrInvalidPolicy, err)
	}
	for {
		var extra yaml.Node
		err := dec.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !isEmpty(&extra) {
			return nil, fmt.Errorf("%w: unexpected data after policy", rbac.ErrInvalidPolicy)
		}
	}
	return f.Policy()
}

// isEmpty reports whether n is an empty document, such as one left by a
// trailing "---" separator.
func isEmpty(n *yaml.Node) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	return n.Kind == 0 || (n.Kind == yaml.DocumentNode && len(n.Content) == 0) ||
		(n.Kind == yaml.ScalarNode && n.Tag == "!!null" && n.Value == "")
}
