// Command basic walks through the rbac library without HTTP or an
// authentication library: it loads a policy, computes the claims a token
// issuer would embed, round-trips them through JSON as a JWT payload would
// be, and checks roles and permissions against the decoded claims.
//
//	go run ./examples/basic
//
// See github.com/tpyle/rbac/authrbac/examples for the same flow with real
// tokens from github.com/tpyle/auth/v2.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/tpyle/rbac"
)

const policyJSON = `{"roles": {
	"viewer": {"permissions": ["posts:read"]},
	"editor": {"inherits": ["viewer"], "permissions": ["posts:*"]},
	"admin":  {"inherits": ["editor"], "permissions": ["users:*"]}
}}`

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, out io.Writer) error {
	policy, err := rbac.ParsePolicyJSON([]byte(policyJSON))
	if err != nil {
		return err
	}

	// In production this is a database-backed RoleStore.
	roles := rbac.NewMemoryRoleStore()
	roles.SetRoles("alice", "editor")

	enforcer, err := rbac.New(
		rbac.WithRoleStore(roles),
		rbac.WithPolicy(policy),
		rbac.WithEmbedRoles(true),        // HasRole needs no lookup
		rbac.WithEmbedPermissions(false), // Can resolves roles through the policy
	)
	if err != nil {
		return err
	}

	// The token issuer adds these claims to alice's access token.
	extra, err := enforcer.ClaimsProvider(nil)(ctx, "alice")
	if err != nil {
		return err
	}
	payload, err := json.Marshal(extra)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "token payload:", string(payload)); err != nil {
		return err
	}

	// A service that verified the token decodes its payload. Arrays decode
	// as []any, which rbac accepts.
	var values map[string]any
	if err := json.Unmarshal(payload, &values); err != nil {
		return err
	}
	// Authentication middleware does this for HTTP requests.
	ctx = rbac.ContextWithClaims(ctx, &rbac.Claims{Subject: "alice", Values: values})

	for _, role := range []string{"viewer", "admin"} {
		ok, err := enforcer.HasRole(ctx, role)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "alice has role %-6s %v\n", role+":", ok); err != nil {
			return err
		}
	}
	for _, perm := range []string{"posts:read", "posts:delete", "users:delete"} {
		ok, err := enforcer.Can(ctx, perm)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "alice can %-13s %v\n", perm+":", ok); err != nil {
			return err
		}
	}
	return nil
}
