// Command basic walks through the rbac library without HTTP: it loads a
// policy, issues a token through the auth package with roles embedded, and
// checks roles and permissions against the verified claims.
//
//	go run ./examples/basic
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
	"github.com/tpyle/rbac/authrbac"
)

const policyJSON = `{"roles": {
	"viewer": {"permissions": ["posts:read"]},
	"editor": {"inherits": ["viewer"], "permissions": ["posts:*"]},
	"admin":  {"inherits": ["editor"], "permissions": ["users:*"]}
}}`

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	policy, err := rbac.ParsePolicyJSON([]byte(policyJSON))
	if err != nil {
		return err
	}

	// In production this is a database-backed RoleStore.
	roles := rbac.NewMemoryRoleStore()
	roles.SetRoles("alice", "editor")

	enforcer, err := rbac.New(
		authrbac.Option(), // read the claims auth verifies
		rbac.WithRoleStore(roles),
		rbac.WithPolicy(policy),
		rbac.WithEmbedRoles(true),        // HasRole needs no lookup
		rbac.WithEmbedPermissions(false), // Can resolves roles through the policy
	)
	if err != nil {
		return err
	}

	users := auth.NewMemoryUserStore()
	a, err := auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
	)
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()

	hash, err := a.HashPassword(ctx, []byte("correct horse"))
	if err != nil {
		return err
	}
	users.SetPasswordHash("alice", hash)

	pair, err := a.Login(ctx, "alice", []byte("correct horse"))
	if err != nil {
		return err
	}
	claims, err := a.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		return err
	}
	fmt.Println("roles in token:", claims.Extra["roles"])

	// The middleware does this for HTTP requests.
	ctx = auth.ContextWithClaims(ctx, claims)
	for _, role := range []string{"viewer", "admin"} {
		ok, err := enforcer.HasRole(ctx, role)
		if err != nil {
			return err
		}
		fmt.Printf("alice has role %-6s %v\n", role+":", ok)
	}
	for _, perm := range []string{"posts:read", "posts:delete", "users:delete"} {
		ok, err := enforcer.Can(ctx, perm)
		if err != nil {
			return err
		}
		fmt.Printf("alice can %-13s %v\n", perm+":", ok)
	}
	return nil
}
