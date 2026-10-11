package rbac_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

func ExampleNewPolicy() {
	policy, err := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		"viewer": {Permissions: []string{"posts:read"}},
		"editor": {Inherits: []string{"viewer"}, Permissions: []string{"posts:*"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(policy.EffectiveRoles("editor"))
	fmt.Println(policy.Permissions("editor"))
	ok, _ := policy.Can([]string{"editor"}, "posts:delete")
	fmt.Println(ok)
	// Output:
	// [editor viewer]
	// [posts:* posts:read]
	// true
}

func ExampleGrants() {
	fmt.Println(rbac.Grants("posts:*", "posts:comments:delete"))
	fmt.Println(rbac.Grants("*:read", "users:read"))
	fmt.Println(rbac.Grants("posts:*", "posts"))
	// Output:
	// true
	// true
	// false
}

func ExampleEnforcer_ClaimsProvider() {
	ctx := context.Background()
	policy, _ := rbac.ParsePolicyJSON([]byte(`{"roles": {
		"viewer": {"permissions": ["posts:read"]},
		"editor": {"inherits": ["viewer"], "permissions": ["posts:write"]}
	}}`))
	roles := rbac.NewMemoryRoleStore()
	roles.SetRoles("alice", "editor")

	e, err := rbac.New(
		rbac.WithRoleStore(roles),
		rbac.WithPolicy(policy),
		rbac.WithEmbedRoles(true),
		rbac.WithEmbedPermissions(true),
	)
	if err != nil {
		log.Fatal(err)
	}
	// Pass this to auth.WithClaimsProvider.
	claims, _ := e.ClaimsProvider(nil)(ctx, "alice")
	fmt.Println(claims["roles"], claims["perms"])
	// Output: [editor viewer] [posts:read posts:write]
}

func ExampleEnforcer_Can() {
	policy, _ := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		"editor": {Permissions: []string{"posts:read", "posts:write"}},
	})
	e, _ := rbac.New(rbac.WithPolicy(policy))

	// Normally auth's middleware puts the verified claims in the context.
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{
		Subject: "alice",
		Extra:   map[string]any{"roles": []any{"editor"}},
	})
	canWrite, _ := e.Can(ctx, "posts:write")
	canDelete, _ := e.Can(ctx, "posts:delete")
	isEditor, _ := e.HasRole(ctx, "editor")
	fmt.Println(canWrite, canDelete, isEditor)
	// Output: true false true
}

func ExampleEnforcer_RequireAllPermissions() {
	var a *auth.Authorizer // from auth.New
	var e *rbac.Enforcer   // from rbac.New
	if a == nil || e == nil {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("DELETE /posts/{id}", e.RequireAllPermissions("posts:delete")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { /* ... */ },
	)))
	// auth verifies the token first; rbac then checks access.
	_ = http.ListenAndServe(":8080", a.RequireAuthHandler(mux))
}
