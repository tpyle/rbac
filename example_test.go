package rbac_test

import (
	"context"
	"errors"
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
	fmt.Println(rbac.Grants("posts:*", "posts:delete"))
	fmt.Println(rbac.Grants("posts:*", "posts:comments:delete"))
	fmt.Println(rbac.Grants("posts:**", "posts:comments:delete"))
	fmt.Println(rbac.Grants("**:read", "posts:drafts:read"))
	fmt.Println(rbac.Grants("posts:*", "posts"))
	// Output:
	// true
	// false
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

func ExampleMatchScope() {
	fmt.Println(rbac.MatchScope("projects/*/docs", "projects/42/docs"))
	fmt.Println(rbac.MatchScope("projects/*", "projects/42/docs"))
	fmt.Println(rbac.MatchScope("projects/**/comments", "projects/42/docs/7/comments"))
	// Output:
	// true
	// false
	// true
}

func ExamplePathScopes() {
	scopes, _ := rbac.PathScopes().Scopes(context.Background(), "projects/42/docs/7")
	fmt.Println(scopes)
	// Output: [projects/42/docs/7 projects/42/docs projects/42 projects]
}

func ExampleEnforcer_CanOn() {
	policy, _ := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		"viewer": {Permissions: []string{"docs:read"}},
		"editor": {Inherits: []string{"viewer"}, Permissions: []string{"docs:write"}},
	})
	// In production this is a database table of (subject, scope, role).
	bindings := rbac.NewMemoryScopedRoleStore()
	if err := errors.Join(
		bindings.Bind("alice", "projects/42", "editor"),       // one project and everything in it
		bindings.Bind("alice", "projects/*/docs/7", "viewer"), // doc 7 of every project
	); err != nil {
		log.Fatal(err)
	}

	e, _ := rbac.New(rbac.WithPolicy(policy), rbac.WithScopedRoleStore(bindings))

	// alice has no global roles in her token.
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{
		Subject: "alice",
		Extra:   map[string]any{"roles": []any{}},
	})
	for _, check := range []struct{ resource, perm string }{
		{"projects/42/docs/1", "docs:write"},
		{"projects/43/docs/1", "docs:read"},
		{"projects/43/docs/7", "docs:read"},
		{"projects/43/docs/7", "docs:write"},
	} {
		ok, _ := e.CanOn(ctx, check.resource, check.perm)
		fmt.Println(check.resource, check.perm, ok)
	}
	// Output:
	// projects/42/docs/1 docs:write true
	// projects/43/docs/1 docs:read false
	// projects/43/docs/7 docs:read true
	// projects/43/docs/7 docs:write false
}

func ExampleEnforcer_RequireAllPermissionsOn() {
	var a *auth.Authorizer // from auth.New
	var e *rbac.Enforcer   // from rbac.New, with rbac.WithScopedRoleStore
	if a == nil || e == nil {
		return
	}
	mux := http.NewServeMux()
	doc := rbac.PathResource("projects/{project}/docs/{doc}")
	mux.Handle("PUT /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:write")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { /* ... */ },
	)))
	_ = http.ListenAndServe(":8080", a.RequireAuthHandler(mux))
}

func ExampleRoleDefinition_except() {
	policy, _ := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		// Every files permission except delete.
		"editor": {Permissions: []string{"files:*"}, Except: []string{"files:delete"}},
		// An editor who may also delete.
		"owner": {Inherits: []string{"editor"}, Permissions: []string{"files:delete"}},
	})
	for _, role := range []string{"editor", "owner"} {
		canWrite, _ := policy.Can([]string{role}, "files:write")
		canDelete, _ := policy.Can([]string{role}, "files:delete")
		fmt.Println(role, canWrite, canDelete, policy.Permissions(role))
	}
	// Output:
	// editor true false [files:* -files:delete]
	// owner true true [files:* -files:delete files:delete]
}

func ExampleWithScopedRolesOnly() {
	policy, _ := rbac.NewPolicy(map[string]rbac.RoleDefinition{
		"admin": {Permissions: []string{"**"}},
	})
	bindings := rbac.NewMemoryScopedRoleStore()
	if err := bindings.Bind("alice", "projects/42", "admin"); err != nil {
		log.Fatal(err)
	}
	e, _ := rbac.New(rbac.WithScopedRolesOnly(), rbac.WithPolicy(policy), rbac.WithScopedRoleStore(bindings))

	// The token claims alice is a global admin, but this service ignores
	// global roles.
	ctx := auth.ContextWithClaims(context.Background(), &auth.Claims{
		Subject: "alice",
		Extra:   map[string]any{"roles": []any{"admin"}},
	})
	here, _ := e.CanOn(ctx, "projects/42", "projects:delete")
	elsewhere, _ := e.CanOn(ctx, "projects/43", "projects:delete")
	_, err := e.Can(ctx, "projects:delete")
	fmt.Println(here, elsewhere, errors.Is(err, rbac.ErrNotConfigured))
	// Output: true false true
}
