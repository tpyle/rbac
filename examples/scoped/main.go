// Command scoped shows permissions granted on individual resources and
// groups of resources. It builds a small documents API, logs in each demo
// user through the auth package and prints which requests they may make.
//
//	go run ./examples/scoped
//
// Resources are named like "projects/42/docs/7". A role bound on a scope
// applies to everything beneath it, and scopes may contain wildcards:
//
//   - alice is a global admin, so she can do anything anywhere;
//   - bob is an editor of projects/42, so of every document in it;
//   - carol is a viewer of projects/42/docs/7 only;
//   - dave is an auditor of projects/*/docs, so of every document in every
//     project.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

const policyJSON = `{"roles": {
	"viewer":  {"permissions": ["docs:read"]},
	"editor":  {"inherits": ["viewer"], "permissions": ["docs:write", "docs:comments:**"]},
	"auditor": {"permissions": ["docs:read", "docs:history:read"]},
	"admin":   {"permissions": ["**"]}
}}`

// globalRoles are assigned in the RoleStore and embedded in tokens; they
// apply to every resource.
var globalRoles = map[string][]string{"alice": {"admin"}}

// bindings are scoped role assignments from the ScopedRoleStore; they are
// never embedded in tokens.
var bindings = []struct{ subject, scope, role string }{
	{"bob", "projects/42", "editor"},
	{"carol", "projects/42/docs/7", "viewer"},
	{"dave", "projects/*/docs", "auditor"},
}

var users = []string{"alice", "bob", "carol", "dave"}

// requests are the calls each user tries.
var requests = []struct{ method, path string }{
	{"GET", "/projects/42/docs/7"},
	{"PUT", "/projects/42/docs/7"},
	{"GET", "/projects/42/docs/8"},
	{"GET", "/projects/43/docs/1"},
	{"GET", "/projects/43/docs/1/history"},
	{"DELETE", "/projects/42"},
}

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, out io.Writer, authOpts ...auth.Option) error {
	policy, err := rbac.ParsePolicyJSON([]byte(policyJSON))
	if err != nil {
		return err
	}

	// In production both stores are database tables.
	roles := rbac.NewMemoryRoleStore()
	for user, r := range globalRoles {
		roles.SetRoles(user, r...)
	}
	scoped := rbac.NewMemoryScopedRoleStore()
	for _, b := range bindings {
		if err := scoped.Bind(b.subject, b.scope, b.role); err != nil {
			return err
		}
	}

	enforcer, err := rbac.New(
		rbac.WithPolicy(policy),
		rbac.WithRoleStore(roles),
		rbac.WithScopedRoleStore(scoped),
		// rbac.PathScopes() is the default: a binding on "projects/42"
		// applies to "projects/42/docs/7".
		rbac.WithScopeResolver(rbac.PathScopes()),
	)
	if err != nil {
		return err
	}

	userStore := auth.NewMemoryUserStore()
	opts := append([]auth.Option{
		auth.WithUserStore(userStore),
		auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
	}, authOpts...)
	a, err := auth.New(ctx, opts...)
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()

	hash, err := a.HashPassword(ctx, []byte("password"))
	if err != nil {
		return err
	}
	handler := a.RequireAuthHandler(routes(enforcer))
	for _, user := range users {
		userStore.SetPasswordHash(user, hash)
		pair, err := a.Login(ctx, user, []byte("password"))
		if err != nil {
			return err
		}
		for _, req := range requests {
			r := httptest.NewRequestWithContext(ctx, req.method, req.path, nil)
			r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if _, err := fmt.Fprintf(out, "%-6s %-7s %-28s %d\n", user, req.method, req.path, w.Code); err != nil {
				return err
			}
		}
	}
	return nil
}

// routes protects each route with a permission on the resource named in its
// path.
func routes(e *rbac.Enforcer) http.Handler {
	doc := rbac.PathResource("projects/{project}/docs/{doc}")
	project := rbac.PathResource("projects/{project}")

	mux := http.NewServeMux()
	mux.Handle("GET /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:read")(ok))
	mux.Handle("PUT /projects/{project}/docs/{doc}", e.RequireAllPermissionsOn(doc, "docs:write")(ok))
	mux.Handle("GET /projects/{project}/docs/{doc}/history", e.RequireAllPermissionsOn(doc, "docs:history:read")(ok))
	mux.Handle("DELETE /projects/{project}", e.RequireAnyRoleOn(project, "admin")(ok))
	return mux
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})
