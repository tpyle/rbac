// Command middleware shows rbac's HTTP middleware behind an authentication
// layer of your own. The authenticate function stands in for any library
// that verifies bearer tokens: it hands the verified claims to rbac with
// rbac.ContextWithClaims. (A library that keeps claims under its own context
// key works too, with rbac.WithClaimsSource.)
//
//	go run ./examples/middleware
//
// Users: alice is an editor, bob a viewer; any other token is rejected.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/tpyle/rbac"
)

const policyJSON = `{"roles": {
	"viewer": {"permissions": ["posts:read"]},
	"editor": {"inherits": ["viewer"], "permissions": ["posts:*"]}
}}`

// tokens maps each demo bearer token to the claims verifying it would
// yield. A real authenticator checks a signature instead.
var tokens = map[string]*rbac.Claims{
	"alice-token": {Subject: "alice", Values: map[string]any{"roles": []any{"editor"}}},
	"bob-token":   {Subject: "bob", Values: map[string]any{"roles": []any{"viewer"}}},
}

// requests are the calls the demo makes, with the Authorization header
// they send.
var requests = []struct{ method, path, authorization string }{
	{"GET", "/posts/1", ""},
	{"GET", "/posts/1", "Bearer forged"},
	{"GET", "/posts/1", "Basic alice-token"},
	{"GET", "/posts/1", "Bearer bob-token"},
	{"DELETE", "/posts/1", "Bearer bob-token"},
	{"DELETE", "/posts/1", "Bearer alice-token"},
}

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(out io.Writer) error {
	policy, err := rbac.ParsePolicyJSON([]byte(policyJSON))
	if err != nil {
		return err
	}
	// Roles are embedded in the tokens, so no RoleStore is needed here.
	enforcer, err := rbac.New(
		rbac.WithPolicy(policy),
		rbac.WithClaimsSource(rbac.ClaimsFromContext), // where authenticate puts them
	)
	if err != nil {
		return err
	}

	handler := authenticate(routes(enforcer))
	for _, req := range requests {
		r := httptest.NewRequest(req.method, req.path, nil)
		if req.authorization != "" {
			r.Header.Set("Authorization", req.authorization)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if _, err := fmt.Fprintf(out, "%-6s %-8s %-20q %d\n", req.method, req.path, req.authorization, w.Code); err != nil {
			return err
		}
	}
	return nil
}

// authenticate stores the claims of a valid bearer token in the request
// context, and rejects invalid tokens and other authorization schemes.
// Requests without an Authorization header pass through unauthenticated,
// and rbac's middleware answers them with 401.
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			next.ServeHTTP(w, r)
			return
		}
		token, isBearer := strings.CutPrefix(header, "Bearer ")
		claims, ok := tokens[token]
		if !isBearer || !ok {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(rbac.ContextWithClaims(r.Context(), claims)))
	})
}

// routes protects each route with a permission.
func routes(e *rbac.Enforcer) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mux.Handle("GET /posts/{id}", e.RequireAllPermissions("posts:read")(ok))
	mux.Handle("DELETE /posts/{id}", e.RequireAllPermissions("posts:delete")(ok))
	return mux
}
