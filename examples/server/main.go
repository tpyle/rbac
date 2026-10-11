// Command server is a small JSON API protected by roles and permissions. The
// policy is policy.yaml, built into the binary (override it with -policy),
// and flags choose which claims are embedded in access tokens.
//
//	go run ./examples/server -embed-roles -embed-permissions
//	curl -s -XPOST localhost:8080/login -d '{"username":"bob","password":"password"}'
//	curl -s localhost:8080/me -H "Authorization: Bearer <access_token>"
//	curl -s -XDELETE localhost:8080/posts/1 -H "Authorization: Bearer <access_token>"
//
// Users (all with password "password"): alice is an admin, bob an editor,
// carol a viewer and dave has no roles.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
	"github.com/tpyle/rbac/rbacyaml"
)

//go:embed policy.yaml
var defaultPolicy []byte

// demoUsers maps each user to their assigned roles.
var demoUsers = map[string][]string{
	"alice": {"admin"},
	"bob":   {"editor"},
	"carol": {"viewer"},
	"dave":  nil,
}

func main() {
	policyPath := flag.String("policy", "", "path to a YAML policy (default: the built-in policy.yaml)")
	embedRoles := flag.Bool("embed-roles", true, "embed roles in access tokens")
	embedPerms := flag.Bool("embed-permissions", false, "embed permissions in access tokens")
	flag.Parse()

	policy, err := loadPolicy(*policyPath)
	if err != nil {
		log.Fatal(err)
	}

	app, err := newApp(context.Background(), policy, rbac.Config{
		EmbedRoles:       *embedRoles,
		EmbedPermissions: *embedPerms,
		RolesClaim:       "roles",
		PermissionsClaim: "perms",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = app.auth.Close() }()

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("listening", "addr", srv.Addr, "embed_roles", *embedRoles, "embed_permissions", *embedPerms)
	log.Fatal(srv.ListenAndServe())
}

// loadPolicy reads the policy at path, or the built-in one if path is empty.
func loadPolicy(path string) (*rbac.Policy, error) {
	if path == "" {
		return rbacyaml.LoadPolicy(bytes.NewReader(defaultPolicy))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return rbacyaml.LoadPolicy(f)
}

type app struct {
	auth  *auth.Authorizer
	rbac  *rbac.Enforcer
	roles *rbac.MemoryRoleStore
}

// newApp wires auth and rbac together and creates the demo users.
func newApp(ctx context.Context, policy *rbac.Policy, cfg rbac.Config, authOpts ...auth.Option) (*app, error) {
	roles := rbac.NewMemoryRoleStore()
	enforcer, err := rbac.New(
		rbac.WithConfig(cfg),
		rbac.WithRoleStore(roles),
		rbac.WithPolicy(policy),
	)
	if err != nil {
		return nil, err
	}

	users := auth.NewMemoryUserStore()
	opts := append([]auth.Option{
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
	}, authOpts...)
	a, err := auth.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	hash, err := a.HashPassword(ctx, []byte("password"))
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	for user, userRoles := range demoUsers {
		users.SetPasswordHash(user, hash)
		roles.SetRoles(user, userRoles...)
	}
	return &app{auth: a, rbac: enforcer, roles: roles}, nil
}

func (a *app) routes() http.Handler {
	// Routes behind RequireAuthHandler have verified claims in their context,
	// which the rbac middleware and checks read.
	protected := http.NewServeMux()
	protected.HandleFunc("GET /me", a.me)
	protected.Handle("GET /posts", a.rbac.RequireAllPermissions("posts:read")(
		jsonHandler(map[string]any{"posts": []string{"hello world"}})))
	protected.Handle("POST /posts", a.rbac.RequireAllPermissions("posts:create")(
		jsonHandler(map[string]string{"status": "created"})))
	protected.Handle("DELETE /posts/{id}", a.rbac.RequireAllPermissions("posts:delete")(
		jsonHandler(map[string]string{"status": "deleted"})))
	protected.Handle("GET /admin/users", a.rbac.RequireAnyRole("admin")(
		jsonHandler(map[string]any{"users": demoUsers})))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", a.login)
	mux.Handle("/", a.auth.RequireAuthHandler(protected))
	return mux
}

// me shows how handlers can run checks themselves, for decisions finer than
// a whole route.
func (a *app) me(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	canModerate, err := a.rbac.CanAny(r.Context(), "comments:delete", "posts:delete")
	if err != nil {
		slog.ErrorContext(r.Context(), "checking access", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":      claims.Subject,
		"token_claims": claims.Extra,
		"can_moderate": canModerate,
	})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	pair, err := a.auth.Login(r.Context(), req.Username, []byte(req.Password))
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case err != nil:
		slog.ErrorContext(r.Context(), "login", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken,
		})
	}
}

func jsonHandler(body any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, body)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
