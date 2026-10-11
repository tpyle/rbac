package rbac_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

// cheapArgon2 keeps password hashing fast in tests.
var cheapArgon2 = auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

type authEnv struct {
	a     *auth.Authorizer
	e     *rbac.Enforcer
	roles *rbac.MemoryRoleStore
	now   time.Time
}

// newAuthEnv wires a real auth.Authorizer to an enforcer. alice is an
// editor; mallory has no roles.
func newAuthEnv(t *testing.T, opts ...rbac.Option) *authEnv {
	t.Helper()
	ctx := context.Background()
	policy, err := rbac.ParsePolicyJSON([]byte(`{"roles": {
		"viewer": {"permissions": ["posts:read"]},
		"editor": {"inherits": ["viewer"], "permissions": ["posts:write"]},
		"admin":  {"inherits": ["editor"], "permissions": ["users:*"]}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	env := &authEnv{roles: rbac.NewMemoryRoleStore(), now: time.Unix(1_800_000_000, 0)}
	env.roles.SetRoles("alice", "editor")

	base := []rbac.Option{rbac.WithRoleStore(env.roles), rbac.WithPolicy(policy)}
	if env.e, err = rbac.New(append(base, opts...)...); err != nil {
		t.Fatal(err)
	}

	users := auth.NewMemoryUserStore()
	env.a, err = auth.New(ctx,
		auth.WithUserStore(users),
		auth.WithRefreshTokenStore(auth.NewMemoryRefreshTokenStore()),
		auth.WithArgon2Params(cheapArgon2),
		auth.WithClaimsProvider(env.e.ClaimsProvider(nil)),
		auth.WithClock(func() time.Time { return env.now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.a.Close() })
	for _, u := range []string{"alice", "mallory"} {
		hash, err := env.a.HashPassword(ctx, []byte("pw-"+u))
		if err != nil {
			t.Fatal(err)
		}
		users.SetPasswordHash(u, hash)
	}
	return env
}

func (env *authEnv) login(t *testing.T, user string) *auth.TokenPair {
	t.Helper()
	pair, err := env.a.Login(context.Background(), user, []byte("pw-"+user))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func (env *authEnv) server() http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux := http.NewServeMux()
	mux.Handle("GET /posts", env.e.RequireAllPermissions("posts:read")(ok))
	mux.Handle("POST /posts", env.e.RequireAllPermissions("posts:write")(ok))
	mux.Handle("GET /admin", env.e.RequireAnyRole("admin")(ok))
	return env.a.RequireAuthHandler(mux)
}

func do(t *testing.T, h http.Handler, method, path, token string) int {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestEndToEnd(t *testing.T) {
	configs := map[string][]rbac.Option{
		"nothing embedded": {rbac.WithEmbedRoles(false)},
		"roles":            nil,
		"permissions":      {rbac.WithEmbedRoles(false), rbac.WithEmbedPermissions(true)},
		"both":             {rbac.WithEmbedPermissions(true)},
	}
	for name, opts := range configs {
		t.Run(name, func(t *testing.T) {
			env := newAuthEnv(t, opts...)
			h := env.server()
			alice := env.login(t, "alice").AccessToken
			mallory := env.login(t, "mallory").AccessToken

			tests := []struct {
				method, path, token string
				want                int
			}{
				{"GET", "/posts", "", http.StatusUnauthorized},
				{"GET", "/posts", alice, http.StatusNoContent},
				{"POST", "/posts", alice, http.StatusNoContent},
				{"GET", "/admin", alice, http.StatusForbidden},
				{"GET", "/posts", mallory, http.StatusForbidden},
			}
			for _, tt := range tests {
				if got := do(t, h, tt.method, tt.path, tt.token); got != tt.want {
					t.Errorf("%s %s = %d, want %d", tt.method, tt.path, got, tt.want)
				}
			}
		})
	}
}

// TestRoleChangeVisibility shows the freshness trade-off: lookups see role
// changes immediately, embedded claims after the next refresh.
func TestRoleChangeVisibility(t *testing.T) {
	ctx := context.Background()
	for _, embed := range []bool{false, true} {
		env := newAuthEnv(t, rbac.WithEmbedRoles(embed))
		pair := env.login(t, "alice")
		claims, err := env.a.VerifyAccessToken(ctx, pair.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := claims.Extra["roles"]; ok != embed {
			t.Fatalf("embed=%v: roles claim present = %v", embed, ok)
		}

		env.roles.SetRoles("alice", "admin")
		ok, err := env.e.ClaimsHaveAnyRole(ctx, claims, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if ok == embed {
			t.Errorf("embed=%v: old token is admin = %v", embed, ok)
		}

		env.now = env.now.Add(time.Minute)
		next, err := env.a.Refresh(ctx, pair.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		if claims, err = env.a.VerifyAccessToken(ctx, next.AccessToken); err != nil {
			t.Fatal(err)
		}
		if ok, err := env.e.ClaimsCanAll(ctx, claims, "users:delete"); err != nil || !ok {
			t.Errorf("embed=%v: refreshed token users:delete = %v, %v", embed, ok, err)
		}
	}
}
