package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tpyle/auth/v2"
	"github.com/tpyle/rbac"
)

func mustLoadPolicy(t *testing.T) *rbac.Policy {
	t.Helper()
	p, err := loadPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPolicyFromFile(t *testing.T) {
	p, err := loadPolicy("policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Roles(), mustLoadPolicy(t).Roles()) {
		t.Errorf("file and built-in policies differ: %v", p.Roles())
	}
	if _, err := loadPolicy("does-not-exist.yaml"); err == nil {
		t.Error("missing file: err = nil")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("rolez: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicy(bad); err == nil {
		t.Error("invalid file: err = nil")
	}
}

func TestServer(t *testing.T) {
	cheap := auth.WithArgon2Params(auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	configs := map[string]rbac.Config{
		"nothing": {RolesClaim: "roles", PermissionsClaim: "perms"},
		"roles":   {EmbedRoles: true, RolesClaim: "roles", PermissionsClaim: "perms"},
		"perms":   {EmbedPermissions: true, RolesClaim: "roles", PermissionsClaim: "perms"},
		"both":    {EmbedRoles: true, EmbedPermissions: true, RolesClaim: "roles", PermissionsClaim: "perms"},
	}
	for name, cfg := range configs {
		t.Run(name, func(t *testing.T) {
			a, err := newApp(context.Background(), mustLoadPolicy(t), cfg, cheap)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.auth.Close() })
			srv := httptest.NewServer(a.routes())
			t.Cleanup(srv.Close)

			tokens := map[string]string{}
			for user := range demoUsers {
				tokens[user] = login(t, srv.URL, user)
			}

			tests := []struct {
				user, method, path string
				want               int
			}{
				{"", "GET", "/posts", 401},
				{"dave", "GET", "/posts", 403},
				{"carol", "GET", "/posts", 200},
				{"carol", "POST", "/posts", 403},
				{"bob", "POST", "/posts", 200},
				{"bob", "DELETE", "/posts/1", 200},
				{"bob", "GET", "/admin/users", 403},
				{"alice", "GET", "/admin/users", 200},
				{"alice", "DELETE", "/posts/1", 200},
			}
			for _, tt := range tests {
				if got := call(t, srv.URL, tt.method, tt.path, tokens[tt.user]).StatusCode; got != tt.want {
					t.Errorf("%s %s as %q = %d, want %d", tt.method, tt.path, tt.user, got, tt.want)
				}
			}

			res := call(t, srv.URL, "GET", "/me", tokens["bob"])
			var me struct {
				Subject     string         `json:"subject"`
				Claims      map[string]any `json:"token_claims"`
				CanModerate bool           `json:"can_moderate"`
			}
			if err := json.NewDecoder(res.Body).Decode(&me); err != nil {
				t.Fatal(err)
			}
			_, hasRoles := me.Claims["roles"]
			_, hasPerms := me.Claims["perms"]
			if me.Subject != "bob" || !me.CanModerate || hasRoles != cfg.EmbedRoles || hasPerms != cfg.EmbedPermissions {
				t.Errorf("/me = %+v", me)
			}
		})
	}
}

func TestLoginErrors(t *testing.T) {
	a, err := newApp(context.Background(), mustLoadPolicy(t), rbac.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.auth.Close() })
	h := a.routes()
	for body, want := range map[string]int{
		`not json`:                             http.StatusBadRequest,
		`{"username":"bob","password":"nope"}`: http.StatusUnauthorized,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/login", strings.NewReader(body)))
		if w.Code != want {
			t.Errorf("login %s = %d, want %d", body, w.Code, want)
		}
	}
}

func TestNewAppInvalidConfig(t *testing.T) {
	if _, err := newApp(context.Background(), mustLoadPolicy(t), rbac.Config{}); err == nil {
		t.Error("newApp with empty config: err = nil")
	}
}

func login(t *testing.T, base, user string) string {
	t.Helper()
	body := `{"username":"` + user + `","password":"password"}`
	res, err := http.Post(base+"/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.AccessToken == "" {
		t.Fatalf("login %s: %v (status %d)", user, err, res.StatusCode)
	}
	return out.AccessToken
}

func call(t *testing.T, base, method, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}
