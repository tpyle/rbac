package rbac

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
})

func serve(h http.Handler, ctx context.Context) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMiddleware(t *testing.T) {
	var logs bytes.Buffer
	f := newFixture(t, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	alice := claimsCtx("alice", f.tokenClaims(t, "alice"))
	bob := claimsCtx("bob", f.tokenClaims(t, "bob"))
	anon := context.Background()

	tests := []struct {
		name       string
		mw         Middleware
		ctx        context.Context
		wantStatus int
		wantBody   string
	}{
		{"role allowed", f.e.RequireAnyRole("admin", "editor"), alice, 200, "ok"},
		{"role denied", f.e.RequireAnyRole("admin"), alice, 403, `{"error":"forbidden"}`},
		{"role no roles", f.e.RequireAnyRole("viewer"), bob, 403, `{"error":"forbidden"}`},
		{"role anonymous", f.e.RequireAnyRole("viewer"), anon, 401, `{"error":"unauthorized"}`},
		{"all allowed", f.e.RequireAllPermissions("posts:read", "posts:write"), alice, 200, "ok"},
		{"all partial", f.e.RequireAllPermissions("posts:read", "users:read"), alice, 403, `{"error":"forbidden"}`},
		{"all anonymous", f.e.RequireAllPermissions("posts:read"), anon, 401, `{"error":"unauthorized"}`},
		{"any allowed", f.e.RequireAnyPermission("users:read", "posts:read"), alice, 200, "ok"},
		{"any denied", f.e.RequireAnyPermission("users:read"), bob, 403, `{"error":"forbidden"}`},
		{"malformed claim", f.e.RequireAnyRole("viewer"),
			claimsCtx("alice", map[string]any{"roles": "editor"}), 500, `{"error":"internal_error"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs.Reset()
			w := serve(tt.mw(okHandler), tt.ctx)
			if w.Code != tt.wantStatus || strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("got %d %q, want %d %q", w.Code, w.Body.String(), tt.wantStatus, tt.wantBody)
			}
			if tt.wantStatus != 200 && w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
			}
			if got := w.Header().Get("WWW-Authenticate"); (tt.wantStatus == 401) != (got == "Bearer") {
				t.Errorf("WWW-Authenticate = %q", got)
			}
			if logged := logs.Len() > 0; logged != (tt.wantStatus == 500) {
				t.Errorf("logged = %v for status %d: %s", logged, tt.wantStatus, logs.String())
			}
		})
	}
}

func TestMiddlewareStoreError(t *testing.T) {
	f := newFixture(t, WithEmbedRoles(false), WithLogger(slog.New(slog.DiscardHandler)))
	f.store.err = errors.New("db down")
	w := serve(f.e.RequireAllPermissions("posts:read")(okHandler), claimsCtx("alice", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMiddlewareClientGone(t *testing.T) {
	var logs bytes.Buffer
	f := newFixture(t, WithEmbedRoles(false), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	f.store.err = context.Canceled
	mw := f.e.RequireAllPermissions("posts:read")(okHandler)

	// The request was cancelled: not an internal error worth logging.
	ctx, cancel := context.WithCancel(claimsCtx("alice", nil))
	cancel()
	serve(mw, ctx)
	if logs.Len() != 0 {
		t.Errorf("logged a cancelled request: %s", logs.String())
	}

	// A cancellation the request did not cause is still logged.
	serve(mw, claimsCtx("alice", nil))
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("cancellation from elsewhere not logged: %q", logs.String())
	}

	// So are deadlines, which point at a slow store.
	logs.Reset()
	f.store.err = context.DeadlineExceeded
	ctx, cancel = context.WithTimeout(claimsCtx("alice", nil), 0)
	defer cancel()
	serve(mw, ctx)
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("deadline not logged: %q", logs.String())
	}
}

func TestCustomErrorHandler(t *testing.T) {
	var gotErr error
	f := newFixture(t, WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusTeapot)
	}))
	w := serve(f.e.RequireAnyRole("admin")(okHandler), claimsCtx("bob", f.tokenClaims(t, "bob")))
	if w.Code != http.StatusTeapot || !errors.Is(gotErr, ErrForbidden) {
		t.Errorf("status = %d, err = %v", w.Code, gotErr)
	}
	serve(f.e.RequireAnyRole("admin")(okHandler), context.Background())
	if !errors.Is(gotErr, ErrNoClaims) {
		t.Errorf("err = %v, want ErrNoClaims", gotErr)
	}
}

func TestMiddlewarePanicsOnBadArguments(t *testing.T) {
	f := newFixture(t)
	for name, build := range map[string]func(){
		"no roles":           func() { f.e.RequireAnyRole() },
		"invalid role":       func() { f.e.RequireAnyRole("a b") },
		"no permissions":     func() { f.e.RequireAllPermissions() },
		"wildcard (all)":     func() { f.e.RequireAllPermissions("posts:*") },
		"no permissions any": func() { f.e.RequireAnyPermission() },
		"invalid (any)":      func() { f.e.RequireAnyPermission("posts:") },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			build()
		})
	}
}

func TestMiddlewareCopiesArguments(t *testing.T) {
	f := newFixture(t)
	ctx := claimsCtx("alice", f.tokenClaims(t, "alice"))
	roles := []string{"editor"}
	perms := []string{"posts:write"}
	mws := []Middleware{f.e.RequireAnyRole(roles...), f.e.RequireAllPermissions(perms...), f.e.RequireAnyPermission(perms...)}
	roles[0], perms[0] = "admin", "users:delete"
	for i, mw := range mws {
		if w := serve(mw(okHandler), ctx); w.Code != http.StatusOK {
			t.Errorf("middleware %d: status = %d; it saw the caller's later change", i, w.Code)
		}
	}
}
