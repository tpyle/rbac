package rbac

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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

func TestMiddlewarePanicsWhenUnanswerable(t *testing.T) {
	p := mustPolicy(t, testDefs)
	roles, scoped := NewMemoryRoleStore(), NewMemoryScopedRoleStore()
	res := PathResource("projects/{id}")
	builders := map[string]func(*Enforcer){
		"role":    func(e *Enforcer) { e.RequireAnyRole("editor") },
		"all":     func(e *Enforcer) { e.RequireAllPermissions("posts:read") },
		"any":     func(e *Enforcer) { e.RequireAnyPermission("posts:read") },
		"role on": func(e *Enforcer) { e.RequireAnyRoleOn(res, "editor") },
		"all on":  func(e *Enforcer) { e.RequireAllPermissionsOn(res, "posts:read") },
		"any on":  func(e *Enforcer) { e.RequireAnyPermissionOn(res, "posts:read") },
	}
	tests := []struct {
		name   string
		opts   []Option
		panics []string
	}{
		{"everything", []Option{WithRoleStore(roles), WithScopedRoleStore(scoped), WithPolicy(p)}, nil},
		{"embedded roles only", []Option{WithPolicy(p)},
			[]string{"role on", "all on", "any on"}},
		{"scoped store only", []Option{WithEmbedRoles(false), WithScopedRoleStore(scoped), WithPolicy(p)},
			[]string{"role", "all", "any"}},
		{"embedded permissions, no policy", []Option{WithEmbedRoles(false), WithEmbedPermissions(true), WithScopedRoleStore(scoped)},
			[]string{"role", "all on", "any on"}},
		{"scoped roles only", []Option{WithScopedRolesOnly(), WithRoleStore(roles), WithScopedRoleStore(scoped), WithPolicy(p)},
			[]string{"role", "all", "any"}},
	}
	for _, tt := range tests {
		e, err := New(tt.opts...)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		for name, build := range builders {
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				defer func() {
					got := recover()
					if want := slices.Contains(tt.panics, name); (got != nil) != want {
						t.Errorf("panic = %v, want panic: %v", got, want)
					}
					if err, ok := got.(error); got != nil && (!ok || !errors.Is(err, ErrNotConfigured)) {
						t.Errorf("panic = %v, want ErrNotConfigured", got)
					}
				}()
				build(e)
			})
		}
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

func TestScopedMiddleware(t *testing.T) {
	var logs bytes.Buffer
	f := newScopedFixture(t, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	carol := claimsCtx("carol", f.tokenClaims(t, "carol"))
	anon := context.Background()
	doc := PathResource("projects/{project}/docs/{doc}")
	failing := ResourceFunc(func(*http.Request) (string, error) { return "", errors.New("lookup failed") })
	invalid := ResourceFunc(func(*http.Request) (string, error) { return "projects/*", nil })

	tests := []struct {
		name         string
		mw           Middleware
		ctx          context.Context
		project, doc string
		wantStatus   int
		wantBody     string
	}{
		{"all allowed", f.e.RequireAllPermissionsOn(doc, "posts:read", "posts:write"), carol, "42", "7", 200, "ok"},
		{"all denied", f.e.RequireAllPermissionsOn(doc, "posts:write"), carol, "43", "7", 403, `{"error":"forbidden"}`},
		{"all anonymous", f.e.RequireAllPermissionsOn(doc, "posts:read"), anon, "42", "7", 401, `{"error":"unauthorized"}`},
		{"any allowed", f.e.RequireAnyPermissionOn(doc, "users:delete", "posts:write"), carol, "42", "7", 200, "ok"},
		{"any denied", f.e.RequireAnyPermissionOn(doc, "users:delete"), carol, "42", "7", 403, `{"error":"forbidden"}`},
		{"role allowed", f.e.RequireAnyRoleOn(doc, "editor"), carol, "42", "1", 200, "ok"},
		{"role denied", f.e.RequireAnyRoleOn(doc, "admin"), carol, "42", "1", 403, `{"error":"forbidden"}`},
		{"empty path value", f.e.RequireAllPermissionsOn(doc, "posts:read"), carol, "42", "", 400, `{"error":"bad_request"}`},
		{"path value with whitespace", f.e.RequireAnyRoleOn(doc, "editor"), carol, "42", "a b", 400, `{"error":"bad_request"}`},
		{"path value with wildcard", f.e.RequireAnyRoleOn(doc, "editor"), carol, "*", "1", 400, `{"error":"bad_request"}`},
		// Path values are unescaped, so "%2F" must not forge ancestry.
		{"path value with separator", f.e.RequireAnyRoleOn(doc, "editor"), carol, "42/docs", "1", 400, `{"error":"bad_request"}`},
		{"path value dot-dot", f.e.RequireAnyRoleOn(doc, "editor"), carol, "..", "1", 400, `{"error":"bad_request"}`},
		{"anonymous before bad resource", f.e.RequireAnyRoleOn(doc, "editor"), anon, "", "", 401, `{"error":"unauthorized"}`},
		{"resource func error", f.e.RequireAnyPermissionOn(failing, "posts:read"), carol, "", "", 500, `{"error":"internal_error"}`},
		{"resource func returns pattern", f.e.RequireAllPermissionsOn(invalid, "posts:read"), carol, "", "", 400, `{"error":"bad_request"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs.Reset()
			r := httptest.NewRequestWithContext(tt.ctx, http.MethodGet, "/", nil)
			r.SetPathValue("project", tt.project)
			r.SetPathValue("doc", tt.doc)
			w := httptest.NewRecorder()
			tt.mw(okHandler).ServeHTTP(w, r)
			if w.Code != tt.wantStatus || strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("got %d %q, want %d %q", w.Code, w.Body.String(), tt.wantStatus, tt.wantBody)
			}
			if logged := logs.Len() > 0; logged != (tt.wantStatus == 500) {
				t.Errorf("logged = %v for status %d: %s", logged, tt.wantStatus, logs.String())
			}
		})
	}
}

func TestScopedMiddlewareWithServeMux(t *testing.T) {
	f := newScopedFixture(t)
	carol := claimsCtx("carol", f.tokenClaims(t, "carol"))
	mux := http.NewServeMux()
	mux.Handle("GET /projects/{project}/docs/{doc}",
		f.e.RequireAllPermissionsOn(PathResource("projects/{project}/docs/{doc}"), "posts:read")(okHandler))
	for path, want := range map[string]int{
		"/projects/42/docs/7":           http.StatusOK,
		"/projects/43/docs/7":           http.StatusForbidden,
		"/projects/99/docs/1":           http.StatusOK,
		"/projects/42%2Fx/docs/1":       http.StatusBadRequest,
		"/projects/42%2F..%2F43/docs/1": http.StatusBadRequest,
		"/projects/%2E%2E/docs/1":       http.StatusBadRequest,
	} {
		r := httptest.NewRequestWithContext(carol, http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("GET %s = %d, want %d", path, w.Code, want)
		}
	}
}

func TestPathResource(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetPathValue("a", "1")
	r.SetPathValue("b", "two")
	r.SetPathValue("rest", "x/y")
	r.SetPathValue("_id2", "3")
	tests := []struct {
		pattern, want string
	}{
		{"static", "static"},
		{"{a}", "1"},
		{"projects/{a}", "projects/1"},
		{"projects/{a}/docs/{b}", "projects/1/docs/two"},
		{"files/{rest...}", "files/x/y"},
		{"files/{a...}", "files/1"},
		{"{rest...}", "x/y"},
		{"a/{_id2}/b", "a/3/b"},
	}
	for _, tt := range tests {
		got, err := PathResource(tt.pattern)(r)
		if err != nil || got != tt.want {
			t.Errorf("PathResource(%q) = %q, %v; want %q", tt.pattern, got, err, tt.want)
		}
	}
	if _, err := PathResource("projects/{missing}")(r); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("missing value err = %v, want ErrInvalidScope", err)
	}
	if _, err := PathResource("files/{rest}")(r); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("separator in single-segment value err = %v, want ErrInvalidScope", err)
	}

	for _, bad := range []string{"projects/{a", "projects/a}", "projects/{a{b}}", "projects/{}", "projects/{...}", "", "projects/../{a}", "projects//{a}", "projects/{a}/", "projects/*/{a}", "{a} {b}",
		// Placeholders must be whole segments, or requests could collide.
		"{a}{b}", "p-{a}-{b}/x", "p{a}", "{a}.json", "projects/{a}x/docs",
		// Only the last placeholder may span segments.
		"files/{rest...}/x", "{a...}/{b...}",
		// Names follow ServeMux's rules.
		"{$}", "projects/{$}", "{1a}", "{a-b}", "{a.b}",
	} {
		t.Run(bad, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("PathResource(%q) did not panic", bad)
				}
			}()
			PathResource(bad)
		})
	}
}

func TestScopedMiddlewarePanicsOnMisuse(t *testing.T) {
	f := newScopedFixture(t)
	global, err := New(WithRoleStore(NewMemoryRoleStore()), WithPolicy(mustPolicy(t, testDefs)))
	if err != nil {
		t.Fatal(err)
	}
	res := PathResource("projects/{id}")
	for name, build := range map[string]func(){
		"nil resource (role)":    func() { f.e.RequireAnyRoleOn(nil, "editor") },
		"nil resource (all)":     func() { f.e.RequireAllPermissionsOn(nil, "posts:read") },
		"nil resource (any)":     func() { f.e.RequireAnyPermissionOn(nil, "posts:read") },
		"no roles":               func() { f.e.RequireAnyRoleOn(res) },
		"invalid role":           func() { f.e.RequireAnyRoleOn(res, "a b") },
		"no permissions":         func() { f.e.RequireAllPermissionsOn(res) },
		"wildcard (all)":         func() { f.e.RequireAllPermissionsOn(res, "posts:*") },
		"invalid (any)":          func() { f.e.RequireAnyPermissionOn(res, "posts:") },
		"no scoped store (role)": func() { global.RequireAnyRoleOn(res, "editor") },
		"no scoped store (all)":  func() { global.RequireAllPermissionsOn(res, "posts:read") },
		"no scoped store (any)":  func() { global.RequireAnyPermissionOn(res, "posts:read") },
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

func TestScopedMiddlewareCopiesArguments(t *testing.T) {
	f := newScopedFixture(t)
	ctx := claimsCtx("carol", f.tokenClaims(t, "carol"))
	res := ResourceFunc(func(*http.Request) (string, error) { return "projects/42", nil })
	roles := []string{"editor"}
	perms := []string{"posts:write"}
	mws := []Middleware{f.e.RequireAnyRoleOn(res, roles...), f.e.RequireAllPermissionsOn(res, perms...), f.e.RequireAnyPermissionOn(res, perms...)}
	roles[0], perms[0] = "admin", "users:delete"
	for i, mw := range mws {
		if w := serve(mw(okHandler), ctx); w.Code != http.StatusOK {
			t.Errorf("middleware %d: status = %d; it saw the caller's later change", i, w.Code)
		}
	}
}
