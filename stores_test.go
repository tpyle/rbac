package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestMemoryRoleStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRoleStore()
	roles := func(subject string) []string {
		t.Helper()
		r, err := s.Roles(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	if got := roles("alice"); len(got) != 0 {
		t.Errorf("unknown subject roles = %v", got)
	}
	s.SetRoles("alice", "viewer", "editor", "viewer")
	if got, want := roles("alice"), []string{"editor", "viewer"}; !slices.Equal(got, want) {
		t.Errorf("after SetRoles = %v, want %v", got, want)
	}
	s.AddRoles("alice", "admin", "editor")
	if got, want := roles("alice"), []string{"admin", "editor", "viewer"}; !slices.Equal(got, want) {
		t.Errorf("after AddRoles = %v, want %v", got, want)
	}
	s.RemoveRoles("alice", "editor", "ghost")
	if got, want := roles("alice"), []string{"admin", "viewer"}; !slices.Equal(got, want) {
		t.Errorf("after RemoveRoles = %v, want %v", got, want)
	}

	got := roles("alice")
	got[0] = "changed"
	if roles("alice")[0] != "admin" {
		t.Error("store changed through returned slice")
	}

	s.RemoveRoles("alice", "admin", "viewer")
	s.AddRoles("bob", "viewer")
	s.SetRoles("bob")
	s.AddRoles("ghost")
	if len(s.roles) != 0 {
		t.Errorf("subjects without roles kept: %v", s.roles)
	}
}

func TestMemoryRoleStoreConcurrent(t *testing.T) {
	s := NewMemoryRoleStore()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			s.AddRoles("alice", "r")
			if i%2 == 0 {
				s.RemoveRoles("alice", "r")
			}
			_, _ = s.Roles(context.Background(), "alice")
		})
	}
	wg.Wait()
}

func TestFuncAdapters(t *testing.T) {
	ctx := context.Background()
	rs := RoleStoreFunc(func(_ context.Context, subject string) ([]string, error) {
		return []string{subject}, nil
	})
	if got, _ := rs.Roles(ctx, "x"); !slices.Equal(got, []string{"x"}) {
		t.Errorf("RoleStoreFunc = %v", got)
	}
	p := mustPolicy(t, nil)
	pp := PolicyProviderFunc(func(context.Context) (*Policy, error) { return p, nil })
	if got, _ := pp.Policy(ctx); got != p {
		t.Error("PolicyProviderFunc returned wrong policy")
	}
	if got, _ := StaticPolicy(p).Policy(ctx); got != p {
		t.Error("StaticPolicy returned wrong policy")
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestCachedPolicyProvider(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	var loads int
	var loadErr error
	policies := []*Policy{mustPolicy(t, nil), mustPolicy(t, nil), mustPolicy(t, nil)}
	c := NewCachedPolicyProvider(func(context.Context) (*Policy, error) {
		if loadErr != nil {
			return nil, loadErr
		}
		loads++
		return policies[loads-1], nil
	}, time.Minute)
	c.now = clock.now

	get := func() *Policy {
		t.Helper()
		p, err := c.Policy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	first, second := get(), get()
	if first != policies[0] || second != policies[0] || loads != 1 {
		t.Fatalf("expected one load, got %d", loads)
	}
	clock.advance(59 * time.Second)
	if get() != policies[0] {
		t.Fatal("reloaded before TTL")
	}
	clock.advance(time.Second)
	if get() != policies[1] {
		t.Fatal("did not reload at TTL")
	}

	c.Invalidate()
	loadErr = errors.New("db down")
	if _, err := c.Policy(ctx); !errors.Is(err, loadErr) {
		t.Fatalf("err = %v, want load error", err)
	}
	loadErr = nil
	if get() != policies[2] {
		t.Fatal("did not retry after failed load")
	}
}

func TestCachedPolicyProviderNoTTL(t *testing.T) {
	var loads int
	c := NewCachedPolicyProvider(func(context.Context) (*Policy, error) {
		loads++
		return mustPolicy(t, nil), nil
	}, 0)
	for range 3 {
		if _, err := c.Policy(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 3 {
		t.Errorf("loads = %d, want 3", loads)
	}
}

func TestCachedPolicyProviderNilPolicy(t *testing.T) {
	var loads int
	c := NewCachedPolicyProvider(func(context.Context) (*Policy, error) {
		loads++
		return nil, nil
	}, time.Minute)
	for _, ttl := range []time.Duration{time.Minute, 0} {
		c.ttl = ttl
		for range 2 {
			if _, err := c.Policy(context.Background()); !errors.Is(err, ErrNilPolicy) {
				t.Fatalf("ttl %v: err = %v, want ErrNilPolicy", ttl, err)
			}
		}
	}
	if loads != 4 {
		t.Errorf("loads = %d, want 4 (nil results are not cached)", loads)
	}
}

// gatedLoader is a loader that blocks until released and counts its calls.
type gatedLoader struct {
	release chan struct{}
	p       *Policy
	err     error
	calls   atomic.Int32
	// ctxErr records the loader context's error when it was released.
	ctxErr atomic.Value
}

func newGatedLoader(p *Policy, err error) *gatedLoader {
	return &gatedLoader{release: make(chan struct{}), p: p, err: err}
}

func (g *gatedLoader) load(ctx context.Context) (*Policy, error) {
	g.calls.Add(1)
	<-g.release
	g.ctxErr.Store(fmt.Sprint(ctx.Err()))
	return g.p, g.err
}

// startCallers calls c.Policy from n goroutines and returns their results
// once all have returned.
func startCallers(ctx context.Context, c *CachedPolicyProvider, n int) func() ([]*Policy, []error) {
	var wg sync.WaitGroup
	ps, errs := make([]*Policy, n), make([]error, n)
	for i := range n {
		wg.Go(func() { ps[i], errs[i] = c.Policy(ctx) })
	}
	return func() ([]*Policy, []error) {
		wg.Wait()
		return ps, errs
	}
}

func TestCachedPolicyProviderSharesLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := mustPolicy(t, nil)
		g := newGatedLoader(p, nil)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		wait := startCallers(context.Background(), c, 5)
		synctest.Wait() // all five are blocked on the one load
		close(g.release)
		ps, errs := wait()
		for i := range ps {
			if ps[i] != p || errs[i] != nil {
				t.Errorf("caller %d: %v, %v", i, ps[i], errs[i])
			}
		}
		if n := g.calls.Load(); n != 1 {
			t.Errorf("loads = %d, want 1", n)
		}
	})
}

func TestCachedPolicyProviderSharesFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		loadErr := errors.New("db down")
		g := newGatedLoader(nil, loadErr)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		wait := startCallers(context.Background(), c, 5)
		synctest.Wait()
		close(g.release)
		_, errs := wait()
		for i, err := range errs {
			if !errors.Is(err, loadErr) {
				t.Errorf("caller %d: err = %v, want load error", i, err)
			}
		}
		if n := g.calls.Load(); n != 1 {
			t.Errorf("loads = %d, want 1 (waiters share the failure)", n)
		}

		// The failure is not cached: the next call retries.
		g.release = make(chan struct{})
		close(g.release)
		if _, err := c.Policy(context.Background()); !errors.Is(err, loadErr) {
			t.Errorf("retry err = %v", err)
		}
		if n := g.calls.Load(); n != 2 {
			t.Errorf("loads = %d, want 2", n)
		}
	})
}

func TestCachedPolicyProviderCancelledStarter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := mustPolicy(t, nil)
		g := newGatedLoader(p, nil)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		// The caller that starts the load gives up...
		ctx, cancel := context.WithCancel(context.Background())
		waitStarter := startCallers(ctx, c, 1)
		synctest.Wait()
		// ...while another caller is waiting for the same load.
		waitOther := startCallers(context.Background(), c, 1)
		synctest.Wait()
		cancel()
		if _, errs := waitStarter(); !errors.Is(errs[0], context.Canceled) {
			t.Errorf("starter err = %v, want context.Canceled", errs[0])
		}

		close(g.release)
		if ps, errs := waitOther(); ps[0] != p || errs[0] != nil {
			t.Errorf("other caller = %v, %v; want the loaded policy", ps[0], errs[0])
		}
		if got := g.ctxErr.Load(); got != "<nil>" {
			t.Errorf("loader context error = %v, want none", got)
		}
		// The load completed and was cached despite the cancellation.
		if got, err := c.Policy(context.Background()); got != p || err != nil || g.calls.Load() != 1 {
			t.Errorf("after load: %v, %v, loads = %d", got, err, g.calls.Load())
		}
	})
}

func TestCachedPolicyProviderNoTTLIsConcurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGatedLoader(mustPolicy(t, nil), nil)
		c := NewCachedPolicyProvider(g.load, 0)

		wait := startCallers(context.Background(), c, 3)
		synctest.Wait()
		// All three loads are running at once: nothing is serialized.
		if n := g.calls.Load(); n != 3 {
			t.Errorf("concurrent loads = %d, want 3", n)
		}
		close(g.release)
		wait()
	})
}

func TestCachedPolicyProviderInvalidateDuringLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := mustPolicy(t, nil)
		g := newGatedLoader(p, nil)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		waitOld := startCallers(context.Background(), c, 1)
		synctest.Wait()
		c.Invalidate()
		// A caller after Invalidate does not join the stale load, and its
		// load waits for the stale one rather than running alongside it.
		waitNew := startCallers(context.Background(), c, 1)
		synctest.Wait()
		if n := g.calls.Load(); n != 1 {
			t.Errorf("loads while stale load runs = %d, want 1", n)
		}
		close(g.release)
		if ps, _ := waitOld(); ps[0] != p {
			t.Error("caller waiting on the stale load got no policy")
		}
		if ps, errs := waitNew(); ps[0] != p || errs[0] != nil {
			t.Errorf("caller after Invalidate = %v, %v", ps[0], errs[0])
		}
		if n := g.calls.Load(); n != 2 {
			t.Errorf("loads = %d, want 2", n)
		}

		// The new load was cached; the stale one did not overwrite it.
		if _, err := c.Policy(context.Background()); err != nil || g.calls.Load() != 2 {
			t.Errorf("after loads: err = %v, loads = %d", err, g.calls.Load())
		}
	})
}

func TestCachedPolicyProviderRepeatedInvalidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGatedLoader(mustPolicy(t, nil), nil)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		var waits []func() ([]*Policy, []error)
		waits = append(waits, startCallers(context.Background(), c, 1))
		synctest.Wait()
		for range 10 {
			c.Invalidate()
			waits = append(waits, startCallers(context.Background(), c, 2))
			synctest.Wait()
		}
		if n := g.calls.Load(); n != 1 {
			t.Errorf("concurrent loads = %d, want 1", n)
		}
		close(g.release)
		for _, wait := range waits {
			if _, errs := wait(); errs[0] != nil {
				t.Error(errs[0])
			}
		}
		// One stale load, then one shared follow-up for everyone after it.
		if n := g.calls.Load(); n != 2 {
			t.Errorf("loads = %d, want 2", n)
		}
		if c.policy == nil {
			t.Error("follow-up load was not cached")
		}
	})
}

func TestCachedPolicyProviderLoaderPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		release := make(chan struct{})
		c := NewCachedPolicyProvider(func(context.Context) (*Policy, error) {
			if calls.Add(1) == 1 {
				<-release
				panic("boom")
			}
			return mustPolicy(t, nil), nil
		}, time.Minute)

		wait := startCallers(context.Background(), c, 3)
		synctest.Wait()
		close(release)
		_, errs := wait()
		for i, err := range errs {
			if err == nil || !strings.Contains(err.Error(), "panicked: boom") {
				t.Errorf("caller %d: err = %v, want the panic", i, err)
			}
		}
		// The provider still works after the panic.
		if p, err := c.Policy(context.Background()); p == nil || err != nil {
			t.Errorf("after panic: %v, %v", p, err)
		}
	})
}

func TestCachedPolicyProviderStaleLoadNotCached(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newGatedLoader(mustPolicy(t, nil), nil)
		c := NewCachedPolicyProvider(g.load, time.Minute)

		wait := startCallers(context.Background(), c, 1)
		synctest.Wait()
		c.Invalidate()
		close(g.release)
		wait()
		if c.policy != nil {
			t.Error("load that straddled Invalidate was cached")
		}
	})
}

func TestCachedPolicyProviderLoadTimeout(t *testing.T) {
	for _, ttl := range []time.Duration{time.Minute, 0} {
		t.Run(fmt.Sprint("ttl ", ttl), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// The loader ignores its context and never returns on its own.
				g := newGatedLoader(mustPolicy(t, nil), nil)
				c := NewCachedPolicyProvider(g.load, ttl, WithLoadTimeout(time.Second))

				start := time.Now()
				if _, err := c.Policy(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("err = %v, want context.DeadlineExceeded", err)
				}
				if d := time.Since(start); d != time.Second {
					t.Errorf("gave up after %v, want 1s", d)
				}
				// The hung load does not block the next one.
				close(g.release)
				if _, err := c.Policy(context.Background()); err != nil {
					t.Errorf("after timeout: %v", err)
				}
			})
		})
	}
}

func TestCachedPolicyProviderDefaultLoadTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var deadline time.Time
		c := NewCachedPolicyProvider(func(ctx context.Context) (*Policy, error) {
			deadline, _ = ctx.Deadline()
			return mustPolicy(t, nil), nil
		}, time.Minute)
		start := time.Now()
		if _, err := c.Policy(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := deadline.Sub(start); got != DefaultLoadTimeout {
			t.Errorf("loader deadline in %v, want %v", got, DefaultLoadTimeout)
		}
	})
}

func TestCachedPolicyProviderNoLoadTimeout(t *testing.T) {
	var hasDeadline bool
	c := NewCachedPolicyProvider(func(ctx context.Context) (*Policy, error) {
		_, hasDeadline = ctx.Deadline()
		return mustPolicy(t, nil), nil
	}, time.Minute, WithLoadTimeout(0))
	if _, err := c.Policy(context.Background()); err != nil || hasDeadline {
		t.Errorf("err = %v, loader had deadline = %v", err, hasDeadline)
	}
}

func TestCachedPolicyProviderStaleGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		old, fresh := mustPolicy(t, nil), mustPolicy(t, nil)
		g := newGatedLoader(old, nil)
		close(g.release)
		c := NewCachedPolicyProvider(g.load, time.Minute, WithStaleGrace(time.Minute))
		if p, err := c.Policy(ctx); p != old || err != nil {
			t.Fatalf("first load: %v, %v", p, err)
		}

		// Past the TTL, within grace: the old policy is served at once while
		// a reload runs, and a failed reload keeps it in use.
		time.Sleep(90 * time.Second)
		g.release, g.p, g.err = make(chan struct{}), nil, errors.New("db down")
		for range 3 {
			if p, err := c.Policy(ctx); p != old || err != nil {
				t.Fatalf("within grace: %v, %v", p, err)
			}
		}
		synctest.Wait()
		if n := g.calls.Load(); n != 2 {
			t.Errorf("loads = %d, want 2 (one background reload)", n)
		}
		close(g.release)
		synctest.Wait()
		if p, err := c.Policy(ctx); p != old || err != nil {
			t.Fatalf("after failed reload: %v, %v", p, err)
		}

		// A successful background reload replaces it.
		synctest.Wait() // the reload started by the call above has failed
		g.p, g.err = fresh, nil
		if p, _ := c.Policy(ctx); p != old {
			t.Errorf("starting reload: got %v, want the old policy", p)
		}
		synctest.Wait()
		if p, _ := c.Policy(ctx); p != fresh {
			t.Errorf("after reload: got old policy")
		}

		// Past the grace period, callers wait for the load and see errors.
		time.Sleep(2*time.Minute + time.Second)
		g.err = errors.New("db down")
		if _, err := c.Policy(ctx); !errors.Is(err, g.err) {
			t.Errorf("after grace: err = %v, want load error", err)
		}

		// Invalidate ends grace at once.
		g.err = nil
		if _, err := c.Policy(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(90 * time.Second)
		c.Invalidate()
		g.err = errors.New("db down")
		if _, err := c.Policy(ctx); !errors.Is(err, g.err) {
			t.Errorf("after Invalidate: err = %v, want load error", err)
		}
	})
}
