package rbac

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

// RoleStore is the source of truth for which roles each user is assigned,
// typically a database table. It is used to build token claims and, when a
// token lacks them, to answer checks directly.
type RoleStore interface {
	// Roles returns the roles directly assigned to subject (inherited roles
	// are added from the [Policy]). An unknown subject has no roles and
	// should return an empty slice and a nil error.
	Roles(ctx context.Context, subject string) ([]string, error)
}

// RoleStoreFunc adapts a function to a [RoleStore].
type RoleStoreFunc func(ctx context.Context, subject string) ([]string, error)

// Roles implements [RoleStore].
func (f RoleStoreFunc) Roles(ctx context.Context, subject string) ([]string, error) {
	return f(ctx, subject)
}

// PolicyProvider supplies the current [Policy]. Use [StaticPolicy] for a
// policy fixed at startup, or [NewCachedPolicyProvider] for one loaded from a
// database. It is called on every check that needs the policy, so it should
// be fast.
type PolicyProvider interface {
	Policy(ctx context.Context) (*Policy, error)
}

// PolicyProviderFunc adapts a function to a [PolicyProvider].
type PolicyProviderFunc func(ctx context.Context) (*Policy, error)

// Policy implements [PolicyProvider].
func (f PolicyProviderFunc) Policy(ctx context.Context) (*Policy, error) {
	return f(ctx)
}

type staticPolicy struct{ p *Policy }

func (s staticPolicy) Policy(context.Context) (*Policy, error) { return s.p, nil }

// StaticPolicy returns a [PolicyProvider] that always returns p.
func StaticPolicy(p *Policy) PolicyProvider {
	return staticPolicy{p}
}

// CachedPolicyProvider wraps a slow policy loader, such as a database query,
// and reuses its result for a fixed time. It is safe for concurrent use.
//
// When the cache is stale, one load runs and every caller that arrives while
// it is in progress shares its result, including a failure. At most one load
// runs at a time: callers arriving after [CachedPolicyProvider.Invalidate]
// while an earlier load is still running share a single follow-up load,
// which starts when the earlier one finishes.
//
// The load is not cancelled when the caller that started it goes away.
// Instead it is bounded by a timeout ([DefaultLoadTimeout], or see
// [WithLoadTimeout]); each caller still stops waiting when its own context
// is done. A panic in the loader is returned to the waiting callers as an
// error.
type CachedPolicyProvider struct {
	load    PolicyProviderFunc
	ttl     time.Duration
	timeout time.Duration
	grace   time.Duration
	now     func() time.Time

	mu       sync.Mutex
	policy   *Policy
	loadedAt time.Time
	gen      uint64      // incremented by Invalidate
	inflight *policyLoad // the load in progress, if any
	next     *policyLoad // a load waiting for inflight to finish, if any
}

// policyLoad is a load shared by every caller waiting for it. p and err are
// set before done is closed.
type policyLoad struct {
	ctx  context.Context
	gen  uint64 // the generation the load started at
	done chan struct{}
	p    *Policy
	err  error
}

// DefaultLoadTimeout is how long a [CachedPolicyProvider] waits for its
// loader unless [WithLoadTimeout] says otherwise.
const DefaultLoadTimeout = 30 * time.Second

// CacheOption configures a [CachedPolicyProvider].
type CacheOption func(*CachedPolicyProvider)

// WithLoadTimeout bounds each load: the loader's context is cancelled after
// d, and the load fails with [context.DeadlineExceeded] even if the loader
// ignores its context, so a hung database cannot block the cache. Zero or
// less disables the timeout. The default is [DefaultLoadTimeout].
func WithLoadTimeout(d time.Duration) CacheOption {
	return func(c *CachedPolicyProvider) { c.timeout = d }
}

// WithStaleGrace lets the provider keep serving the last loaded policy for
// up to d after its TTL expires. During that time callers get the old policy
// at once while a reload runs in the background, and a failed reload leaves
// the old policy in use, so a brief database outage does not fail every
// check. Once the grace period is over, callers wait for a load as usual.
// [CachedPolicyProvider.Invalidate] discards the policy immediately, grace
// or not. The default is zero: an expired policy is never used.
func WithStaleGrace(d time.Duration) CacheOption {
	return func(c *CachedPolicyProvider) { c.grace = d }
}

// NewCachedPolicyProvider returns a provider that calls load at most once
// per ttl. A failed load, or one that returns a nil policy, is not cached:
// its error is returned to the callers sharing it and the next call retries,
// so a check never succeeds against a policy that could not be loaded
// (unless [WithStaleGrace] allows the previous one). A ttl of zero or less
// disables caching, and load is then called on every use, concurrently, with
// the caller's context.
func NewCachedPolicyProvider(load func(ctx context.Context) (*Policy, error), ttl time.Duration, opts ...CacheOption) *CachedPolicyProvider {
	c := &CachedPolicyProvider{load: load, ttl: ttl, timeout: DefaultLoadTimeout, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Policy implements [PolicyProvider].
func (c *CachedPolicyProvider) Policy(ctx context.Context) (*Policy, error) {
	if c.ttl <= 0 {
		return c.loadPolicy(ctx)
	}
	c.mu.Lock()
	if c.policy != nil {
		age := c.now().Sub(c.loadedAt)
		if age < c.ttl {
			p := c.policy
			c.mu.Unlock()
			return p, nil
		}
		if age < c.ttl+c.grace {
			// Serve the stale policy and refresh it in the background.
			if c.inflight == nil {
				c.start(c.newLoad(ctx))
			}
			p := c.policy
			c.mu.Unlock()
			return p, nil
		}
	}
	var l *policyLoad
	switch {
	case c.inflight == nil:
		l = c.newLoad(ctx)
		c.start(l)
	case c.inflight.gen == c.gen:
		l = c.inflight
	default:
		// The running load predates an Invalidate, so its result may be
		// out of date: wait for a fresh one queued behind it.
		if c.next == nil {
			c.next = c.newLoad(ctx)
		}
		l = c.next
	}
	c.mu.Unlock()

	select {
	case <-l.done:
		return l.p, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *CachedPolicyProvider) newLoad(ctx context.Context) *policyLoad {
	return &policyLoad{ctx: context.WithoutCancel(ctx), done: make(chan struct{})}
}

// start runs l in the background. c.mu must be held.
func (c *CachedPolicyProvider) start(l *policyLoad) {
	l.gen = c.gen
	c.inflight = l
	go c.run(l)
}

// run performs the shared load l, then starts the queued load, if any.
func (c *CachedPolicyProvider) run(l *policyLoad) {
	p, err := c.loadPolicy(l.ctx)
	c.mu.Lock()
	// A policy loaded across an Invalidate may predate the change that
	// prompted it, so it is handed to its waiters but not cached.
	if err == nil && c.gen == l.gen {
		c.policy, c.loadedAt = p, c.now()
	}
	c.inflight = nil
	if c.next != nil {
		c.start(c.next)
		c.next = nil
	}
	c.mu.Unlock()
	l.p, l.err = p, err
	close(l.done)
}

// loadPolicy calls the loader, applying the load timeout and turning a nil
// policy or a panic into an error.
func (c *CachedPolicyProvider) loadPolicy(ctx context.Context) (*Policy, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	if ctx.Done() == nil {
		return c.safeLoad(ctx)
	}
	// Run the loader separately so that one ignoring its context cannot
	// hold up the caller past the deadline.
	type result struct {
		p   *Policy
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := c.safeLoad(ctx)
		ch <- result{p, err}
	}()
	select {
	case r := <-ch:
		return r.p, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// safeLoad calls the loader, turning a panic into an error: the load may
// run in its own goroutine, where a panic would otherwise crash the program.
func (c *CachedPolicyProvider) safeLoad(ctx context.Context) (p *Policy, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, fmt.Errorf("rbac: policy loader panicked: %v\n%s", r, debug.Stack())
		}
	}()
	p, err = c.load(ctx)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNilPolicy
	}
	return p, nil
}

// Invalidate discards the cached policy, so the next call reloads it. Call
// it after changing the stored policy. Callers already waiting on a load in
// progress still receive its result, but it is not cached; later callers
// wait for a new load that starts once it finishes.
func (c *CachedPolicyProvider) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = nil
	c.gen++
}
