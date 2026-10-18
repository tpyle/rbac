# Connecting Authentication

rbac decides what a user may do; something else decides who they are. rbac doesn't issue or verify tokens and doesn't depend on any authentication library. It meets the authentication layer at two points:

1. **Issuing tokens.** `Enforcer.ClaimsProvider` computes the claims to embed (see [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md)). The token issuer calls it on every login and refresh.
2. **Checking tokens.** After a token is verified, its claims reach rbac as an `rbac.Claims`, either in the request context or passed to a check directly.

## With github.com/tpyle/auth/v2

The `github.com/tpyle/rbac/authrbac` module does the wiring. It is a separate module, so services that use rbac without auth don't pull auth in.

```bash
go get github.com/tpyle/rbac/authrbac
```

```go
enforcer, err := rbac.New(
	authrbac.Option(), // read auth's claims, reject claim names auth reserves
	rbac.WithRoleStore(roles),
	rbac.WithPolicy(policy),
)

a, err := auth.New(ctx,
	auth.WithUserStore(users),
	auth.WithClaimsProvider(enforcer.ClaimsProvider(nil)),
)

handler := a.RequireAuthHandler(mux) // rbac middleware inside mux
```

`authrbac.Option()` sets two things:

- `rbac.WithClaimsSource(authrbac.ClaimsFromContext)`: checks and middleware read the claims that `RequireAuthHandler`, `AuthHandler` or `auth.ContextWithClaims` stored.
- `rbac.WithReservedClaims(auth.IsReservedClaim)`: `rbac.New` rejects a `RolesClaim` or `PermissionsClaim` that auth manages itself, such as `typ`.

For checks on claims you verified yourself, convert them:

```go
claims, err := a.VerifyAccessToken(ctx, token)
ok, err := enforcer.ClaimsCanAll(ctx, authrbac.Claims(claims), "posts:read")
```

Runnable examples using auth are in [`authrbac/examples`](../authrbac/examples).

## With any other library

### Issuing

`ClaimsProvider` returns a plain `func(ctx context.Context, subject string) (map[string]any, error)`. Call it when you build an access token and merge the map into the token's claims:

```go
provide := enforcer.ClaimsProvider(nil)

extra, err := provide(ctx, user.ID)
if err != nil { /* don't issue the token */ }
for k, v := range extra {
	jwtClaims[k] = v
}
```

The function type is unnamed, so it can be passed directly wherever a library expects a named function type of the same shape.

### Checking

Your authentication middleware verifies the token, then stores its subject and claims for rbac:

```go
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := verify(r) // your library
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := rbac.ContextWithClaims(r.Context(), &rbac.Claims{
			Subject: tok.Subject,
			Values:  tok.Claims, // map[string]any decoded from the payload
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

If your library already puts its claims in the context, give rbac a `ClaimsSource` that reads them instead:

```go
rbac.WithClaimsSource(func(ctx context.Context) (*rbac.Claims, bool) {
	tok, ok := mylib.FromContext(ctx)
	if !ok {
		return nil, false
	}
	return &rbac.Claims{Subject: tok.Subject, Values: tok.Claims}, true
})
```

`Values` only needs the roles and permissions claims. Each must be a `[]string` or, as decoded from JSON, a `[]any` of strings. A claim that is missing means "look it up"; one that is present but malformed fails with `ErrMalformedClaim` (see [Token Claims and Trade-offs](Token-Claims-and-Tradeoffs.md)).

### Reserved claim names

`Config.Validate` rejects the claim names registered by RFC 7519 (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`). If your issuer manages other names, pass them to `rbac.WithReservedClaims` so a clash shows up when the enforcer is built:

```go
rbac.WithReservedClaims(func(name string) bool { return name == "scope" || name == "azp" })
```

[`examples/middleware`](../examples/middleware) shows a complete service with a stand-in authenticator.
