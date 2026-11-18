## Unreleased

- `auth`: the session core — signed session cookies over server-side records in a `Store`, the
  `Require` middleware, revalidation through a registered `Method` with a grace window, deadline
  sessions, `Authorize` policies (`AllowSubjects`, `AnyOf`), and host values on a session (`Link`,
  `SetValue`).
- `auth/oidc`: sign-in through an OpenID Connect provider (authorization code flow with PKCE), one
  registered `Provider` per provider, sessions revalidated by exchanging the refresh token. The
  provider refuses a non-https issuer or endpoint itself unless `Options.InsecureAllowHTTP` is set,
  and `Options.HTTPClient` supplies the client it uses.
- `auth/mint`: sign-in by redeeming a one-time ticket issued on the host, into a session with a fixed
  deadline.
- `auth/store/memory`: an in-process `Store` with per-record expiry and a feed for `FollowSessions`,
  and in-process `mint.Tickets`.
- `auth/store/storetest`: the `Store` and `mint.Tickets` contracts as test suites any implementation
  runs.
