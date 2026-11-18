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
- `auth/mint`: opening a sign-in link serves a page that submits itself (a button without
  JavaScript), and only that POST spends the ticket, so a link preview no longer burns it.
  Cross-origin POSTs are refused.
- `auth`: the package documentation points to `examples/auth` in the repository, a complete host
  app with end-to-end tests against a real provider and browser.
- `auth/mint`: `Issue` writes a ticket from `Options` alone, so a host command needs no
  `auth.Manager`.
- `auth`: `POST /auth/logout` sends a browser on with `303 See Other` to the on-site path in `ret`
  (form body or query string), or to `/`, so a plain HTML form can sign out. A request accepting JSON
  still gets `204`. A POST from another site is refused with `403 cross_origin_request`.
- `auth`: `Manager.Optional` serves a request with or without a session, so a public page can show
  who is signed in; it admits, revalidates and clears cookies as `Require` does.
