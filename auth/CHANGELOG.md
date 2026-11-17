## Unreleased

- `auth`: the session core — signed session cookies over server-side records in a `Store`, the
  `Require` middleware, revalidation through a registered `Method` with a grace window, deadline
  sessions, `Authorize` policies (`AllowSubjects`, `AnyOf`), and host values on a session (`Link`,
  `SetValue`).
- `auth/store/memory`: an in-process `Store` with per-record expiry and a feed for `FollowSessions`.
- `auth/store/storetest`: the `Store` contract as a test suite any implementation runs.
