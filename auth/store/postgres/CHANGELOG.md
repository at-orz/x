## Unreleased

- `auth/store/postgres`: an `auth.Store` and `auth.Claimer` in PostgreSQL through a `pgxpool.Pool`,
  with compare-and-swap on a version column and every expiry on the database's clock; `Schema` and
  `CreateTables` for its tables, `Sweep` for expired rows, `List` and `Remove` for host commands, and
  `mint.Tickets` redeemed by a single delete.
