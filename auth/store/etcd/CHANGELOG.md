## Unreleased

- `auth/store/etcd`: an `auth.Store` and `auth.Claimer` in etcd, with a record per session on a lease
  of its own, a feed for `FollowSessions`, `List` and `Remove` for host commands, and `mint.Tickets`
  redeemed by a single delete.
