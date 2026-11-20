// Package auth is the session core of a web login: a signed cookie naming a server-side session
// record, the middleware that admits a request on it, and the policy that keeps a session alive by
// going back, now and then, to whoever vouched for it.
//
// How a person signs in is up to a [Method], each registered with a [Manager] under a unique name.
// Package auth/oidc signs in through one OpenID Connect provider (register one per provider), and
// package auth/mint redeems a one-time ticket issued on the host. Every method issues the same kind of
// session — the same cookie, the same record, the same [Manager.Require] and [Manager.Optional] — so
// the rest of a host never asks how a session began.
//
// Records live in a [Store]: auth/store/memory keeps them in one process, auth/store/etcd and
// auth/store/postgres (each a module of its own) share them between instances, and auth/store/storetest
// is the contract any other implementation runs.
//
// The boundary is deliberate. A session belongs to an [Identity], a subject as one provider names it;
// linking several identities to one user of the host is the host's job, and [Session.Values] is where
// it may keep the result. A page offering several ways to sign in is the host's to render as well;
// each method provides the URL its login starts at.
//
// A complete host is in examples/auth of this module's repository: an app signing people in through
// an OpenID Connect provider and automated clients through tickets, with its sessions in etcd shared
// by two instances behind TLS. It uses only the public API, and its end-to-end tests run it against a
// real provider and a real browser.
package auth
