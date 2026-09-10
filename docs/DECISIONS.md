# Decisions (ADR log)

Append-only. Each entry: what was decided, why, and what would reopen it.

## D-001 — Fork glkvm-cloud, not clean-build
The management plane (domain model, OIDC/LDAP, RBAC, groups, audit, UI) is weeks
of work and has nothing to do with the connection model. The device-connection
core is ~100 lines behind a clean `net.Conn` seam, framing is transport-agnostic,
TLS is already wired. Forking inherits the plane; the trust swap is contained.
*Reopens if:* the message protocol turns out to bake in rttys assumptions the
pinned-mTLS path can't satisfy (checked: it doesn't — 3-byte-header framing over
net.Conn).

## D-002 — Pinned mutual TLS replaces the shared device token
Stock auth is `dev.token != cfg.Token`. A shared fleet bearer token is
replayable and relayable (the same class as the firmware-side findings).
Identity moves to the client certificate presented in the TLS handshake —
channel-bound, per-device, non-relayable. The register message becomes metadata.
*Reopens if:* never for the token; cert-management ergonomics might add a
pairing-assisted issuance path (that's provisioning, D-005, not a reversal).

## D-003 — Inward trust, runtime dial-in
Trust is established *inward* (device enrols against a controller it pins; server
pins the device cert). At runtime the device still *dials in* (NAT requires it),
but over pinned mutual TLS. Dial direction was never the anti-pattern — unpinned
trust of a third party was. This keeps NAT traversal while fixing trust.
*Reopens if:* a genuinely serverless local mode is wanted (still fits — the
device can pin an operator's cert directly).

## D-004 — Core + modules; features are opt-in
A small core (connection, identity, module loader) plus modules that register
against it. Each module declares a mode (local-only / cloud-managed / both).
Not a monolith. *Reopens if:* never — this is the product's shape.

## D-005 — Modular signing backends, secure-by-default
A `Signer` interface with `file` (default, zero-dependency, low-assurance),
`pkcs11`/HSM, `openbao`, `yubikey-piv`, `kms`. Secure by *default* (file backend
generates a key and works), high assurance by *configuration* (swap the backend).
*Reopens if:* a backend proves unsafe as a default (then relabel, don't remove).

## D-006 — External identity never the only auth path
RADIUS/OIDC/LDAP authenticate when reachable; a local credential (WebAuthn or a
vault break-glass password) logs in when they aren't. An OOB device must not die
with its IdP. *Reopens if:* never — this is a hard rule for the domain.

## D-007 — Recipes are declarative-only
Pushable action recipes express intent from a fixed, reviewed action vocabulary;
they cannot express arbitrary commands. An imperative/shell recipe is remote code
execution with YAML syntax and will not be built. Recipes are signed,
capability-gated, and target-bound. *Reopens if:* never for the shell escape;
the vocabulary grows by reviewed additions.

## D-008 — Gut, not mask, for owned code
Unused features are absent, not disabled — presence is a security property.
Mask only closed upstream services a removal orphans. *Reopens if:* never.

## D-009 — Per-device permissions include a port scope (Comet X)
The capability model's scope is (subject, capability, scope) where scope may be a
device, a device group, or a **port** on a multi-channel device. Enforcement is
at the tunnel/stream layer, not the UI. *Reopens if:* never — the Comet X's four
channels require it.

## D-010 — Port-scoped grants are tier-conditional, never advisory (amends D-009)
D-009 made `port` a first-class scope. Measurement of the rm4pe
(`docs/modules/permissions-capabilities.md` §4.1) found the hardware does not
provide the partition D-009 assumed: four "ports" are a time slice behind one
mux, there is no per-port endpoint to filter, and the mux moves on a keystroke
via kvmd-vnc's `MagicHandler` with no API call to gate. A grant that displays
and does not hold is a hidden button with extra steps — the failure this whole
module exists to prevent.

`Scope` keeps its port. The condition moves to **issuance**: the server refuses
to issue a port-scoped grant unless the device is `trusted` tier on firmware
that gates `/switch/set_active*` behind `port.switch` and has the chord
bindings gutted. Fail closed on the grant, not advisory on the enforcement. A
Comet X on `legacy` tier is one device with four ports, not four scopes.
*Reopens if:* the hardware gains genuinely independent capture paths — then
port becomes a real partition and the issuance condition can relax.

## D-011 — One session-construction function; the decision is never the path
There is no layer on the device that every path to an operation crosses. That
is an argument for building one on the kazbek side, not for placing independent
checks at each path — three places to remember is how the `/streamer` bypass
happened.

Every device-bound path constructs its session through a single function that
resolves the subject, resolves capabilities **once** at establishment, and
returns a connection with only the permitted channels demuxed. Absent
capabilities are absent wiring, not disabled features (D-008 applied to a
session). There is no re-check API: a session cannot acquire a capability it
was not constructed with. **A route that can obtain a device connection without
going through that function is a bypass**, and adding one is a trust-boundary
change that stops for review.

Corollary, from the chord finding: *enforcement points that live at routes
cannot see operations that do not traverse routes.* A capability whose
operation has a non-route path needs an enforcement point that is not a route.
*Reopens if:* never for the single-path rule.

## D-012 — `/web/:devid/:proto/:addr/*path` is removed, and replaced by two things
The route takes a caller-supplied IPv4 address with no allowlist and no
RFC1918/loopback exclusion (`httpProxyVaildAddr`), and the connection is made
by the device from the device's network position. Its reachable set is the
managed segment, whose isolation THREAT-MODEL.md makes load-bearing. It has no
capability that can honestly describe it, so per D-008 it goes.

It is also the path the inherited product uses to reach the KVM control UI for
non-`rtty-go` devices, so it is replaced, not merely deleted, by: (1) a
device-scoped channel taking a **named service** rather than an address,
capability-gated; and (2) nothing for the arbitrary-host case. Migration gets
(1) plus a purpose-built, server-initiated, enumerable channel where
adopt-and-harden needs more.

These land together — gut-now-replace-later breaks the console.
*Reopens if:* a genuine need for arbitrary-host proxying appears; it returns as
its own capability with its own threat-model entry, never as a parameter.
