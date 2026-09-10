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
