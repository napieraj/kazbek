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

## D-013 — A device's claims about itself are metadata, never authorization inputs
D-002 took device identity from the client certificate instead of a shared
token. That was correct, but it was written as a **specific swap**, not as a
rule — which is why three instances of the same defect survived it:

- **client type** — read from the device's own info message and used to
  classify that device's sessions (fixed: recorded server-side once, not
  device-updatable).
- **the register message** — id, MAC, group, heartbeat, all device-supplied.
  D-002 already says these are "metadata to check against the cert"; this
  generalises *why*.
- **two-step approval** (`/auth/two_step_approve`, `auth_required=False` on the
  firmware) — a presence signal the device asserts about itself.

They are one defect: **a claim authored by the device, consumed by the server
as if it were a fact.** Pinned mTLS establishes *which* device is speaking. It
does not make what that device says about itself true.

**The rule.** Anything that decides
- what a subject may do,
- which server path handles a session, or
- whether presence was demonstrated

must resolve from **server-side state** or from **the certificate**. A
device-supplied value may be stored, displayed, logged as a claim, and checked
for divergence — never consulted to make one of those three decisions.

**The test for the next person:** *if the device lied about this field, would
the server do something different?* If yes, it is an authorization input and
this rule applies. If it only changes what is displayed or recorded, it is
metadata.

This pre-answers a question `requires_presence` would otherwise reach:
**presence a device can self-assert is not presence.** A ceremony built on the
firmware's two-step approval satisfies the letter of the constraint and none of
its purpose. *Reopens if:* never — this is the generalisation of D-002, and
D-002 does not reopen.

## D-014 — `internal/authz/` stays portable, and that is load-bearing
The capability model is built as a package with its own seam and **no
dependency on GL-original code beyond a defined interface**. It consumes
subjects, capabilities, scopes and targets as its own types and is handed them;
it does not reach into the inherited domain, store, or HTTP layers.

This is not tidiness. The licensing measurement (`docs/LICENSING.md`) found the
expensive inherited management plane is GL-original and BUSL-encumbered, while
the transport kazbek actually swaps is MIT. Keeping the authorization spine
portable means it **survives any of the three licence outcomes** — grant, wait,
or reopen D-001 — which is what takes the licence question off the critical
path and lets Phases 1-3 proceed while it is resolved.

Concretely: a dependency from `internal/authz/` into GL-original code is a
defect to be removed, not a convenience to be accepted, and the review for each
phase checks it. *Reopens if:* the licence question resolves in a way that
makes the inheritance permanent — and even then portability costs little enough
to keep.

## D-015 — D-001 is NOT reopened; the encumbered surface shrinks monotonically
The BUSL finding (`docs/LICENSING.md`) put D-001 back on the table: the fork
was justified by inheriting the management plane, and the management plane is
the encumbered part. Measured rather than argued, the answer is **do not
reopen**.

What GL-original code we still intend to run after roadmap items 1-5:
authorization is replaced by item 1; audit is being rebuilt; OIDC is ~524 lines
of thin wrapper over `go-oidc` and LDAP the same over `go-ldap`; `/web` is
gutted by D-012. **What survives is the Vue UI (~14k lines), the sqlite store
(~2k), and the CRUD/domain layer around groups, users and relations (~3.7k).**

A Vue UI, a sqlite store and some CRUD is not a rebuild that justifies
discarding the management plane. D-001's technical premise was never in doubt;
its economics survive the measurement too, just with a smaller margin than it
assumed.

**The direction is the load-bearing part: the encumbered surface shrinks
monotonically as the roadmap executes.** Every item that lands replaces
GL-original code with kazbek-original code; none adds dependency on it. That is
the opposite of the usual dependency trap, and it means time works for us.

> Consequently, **a future item that *adds* dependency on GL-original code is a
> reversal of this decision** and must be argued as one, not slipped in as
> convenience. That is the whole reason this is recorded here rather than only
> in a report.

Independent of this: a production-use grant is being requested from GL
(`docs/gl-request.md`), and D-014 keeps `internal/authz/` portable so the
authorization spine survives whatever the answer is. Neither blocks the other.
*Reopens if:* the surviving surface stops shrinking — i.e. if an item is
proposed that deepens the inheritance.
