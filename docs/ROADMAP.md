# Roadmap

Sequenced by dependency. Each item is a design → threat-model → build →
mutation-check cycle, not a task. Items marked *research-grade* must have a
reviewed design doc before code.

```
0. Fork + rebrand + device-auth swap   ← first PR; contained, ~100 lines
1. Capability model (permissions)      ← the authorization spine, local-only
2. Signer / TrustStore  [research]     ← the trust spine; everything verifies here
3. Provisioning / pairing [research]   ← enrolment ceremony, cert issuance
4. External identity (RADIUS/OIDC/LDAP) ← plugs UNDER the capability model
5. Plugins (device, then management)   ← signed; mgmt plugins out-of-process
6. Recipes  [research]                 ← LAST; needs signing + capabilities + vocab
7. Screenwall (Comet X)                ← simultaneous multi-view, cloud-managed
```

## 0 — Fork, rebrand, device-auth swap (first PR)
Fork `glkvm-cloud`; rename module path/binary/configs to kazbek. Then the
contained swap (see ARCHITECTURE): `RequireAndVerifyClientCert` + pinned CA pool,
identity from `PeerCertificates`, cert-match replaces `cfg.Token`. Keep the
register message as metadata, and every layer above the seam. Tests: a device
with a valid pinned cert registers; wrong/absent cert refused; a spoofed
register message without the matching cert refused.

## 1 — Capability model (permissions), local-only
The authorization spine — build before external identity, which plugs *under*
it. Grant = (subject, capability, scope). Capabilities map 1:1 to enforceable
device operations: `view`, `screenshot`, `screen.control`, `hid.input`,
`atx.soft/hard/reset`, `msd.mount`, `serial`, plus management ones. Scope =
device | group | **port** (Comet X). Enforcement at the tunnel/stream layer, not
the UI (the `/streamer`-bypass finding is the warning). Constraints on
high-consequence caps: `requires_presence`, `time_window`, approval (four-eyes).
Check GL's `policy-engine` and KVM Fleet's (Apache-2.0) before writing one.

## 2 — Signer / TrustStore  [research-grade — design doc first]
`Signer` interface, backends: `file` (default), `pkcs11`, `openbao`,
`yubikey-piv`, `kms`. `TrustStore` for how a device decides what to trust
(`file`/pinned, `pairing`-delivered, `tofu`). Secure-by-default (file backend
works out of the box), high-assurance-by-config. Everything downstream (plugins,
recipes, firmware) verifies against this — a wrong abstraction here poisons all
of it. Write and review the interfaces + file default before dependent code.

## 3 — Provisioning / pairing  [research-grade]
No broadcast — manual bring-up: point at `.local`/IP, numeric-comparison pairing
(Bluetooth-SSP-style) on screen'd models, paste-key on screenless. Ends in
pinned mutual certs (device cert issued, server cert pinned). This is where the
inward-trust model lives; the runtime dial stays as-is. The device must never
carry a reusable secret — challenge-response and authorization-to-act only.

## 4 — External identity (RADIUS / OIDC / LDAP)
Inherited bones from glkvm-cloud (OIDC/LDAP present). RADIUS is a `plugins/auth/`
module like WebAuthn was. These **authenticate** (who is this); the capability
model (item 1) **authorizes** (may they do X). Never conflate. Always with local
break-glass (D-006).

## 5 — Plugins
Device plugins (blast radius: one console) — the kvmd typed-plugin dirs, signed,
installable locally or pushed. Management plugins (blast radius: the fleet) —
higher bar: out-of-process over RPC, capability-scoped, curated/self-signed only,
never community-TOFU. Manifest schema, GitHub-as-registry with signatures-over-
releases (the trust spine HACS lacks).

## 6 — Recipes  [research-grade — LAST]
Declarative-only, fixed action vocabulary (the vocabulary IS the security
boundary — an allowlist of reviewed capabilities). Signed, capability-gated,
target-bound (device+action+nonce, per the WebAuthn purpose-confusion lesson).
Dry-run + atomic-or-rollback (a half-applied boot/network recipe bricks access).
Depends on signing (2) and capabilities (1); do not build before them.

## 7 — Screenwall (Comet X)  [SPEC INVALID — rewrite before scheduling]
As written this item describes hardware that does not exist here. The rm4pe is
**one capture path and one USB gadget behind a mux**
(`docs/modules/permissions-capabilities.md` §4.1) — its four channels are a time
slice, so "simultaneous multi-view of the four channels" is not a feature that
was paywalled, it is a feature the hardware cannot provide.

Whatever replaces it is one of:
- **round-robin capture at divided framerate** — the mux walks, each port is
  sampled in turn, and every tile is stale by up to (N-1) × dwell; or
- **server-side compositing of sequential grabs** — same walk, assembled into
  one view server-side.

Both are buildable. Neither is what this item currently promises, and the
difference is user-visible (a "live" wall that is four stale stills is worse
than an honest one).

**This is not a deferral — the spec is wrong and must be rewritten first.**

### It also constrains item 1, now

A compositing or round-robin view is, **by construction, a session that walks
the mux across all four ports.** Under D-010 port scope is enforced as an
interlock — the session's grant is checked against the currently active channel
and the connection is torn down when the channel moves. A screenwall session
moves the channel continuously and deliberately.

So: is a screenwall session expressible under tier-conditional port scope? The
candidate answers each cost something:
- it requires a grant on **every** port it displays (honest, and makes a
  screenwall a privileged thing — probably right);
- it is a distinct capability that subsumes port scope (simpler, but it is a
  capability that means "ignore the interlock", which is the shape of every
  bad exception);
- the interlock distinguishes *the session moved the mux* from *the mux moved
  under the session* (most precise, most state).

**The interlock design must answer this before it is built, not discover it
afterwards.** Recorded in `docs/modules/permissions.md` under Port scope.

## Blocking open questions
- **Which devices are on the bench?** Per-model, pairing (screen), and per-port
  (Comet X) work needs the real Pro and Comet X — RM1PE code can't validate them.
- **Adopt or reinvent the policy engine** (item 1)? Measure GL's and KVM Fleet's
  first.
