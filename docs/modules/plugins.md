# Module: plugins (foundation — transport, protocol, invariants)

**Mode:** both (local drop-in and cloud-managed push, one verify path)
**Core dependency:** device connection (pinned-mTLS tunnel), `Verifier` hook
**Status:** planned — foundation is signing-INDEPENDENT and buildable now
**Spans:** kazbek (catalog/push/sidecar) + glkvm-debloat (device load)

## The correction that scopes this
Signing is NOT a prerequisite. The transport, protocol, manifest, sidecar,
deployment mechanics, and invariants are identical regardless of which `Signer`
backend is eventually chosen — the crypto is a swappable hook, not a gate. Build
the foundation now against a **`Verifier` interface** (stubbed `noop` /
`hash-only`); the real signing backend and trust-anchor distribution fill the
hook later without touching the plumbing. Same discipline as the WebAuthn
token-plumbing: put the seam in from line one, fill it later.

The ONLY research-grade part deferred: key custody + trust-anchor distribution +
the trust-tier model. Everything else is foundational and starts now.

## The one invariant that defines the whole thing
**The device verifies identically whether a plugin arrived by local drop-in or
by fleet push.** Trust is the verification (the `Verifier` result), never the
delivery channel. Local and pushed are two *sources* feeding one
*verify-and-load* path — not two mechanisms. Get this right and "local +
centralized" is free.

## Wire protocol (over the existing pinned-mTLS tunnel)
Framed like the device connection's existing typed messages:
- `plugin.offer`   — server -> device: manifest, no payload. "This is available."
- `plugin.fetch`   — device -> server: request payload for a manifest by hash.
- `plugin.payload` — server -> device: the bundle (chunked; large).
- `plugin.install_result` — device -> server: verify+install outcome.
- `plugin.readback` — device -> server: hash of what's actually on disk
  post-install, for the server to compare against the manifest.
Channel encryption is the pinned-mTLS tunnel that already exists; plugins ride
it, nothing new.

## Manifest schema (signature is a stubbed FIELD, not a blocker)
```yaml
name: <string>
type: atx | msd | hid | ugpio | auth        # device-plugin types (existing dirs)
runtime: device | management                 # blast-radius tier
model_compat: ">=rm1pe" | "rm4pe" | ...      # per-model
firmware_compat: ">=<version>"
entry: plugins/<type>/<file>
payload:
  sha256: <hash>                             # ALWAYS present, ALWAYS checked
  size: <bytes>
signature:                                   # STUBBED FIELD — filled by signing
  alg: <deferred>
  value: <deferred>
  key_id: <deferred>
capabilities: [ ... ]                        # management plugins only (see permissions)
```
The `sha256` is checked from day one (hash-only integrity). The `signature`
block is defined but unpopulated until signing lands — its presence in the schema
is what lets signing drop in without a schema change.

## Verifier interface (the swap seam)
```
Verifier:
  Verify(manifest, payload) -> ok | reason
```
- `noop`      — accepts anything (dev only; NEVER a default in any real config).
- `hash-only` — verifies payload.sha256 matches. Buildable-now floor: integrity
  without authenticity.
- `signed`    — LATER: verifies signature against the pinned trust anchor. Drops
  into the same hook; the invariants below do not change.
The loader/sidecar depends only on `Verifier`. Swapping the impl is config.

## Deployment mechanics
Device-side (glkvm-debloat):
- Read-only rootfs: the rw/ro remount dance is defined HERE and shapes
  everything — a defined writable plugin location + remount-rw -> place ->
  remount-ro, or an overlay. Settle this first; it constrains the rest.
- Unpack -> Verify (the hook) -> place into plugins/<type>/ (a loader-OWNED
  location, never an arbitrary manifest path) -> load via the existing kvmd
  plugin mechanism -> emit readback.
- Rollback: a failed load reverts atomically. A half-placed plugin never runs.
Server-side (kazbek):
- Catalog (the store); push manifest+payload over the tunnel; handle
  install_result and readback; flag drift.
- The sidecar: holds the verify hook + orchestrates place/load coordination.

## Invariants (testable NOW against the stub Verifier)
Hold regardless of trust model — write them as a shared test contract:
1. A plugin loads ONLY from a loader-owned location — never an arbitrary path
   from the manifest.
2. Push is idempotent — the same manifest pushed twice is a no-op.
3. A failed Verify REFUSES install — prove with an always-fail verifier: the
   refuse path must fire. (This test becomes real signing-verification later,
   unchanged.)
4. Read-back is mandatory — install is not "done" until the on-disk hash is
   reported and matches; mismatch is flagged, not ignored.
5. Identical verify path for local vs pushed — same Verify call, same place/load,
   same readback; a test drives both sources through one path and asserts they're
   indistinguishable downstream of Verify.
6. management-runtime plugins are NOT loaded by a device; device plugins are NOT
   loaded in-process by the server (tier separation / blast-radius split).

## Deferred to the signing module (the only research part)
- Signer backends (file default -> pkcs11/openbao/kms).
- Trust-anchor distribution: how a device gets its pinned verification key
  (pairing-delivered, per the provisioning module).
- Trust tiers: device-plugin (per-console blast radius, community-signable with
  per-author key pinning) vs management-plugin (fleet blast radius,
  out-of-process, curated/self-signed only, never community-TOFU).
- GitHub-as-registry with signatures-over-releases (the trust spine HACS lacks).
When these land, they fill the signature field and swap hash-only -> signed.
Invariants 1-6 are unchanged; only Verify's implementation strengthens.

## Tests (foundation, now)
Per invariant, against the stub verifier. Plus: rw/ro remount is atomic (crash
mid-place leaves no partial plugin); the wire protocol round-trips each message
type; chunked payload reassembly; the readback-mismatch path flags.
Mutation-check invariant 3 (remove refuse-on-fail -> an unverified plugin
installs -> test goes red) — the load-bearing one; it must have teeth before
noop is ever in a tree.
