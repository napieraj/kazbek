# Handoff — plugin foundation (transport, protocol, invariants)

**Scope:** BOTH repos this cycle — `kazbek` (server) and `glkvm-debloat`
(firmware). Add both to this session. They meet at ONE seam: the plugin wire
protocol over the pinned-mTLS tunnel. Same-named branches in the two repos are
independent — push each half to its own origin, nothing spans both.

Read first: `kazbek/docs/modules/plugins.md` (the spec), `kazbek/AGENTS.md`
(standing rules). Standing rules apply in both repos: re-derive line numbers,
full staged testenv only (partial = false green), one commit per logical change,
mutation-check silent-if-missed checks, gut-not-mask, stop-at-design-steps.

## The scoping correction (why this is buildable now)
Signing is NOT a prerequisite. Build the whole foundation against a **`Verifier`
interface** with `noop` and `hash-only` implementations. The real signing backend
and trust-anchor distribution fill the hook LATER without touching this plumbing.
Do NOT build any signing/key-custody logic in this cycle — it's a separate,
research-grade module. Your job is the transport, protocol, manifest, sidecar,
deployment, and the invariants, all signing-independent.

## Deliverables

### Shared contract (define once, both repos consume)
- The wire protocol: `plugin.offer / fetch / payload / install_result /
  readback`, framed like the device connection's existing typed messages.
- The manifest schema (signature is a STUBBED field — define it, leave it
  unpopulated; the `sha256` IS checked from day one).
- The `Verifier` interface + `noop` + `hash-only` impls.
- The invariants as a shared test contract (see spec, 1-6).

### kazbek (server)
- Catalog (the store), push manifest+payload over the existing pinned-mTLS
  tunnel, handle `install_result` + `readback`, flag drift.
- The sidecar: the verify hook + server-side place/load orchestration.

### glkvm-debloat (device)
- The rw/ro remount dance FIRST (read-only rootfs — settle the writable plugin
  location / overlay; it constrains everything).
- Unpack -> Verify (hook) -> place into a LOADER-OWNED plugins/<type>/ location
  (never an arbitrary manifest path) -> load via the existing kvmd plugin
  mechanism -> emit readback. Atomic rollback on failed load.

## Parallelization
Parallelize the independent inputs, serialize the shared seam:
- Sub-agent A: the shared protocol + manifest schema + Verifier interface — a
  design artifact both repos import. Net-new, no contention. MUST land first
  (it's the contract).
- Then, concurrently once the contract exists:
  - kazbek half (catalog/push/sidecar) — one owner.
  - glkvm-debloat half (remount/place/load/readback) — one owner, different repo,
    no shared files with the kazbek half.
- They only interoperate at the wire protocol, which A fixed — so they can build
  against it in parallel and integration is a protocol conformance test, not a
  merge.

## The load-bearing test (do not skip)
Invariant 3, mutation-checked: an always-fail `Verifier` -> install is REFUSED.
Remove the refuse-on-fail path -> an unverified plugin installs -> the test must
go red. This test is written now against the stub and becomes the real
signature-verification guard later, UNCHANGED. It must have teeth before `noop`
exists anywhere in a tree, because `noop` accepting everything is exactly the
thing this test proves is contained.

## Stop-and-report
- After the shared contract (A) lands — it's the design step; review before both
  halves build on it.
- After each repo half is green.
- Any point the device's kvmd plugin-load mechanism needs a change to accept a
  dynamically-placed plugin (that's a firmware design step, not mechanical).

## Explicitly NOT in this cycle
Signing, key custody, trust-anchor distribution, trust tiers, GitHub registry.
Those are the signing module (research-grade, later). If you find yourself
writing crypto beyond "hash a blob, compare it," you've left scope — stop.
