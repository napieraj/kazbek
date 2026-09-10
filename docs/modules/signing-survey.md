# Signing — survey and prior art

Companion to [`signing.md`](./signing.md), which is the module spec. This
file is not a second spec: it holds the survey the design starts from, so
the work is not re-derived later. Both were written independently, on
different branches, at the same path; they are kept apart because one
declares an interface and the other records what was read.

**Status:** not started, and deliberately not started in the plugin-foundation
cycle. This file exists to hold the survey the design will start from, so that
work is not re-derived later.

## Why it is deferred

The plugin foundation is signing-independent by construction. Transport,
manifest schema, placement, rollback and readback are identical whichever
crypto eventually lands, so the crypto is a hook — the `Verifier` seam — filled
later without touching the plumbing. See `docs/modules/plugins.md`.

What is genuinely research-grade is not the algorithm. It is key custody,
trust-anchor distribution, and the trust-tier model.

## What already exists for this module to fill

- `Verifier` — `Verify(manifest, payload) -> ok | reason`, with `noop` and
  `hash-only` implementations. A `signed` implementation drops into the same
  hook.
- `signature` in the manifest — `model` (a required enum currently accepting
  only `hash-only`), `entries` (a required list, currently required empty),
  `threshold` and `expires`. Populating these is this module's job and needs no
  schema migration.
- `revision` — monotonic anti-rollback, already enforced at offer admission.
  Rollback protection does not wait on signing and has not.

## Survey to start from

`docs/research/plugin-architecture.md` §3b–§3e, plus §7. **Informing, not
normative** — see that document's header, including the two claims not to cite
without independent verification.

- **§3b, single pinned key.** The OPA bundle model (detached `signatures.json`
  as a JWT over a `files` array) is the closest ready-made artifact format.
  Algorithm options and their trade-offs are surveyed there.
- **§3c, threshold / K-of-N.** Surveyed as proportionate to the management
  tier's fleet blast radius. `signature.threshold` exists for it.
- **§3d, keyless / transparency log.** Surveyed for community plugins; note the
  verify-time network dependency.
- **§3e, TUF.** The recommendation is to adopt the threat model and disciplines
  incrementally rather than the full four-role stack.
- **§7, fleet prior art.** Persist-last-good for intermittently connected
  devices, and digest-pinned read-back attestation, which the existing readback
  already implements in its hash-only form.

## Open questions this module must answer

1. Key custody: file, PIV token, HSM/PKCS#11, or a transit service.
2. Trust-anchor distribution: how a device obtains its pinned verification key.
   Expected to be pairing-delivered, per the provisioning module.
3. The trust-tier model: device-plugin (per-console blast radius) versus
   management-plugin (fleet blast radius), and whether community authorship is
   in scope for either.
4. Revocation, and its relationship to `expires`.

None of these are answerable without a threat model, which is where this module
starts.
