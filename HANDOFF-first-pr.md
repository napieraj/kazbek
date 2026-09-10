# Handoff — first PR: fork, rebrand, device-auth swap (roadmap item 0)

Read `AGENTS.md` and `docs/ARCHITECTURE.md` first. Standing rules apply.

## Precondition
The kazbek repo is a fork of `gl-inet/glkvm-cloud`. Upstream remote kept as
`glinet` for future merges.

## Task A — rebrand (mechanical, one commit)
Module path, binary name, configs, log tags: `glkvm-cloud` → `kazbek`. Do not
touch behaviour. Full test suite green after (inherited tests should pass
unchanged — a rename that breaks a test means you changed more than the name).

## Task B — device-auth swap (the real change)
Replace shared-token device auth with pinned mutual TLS. Re-derive every line
number against the tree first; the numbers below are from the reference read and
WILL have moved.

1. **`ListenDevices`** (was ~`internal/server/device.go:171`) — the code already
   builds a `tls.Config` and `tls.NewListener` when a cert is set. Extend that
   config: `ClientAuth: tls.RequireAndVerifyClientCert`, `ClientCAs:` a pool of
   the pinned device CA (or the set of pinned device certs). No client cert / bad
   cert → the TLS handshake fails before any app code runs. That is the point.

2. **`handleDeviceConnection`** (was ~`:200`) — after accept, the conn is a
   `*tls.Conn`. Read identity from `conn.ConnectionState().PeerCertificates[0]`.
   This is the device's cryptographic identity — channel-bound, non-relayable.

3. **`ParseRegister` / `Register`** (was ~`:416` / `:462`) — the register message
   still arrives and still carries id/MAC/group/heartbeat: KEEP it as metadata.
   But the auth check `if cfg.Token != "" && dev.token != cfg.Token → reject`
   becomes: does the presented client cert match an enrolled device (by cert
   fingerprint / subject / pinned mapping). The token stops being an
   authenticator. Keep the empty-MAC check, the DevHookUrl webhook, the
   AddDevice conflict check, `registered.Store(true)`, and the online/offline +
   dedup logic — all unchanged.

4. **Everything above the seam** (`domain/`, `http/`, OIDC/LDAP, RBAC, groups,
   audit, notifications, UI) — DO NOT TOUCH. The swap is confined to the
   device-connection core.

## Tests (per silent-failure mode — mutation-check each)
- a device presenting a valid pinned client cert registers and comes online
- **no client cert** → handshake refused (mutation: remove RequireAndVerifyClientCert
  → an unauthenticated device connects → test must go red)
- **wrong/unpinned cert** → refused
- **spoofed register message** (valid cert for device A, register claims device
  B's id/MAC) → identity is the CERT, so it's device A regardless of the claim;
  assert the claim cannot override the cert
- the old shared-token path is GONE (mutation: a device with the right token but
  no cert must NOT connect)
- everything above the seam still green (inherited tests unchanged)

## Not in this PR
Cert issuance / pairing is the provisioning module (roadmap item 3). For this PR,
enrol test devices with manually-issued certs against a test CA. The pairing
ceremony that issues them in production is later and separate.

## Report
Post-swap: the diff confined to the device-connection files, the inherited tests
still green, the mutation results for each auth test, and the re-derived line
numbers you actually edited. Stop after this PR — the capability model (item 1)
is the next design step and stops for review.
