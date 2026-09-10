# Module: signing (Signer / TrustStore)

**Mode:** both
**Core dependency:** `Signer`, `TrustStore` interfaces
**Status:** planned (item 2 — RESEARCH-GRADE, design doc before code)

## Purpose
The trust spine. Everything provisioned to a device — plugins, recipes, firmware
images, ISOs — is signed by a `Signer` and verified by the device against a
pinned `TrustStore` anchor, not the channel. A wrong abstraction here poisons
every dependent module.

## Signer interface (server-side)
`Sign(digest) -> signature ; PublicKey() -> key ; KeyID() -> id`
Backends, easy→high-assurance:
- `file` — local Ed25519, zero-dependency, generates a key on first run, **the
  default**, clearly labelled low-assurance.
- `pkcs11` — any HSM / YubiHSM.
- `openbao` / `vault-transit` — key never leaves the vault.
- `yubikey-piv` — a YubiKey as signer.
- `kms` — cloud KMS.
Config picks one; the rest of the system sees only `Signer`. Secure by *default*,
high-assurance by *configuration*.

## TrustStore interface (device-side)
How a device decides which signatures to trust: `file` (pinned pubkey, default),
`pairing` (delivered at enrolment), `tofu`. The provisioning module's pairing
flow is one implementation.

## The load-bearing property
The signing key is **not in the server**. A compromised management server can
*request* signatures (within its policy) but cannot forge artifacts offline, and
devices verify against the pinned anchor — so a compromised server or MITM'd
channel cannot push unsigned code. This is what makes "the server sees the fleet"
survivable (threat model).

## Attestation
After install, the device reports a hash of what's actually on disk; the server
compares against the manifest and flags drift (read-back attestation).

## Tests
- each backend signs and the device verifies
- a wrong-signed artifact is refused at the device
- a compromised-server simulation cannot produce a valid signature offline
- read-back mismatch is detected
