# Threat model

## The property kazbek must provide

An out-of-band management plane must be a **diode**: compromise of a managed host
must not yield control of the manager, and the manager must answer only to the
operator — not a vendor, not a network position, not a stolen token.

## Adversaries and what each yields

**On-path network attacker (management segment or between device and server).**
- Cannot impersonate a device: identity is the pinned client cert, not a token
  or header. A relayed handshake produces a different channel and fails.
- Cannot impersonate the server: the device pins the server cert.
- Cannot replay: TLS session binding; nothing reusable crosses the wire.
- Residual: denial of service (drop the connection) — availability, not
  escalation.

**Compromised device.**
- Yields that device's console (it already had it) and its own pinned cert.
- Does **not** yield the fleet: each device has its own cert; the server does
  not hand a compromised device others' credentials.
- Read-back attestation (provisioning module) surfaces on-disk drift.

**Compromised management server.**
- Serious — it sees the fleet. Mitigations: the signing key is not in the server
  (HSM/OpenBao via the `Signer` interface, D-005), so a compromised server
  cannot forge signed plugins/recipes/firmware; devices verify signatures
  against a pinned anchor, not the channel. Audit is append-only. The server can
  still command devices it's trusted to command — that is its job — so server
  custody and access control are the real defense here.

**Stolen device certificate / key.**
- Bounded to one device. Revocation via the pinned-CA / CRL; a suspected
  compromise means re-enrolling that device, not a fleet reset.

**Unreachable IdP (the OOB outage case).**
- External identity being down must not lock the operator out — the exact outage
  a KVM exists for. Local break-glass (WebAuthn against the pinned credential, or
  a vault password) always logs in. (D-006.)

## Non-goals / accepted limits

- kazbek does not defend a *managed host's own OS* — that's the host's problem; a
  KVM gives console access, and console access to a compromised host is expected.
- The firmware's closed upstream userland (`glkvm-debloat` caveat) is not
  audited by kazbek; **network isolation of the management segment is
  load-bearing**, not optional.
- A malicious operator with granted capabilities can do what those capabilities
  allow — the capability model bounds *scope*, not intent; high-consequence
  actions get presence/approval constraints, but a trusted operator is trusted.

## The load-bearing controls

1. Pinned mutual TLS (device identity is a cert, not a token/header).
2. Signing key off the server (a compromised server can't forge artifacts).
3. Per-action, per-scope capabilities enforced at the tunnel, not the UI.
4. Local break-glass so external-identity outage ≠ lockout.
5. Management segment isolation (bounds the unaudited firmware userland).
