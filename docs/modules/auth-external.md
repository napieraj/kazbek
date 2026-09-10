# Module: auth-external (RADIUS / OIDC / LDAP)

**Mode:** cloud-managed (always with local break-glass)
**Core dependency:** `AuthProvider`
**Status:** planned (item 4). OIDC/LDAP bones inherited from glkvm-cloud.

## Purpose
Authenticate operators against an external identity system. These modules answer
**who is this** — they do NOT authorize. Authorization is the `permissions`
module (item 1), which these plug *under*.

## Implementations
- `auth-oidc`, `auth-ldap` — inherited, adapted.
- `auth-radius` — a `plugins/auth/` module against the `AuthProvider` interface
  (as WebAuthn was on the firmware side). RADIUS validates a credential; it does
  not carry capabilities.

## The hard rule (D-006)
**External identity is never the only path.** If the IdP/RADIUS server is
unreachable — the exact outage a KVM exists for — a local credential must still
log in:
- WebAuthn against the device's pinned credential, or
- a break-glass password in the vault.
The core trusts the external system *when reachable* and a local credential *when
not*. An OOB device that dies with its IdP has failed at its one job.

## Fallback
Documented above — this module's degradation IS the break-glass path, and it is
mandatory, not optional. A deployment that enables an external `AuthProvider`
without a configured local fallback should refuse to start (or warn loudly).

## Tests
- valid external credential authenticates; identity flows to the capability layer
- IdP unreachable → local break-glass still logs in
- external auth without a configured fallback → startup refuses/warns
- external identity carries no capability by itself (authz is separate)
