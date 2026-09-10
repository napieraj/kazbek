# Architecture

kazbek is a **small trusted core** plus **opt-in modules**. The core is the only
thing every deployment runs and the only thing that touches device trust;
modules register against it and are enabled per deployment.

## Two products, one boundary

- **Device** — `glkvm-debloat`, the hardened kvmd daemon on the KVM.
- **Management** — kazbek, this server.

They meet at exactly one boundary: the device connection. Everything about *how
you manage* sits on the kazbek side of it; everything about *the console
hardware* sits on the device side. Keep them distinct — a feature belongs to one
or the other, and the boundary is the pinned-mTLS connection between them.

## The core (always present)

1. **Device connection.** The device dials in to the server's device listener.
   The connection is **mutual TLS**: the device verifies the server's pinned
   certificate and presents its own pinned client certificate. The device still
   dials out (across NAT something must), but it dials a connection where both
   ends are pinned — which is the secure inversion of the vendor-cloud tunnel,
   not the same thing. The anti-pattern was *unpinned trust of a third party*,
   not the dial direction.

2. **Device identity.** Identity comes from the **client certificate** presented
   in the TLS handshake — channel-bound, non-replayable, non-relayable. The
   register message the device sends (id, MAC, group, heartbeat) is *metadata to
   check against the cert*, never the authenticator. This replaces the stock
   fork's single shared token.

3. **Module loader + capability contract.** The interfaces modules implement:
   `AuthProvider`, `Signer`, `TrustStore`, capability enforcement points. A
   module is a registration against these, enabled by config.

Nothing else is in the core. Auth methods, permissions, signing, provisioning,
plugins, recipes, screenwall — all modules.

## Why a fork of glkvm-cloud, not a clean build

Measured, not assumed. The stock device-connection core is ~100 lines behind a
clean `net.Conn` seam:
- `ListenDevices` does `net.Listen` / `Accept` and already wraps `tls.NewListener`
  when a cert is configured.
- `ReadMsg`/`WriteMsg` is a transport-agnostic 3-byte-header framing over a
  `bufio.Reader` on `net.Conn` — indifferent to TCP vs TLS.
- `Register`'s entire device auth is one check: `dev.token != cfg.Token → reject`.

So the swap from shared-token to pinned-mTLS is: turn on
`RequireAndVerifyClientCert` with a pinned CA pool, read identity from
`ConnectionState().PeerCertificates`, and change one `if`. The **entire
management plane above the seam** — domain model, OIDC/LDAP, RBAC, groups, audit,
notifications, UI — is inherited unchanged. Forking saves that; the connection
model is a contained change, not the architecture's spine. (The earlier worry
that the tunnel direction was fundamental was wrong: the transport is thin and
seam-isolated, and pinned-mTLS keeps the dial-in while fixing the trust.)

## The connection swap (first work)

```
ListenDevices          → tls.Config{ClientAuth: RequireAndVerifyClientCert,
                          ClientCAs: pinnedDeviceCAs}
handleDeviceConnection → identity := conn.PeerCertificates[0]; register msg
                          becomes claims-to-check, not identity
Register               → cert-match replaces cfg.Token equality; keep metadata,
                          heartbeat, dedup, online/offline events unchanged
everything above       → untouched
```

## Modes

Every module declares one:
- **local-only** — works with the core and nothing else (password, webauthn,
  permissions).
- **cloud-managed** — needs the server's richer services (external identity,
  screenwall).
- **both** — degrades to local, richer with the server (signing, provisioning,
  plugins, recipes).

The rule that makes this safe for an OOB device: **no cloud-managed auth path is
ever the only path.** External identity (RADIUS/OIDC/LDAP) authenticates when
reachable; a local credential (WebAuthn against a pinned key, or a break-glass
password in the vault) logs in when it isn't. An OOB device that dies with its
IdP has surrendered its reason to exist.

## Gut, not mask

For code kazbek owns, unused features are *absent*, not disabled — presence is a
security property. (Mask only the closed upstream services a removal orphans, as
on the firmware side.) A module you don't enable isn't loaded; a capability you
don't grant isn't reachable.
