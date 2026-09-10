# Module: tunnel-client (device dial-out with a pinned client certificate)

**Owner:** `glkvm-debloat`
**Status:** filed, not started
**Blocks:** the device half of the mTLS swap; end-to-end exercise of that swap
**Does not block:** the plugin foundation's device half — see "Sequencing" below

## The gap

`glkvm-debloat` contains **no tunnel client.** GL.iNet ships one as `S99rtty`,
outside both repositories. That binary authenticates with a **shared token**:
registration carries `msgRegAttrToken`, and the server compares it against a
single fleet-wide `cfg.Token` (`internal/server/device.go`, the
`devRegErrInvalidToken` path). One secret, every device.

The device listener's TLS is **server-only** today. `ListenDevices` builds a
`tls.Config` with `GetCertificate` and wraps the listener with
`tls.NewListener`; it sets neither `ClientAuth` nor `ClientCAs`, and nothing in
`internal/` reads `PeerCertificates`. There are no client certificates in the
system at all.

The mTLS work replaces the shared token with pinned mutual TLS. **GL's rtty
client cannot present a pinned client certificate**, so the device end of that
swap has no implementation and, until this item exists, no owner.

## Why this is a deliverable and not a detail

The mTLS handoff is entirely server-side: require and verify the client cert,
take identity from `PeerCertificates`, replace one comparison. It never says
who dials in holding the cert.

That omission is load-bearing. Turning on `RequireAndVerifyClientCert` today
stops **every stock device** connecting, because none of them has a certificate
to present. So the swap cannot be exercised end to end — not partially, not in
a lab, not at all — until something on the device dials out with one. An
unbudgeted core deliverable is sitting underneath a change that reads like a
one-line edit.

This is the same shape as a plan scoped against a seam that exists on only one
end: the server side is small precisely because the hard half was never
counted.

## Deliverable

A dial-out tunnel client, owned by `glkvm-debloat`, that:

1. connects to kazbek's device listener over TLS;
2. presents a **per-device** client certificate;
3. pins the server's certificate rather than trusting a system trust store;
4. speaks the existing rtty framing — `type:1 | len:2 BE | body` — so the
   message layer is unchanged;
5. obtains and stores its certificate and private key on a read-only rootfs
   (this overlaps the plugin half's writable-storage question — see
   `docs/modules/plugins.md` on `kvmd-pst`).

Item 5 is not incidental. A device that cannot durably hold a private key
cannot hold a client certificate either, and the storage question is the same
one the plugin half opens with.

## What it unblocks

- **The mTLS swap becomes exercisable.** Server-side and device-side land
  together or the fleet is offline.
- **Plugin frames become ordinary.** Once this exists, `0xF1` and its
  sub-types are just a message type on a transport we own both ends of, and the
  message-type collision domain stops being a question about somebody else's
  binary.
- **Per-device identity replaces a fleet-wide secret.** One compromised device
  currently yields the token every other device uses.

## Sequencing

This item does **not** gate the plugin foundation's device half. Invariant 5 is
what makes that true: local drop-in and fleet push are two sources feeding one
verify-and-load path, so the device half — remount, unpack, verify, place, load,
readback, atomic rollback — can be built and tested against local drop-in alone,
with no transport at all. When this client lands, pushed bytes join that path at
the verify step.

That is invariant 5 used as a build order rather than asserted as a property.

## Open questions

1. Certificate issuance: how a device gets its first cert. Expected to be
   pairing-delivered, per the provisioning module, which makes this item and
   that one adjacent.
2. Key storage on a read-only rootfs, shared with the plugin half's question.
3. Rotation and revocation, and whether the shared-token path stays as a
   fallback during migration — noting that a fallback which never expires is
   the shared-token model with extra steps.
4. Whether the client is a new binary or a fork of rtty.
