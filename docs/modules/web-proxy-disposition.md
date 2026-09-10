# `/web/:devid/:proto/:addr/*path` — disposition

**Question asked:** gut it (D-008), after checking whether the migration path
depends on it.

**Answer: it is worse than described AND more load-bearing than described.**
Both halves changed on measurement, so the decision changes shape.

## It is a worse primitive than "a proxy into the device"

The address is not restricted to the device. `httpProxyVaildAddr`
(`internal/server/http.go:555-575`) parses `addr` with `net.SplitHostPort`,
defaults the port to 80, and requires only that the host parse as an IPv4
literal:

```go
ip := net.ParseIP(ips)
if ip == nil { return nil, 0, errors.New("invalid IPv4 Addr") }
ip = ip.To4()
if ip == nil { return nil, 0, errors.New("invalid IPv4 Addr") }
```

No allowlist, no loopback/RFC1918 exclusion, no port restriction. The proxied
connection is then made **by the device**, from the device's network position.

So the reachable set is not "the device's own HTTP surface" — it is **any
IPv4:port the device can route to**, which is the managed segment: the very
network the KVM exists to reach out-of-band. That is an SSRF primitive aimed at
the inside of the estate, and `docs/THREAT-MODEL.md` makes management-segment
isolation load-bearing precisely because the firmware userland is unaudited.
This route punches through that isolation by design.

## But it is also how the product reaches a device's web UI

`httpProxyRedirect` branches on the device's self-reported client type
(`internal/server/http.go:374`):

```go
if dev.ClientType() != "rtty-go" {
        // Non-rtty-go clients use the KVM control UI → remote_control
        ses.logID = cont.DeviceLogSvc.StartRemoteControlSession(...)
} else {
        ses.logID = cont.DeviceLogSvc.StartRemoteWebSession(...)
}
```

The inherited product routes **the KVM control UI itself** through this proxy
for non-`rtty-go` devices, and audits it as `remote_control`. So gutting the
route wholesale does not merely remove a generic proxy and break legacy
adoption — for some device types it removes **the primary console path**.

That is a bigger blast radius than the migration question that prompted the
check. Migration's dependency is real but secondary: the root-shell path in
`docs/modules/migration.md` §3 reaches a stock device's admin surface over the
network, and this is the route that would carry it.

*(Aside: `ClientType()` reads a device-self-reported JSON field
(`internal/server/device.go:530`). A device chooses which branch — and which
audit record — its own session gets. Noted for the audit work, not resolved
here.)*

## Disposition

**Gut it, and the replacement is not one thing but two.** The route conflates
two functions that have different threat profiles and must not share a
mechanism:

1. **Reaching a managed device's own web UI** — legitimate, frequent, and
   enumerable. Replacement: a device-scoped channel where the destination is
   *the device*, not a caller-supplied address. The device's own service ports
   are a short, known list; the proxy should take a named service, not an
   `addr`. Capability-gated like any other device operation.
2. **Reaching an arbitrary host on the managed segment** — this is the SSRF
   primitive. It has no capability that can honestly describe it, and per D-008
   it goes away. If a genuine need for it appears later it comes back as its
   own capability with its own threat-model entry, not as a parameter.

Migration's needs are served by (1) plus, where adopt-and-harden needs more
than the device's web UI, a **purpose-built, server-initiated, enumerable
migration channel** — not a retained general proxy.

**Sequencing.** Removing (2) is the security fix and is cheap. Building (1) is
the work. They must land together or the console path breaks for non-`rtty-go`
devices; this is not a "gut now, replace later" item.

## Interim: narrowed to loopback, NOW (landed)

Gut-and-replace-together is right, but the SSRF was live meanwhile. The same
boundary the named-service channel will draw permanently is drawn early and
crudely instead: `httpProxyVaildAddr` now rejects any non-loopback destination.

**Measurement that made this safe** — the console path does not need an
off-device address. `handleRemoteControl`
(`ui/src/views/device/components/deviceListView.vue`) builds its URL from a
**hardcoded** `127.0.0.1:443`:

```js
let proto = 'https'
let ipaddr = '127.0.0.1'
let port = 443
const addr = encodeURIComponent(`${ipaddr}:${port}${path}`)
window.open(`/web/${id}/${proto}/${addr}`)
```

So the console is untouched by the restriction. The *other* call site,
`accessDeviceWebDialog.vue`, is a form where the operator types an arbitrary IP
and port — that is the arbitrary-host feature, and it is exactly what the
narrowing removes.

This answers one of the three open measurements: **the console only ever
proxies to the device itself.** That is the more boring of the two possible
answers, and it is the one that makes the replacement simple.

**Ports are not restricted yet, and the residual risk is named.** Loopback-only
removed the *segment*; it did not remove the device's own loopback, which is
where a box's unauthenticated internal services live — services whose only
access control was "you must already be on this box". That is the `/streamer`
class again, one layer in.

### What the firmware tree says (partial — see the caveat)

Measured against `glkvm-debloat`, this risk looks **smaller on this firmware
than the general case**, because its internal IPC is not TCP:

- kvmd ↔ nginx and the streamer talk over **unix sockets**, not loopback TCP —
  `configs/nginx/kvmd.ctx-http.conf:2` (`unix:/run/kvmd/kvmd.sock`) and `:6`
  (`unix:/run/kvmd/ustreamer.sock`). The `pst` client's
  `http://localhost:0/...` (`kvmd/clients/pst.py:56,72`) is the aiohttp
  unix-connector idiom, not a TCP port.
- The TCP services shipped — nginx (`configs/nginx/nginx.conf.mako:42-72`),
  janus, ipmi, vnc — bind on all interfaces, not loopback-only, so a loopback
  proxy reaches nothing through them that the segment could not already reach.

A service reachable **only** via loopback TCP is the thing that would make port
restriction urgent, and none is visible in the tree.

> **Caveat (rule 2): this measurement is incomplete and must not be read as a
> clean bill.** It is a source read, not a runtime enumeration. A shipped image
> runs binaries that are not in this tree (`webrtc_client`, `gl-pion`,
> `ustreamer`, `atxpower`, `fingerbot`) plus whatever the closed upstream
> userland starts. The authoritative list is `ss -ltnp` on a real unit, and
> **there is no unit on this bench** — so this result is "nothing found in the
> source", not "nothing listens".

### Consequence

Port restriction stays deferred, but as a **blocked measurement rather than a
judgement call** — it is on the firmware worklist. When that list is run on a
real unit, the same enumeration produces both the residual-risk answer and the
named-service list the replacement needs. One measurement, two uses.

Mutation-checked: deleting the `ip.IsLoopback()` guard turns
`TestHTTPProxyAddrIsLoopbackOnly` red on all six off-device cases (managed
segment, the U-Boot failsafe address, egress, cloud metadata).

**Known rough edge:** `accessDeviceWebDialog.vue` still offers the arbitrary-
address form, which now returns an error for any off-device address. Removing
that dialog is part of the D-012 gut and lands with the replacement, not here —
flagged so it is not mistaken for a regression.

## What must be true before the full replacement lands

- ~~confirmation that the console only proxies to the device itself~~ —
  **done**, see above: hardcoded `127.0.0.1:443`.
- the named-service list for (1), derived from the firmware rather than guessed
- the migration module's channel requirement, since it is a second consumer

**Status:** interim narrowing **landed**. Full gut + named-service replacement
decided in principle, blocked on the two remaining measurements.
