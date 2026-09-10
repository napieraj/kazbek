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

## What must be true before this lands

- the named-service list for (1), derived from the firmware rather than guessed
- confirmation of which device types actually report a non-`rtty-go` client, so
  the blast radius of (1) is measured rather than assumed
- the migration module's channel requirement, since it is a second consumer

**Status:** decided in principle (gut + two replacements), blocked on those
three measurements. Not started.
