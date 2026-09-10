# Module: permissions (capability model)

**Mode:** local-only
**Core dependency:** capability enforcement points
**Status:** planned (item 1 — the authorization spine)

## Purpose
Per-action, per-scope authorization. Answers "may this subject do this action on
this target," distinct from authentication ("who is this"). External-identity
modules plug *under* this — they establish identity; this decides authorization.

## Model
`grant = (subject, capability, scope, constraints?)`
- **subject:** user | user-group
- **capability:** maps 1:1 to an enforceable device operation —
  `view`, `screenshot`, `hid.input`, `atx.soft`, `atx.hard`, `atx.reset`,
  `atx.on`, `msd.mount`, `serial`, `port.switch`, plus management
  capabilities (`plugin.install`, `iso.mount`, `device.config`,
  `device.trust`). See `permissions-capabilities.md` for the 1:1 mapping and
  the five places the spec's original list did not survive contact with the
  firmware. In particular:
  - **`screen.control` is not a capability.** It has no firmware referent; it
    is the conjunction of `view` and `hid.input`. It is stated below as the
    enforcement rule, not granted.
  - **`serial` must be path-scoped.** `/serial/ws` opens any path under
    `/dev/`, and the ATX relay is `/dev/ttyACM0` — so an unscoped `serial`
    grant *dominates* `atx.*` and silently voids their constraints. kazbek
    imposes an allowlist of device paths at the tunnel; the firmware does not
    provide one.
  - **`device.admin` is split** into `device.config` (reversible/disruptive)
    and `device.trust` (boot-media: firmware, ssl_cert, ssh_key, overlay-network
    enrolment, factory reset). Four-eyes on all of `device.admin` gets switched
    off; four-eyes on `device.trust` survives.
  - **`atx.on` is new.** `atx.soft/hard/reset` cover only *off* and *reset*;
    powering a host **on** was unnamed.
- **scope:** device | device-group | **port** (a channel on a Comet X).
  A port-scoped grant is **tier-conditional** — see "Port scope" below. It is
  never issued as advisory.
- **constraints:** `requires_presence` (ceremony tap), `time_window`, approval
  (four-eyes) — for high-consequence capabilities (`atx.hard`, `msd.mount`).

Effective capabilities = union of group grants + direct grants, minus explicit
denies.

## Port scope — conditional on enforcement, never advisory

`docs/modules/permissions-capabilities.md` §4.1 measured the rm4pe: it is one
capture path and one USB gadget behind a mux, so its four "ports" are a **time
slice, not four addressable devices**. There is no per-port endpoint to filter,
and the mux moves on a keystroke from inside a session — kvmd-vnc's
`MagicHandler` and kvmd-localhid call `set_active_prev/next/port` directly, with
no API call and no route to gate.

A port grant that shows in the UI and does not hold at the mux is a hidden
button with extra steps: the `/streamer` failure and the vacuous-test failure in
one object. **If we cannot enforce it, we do not offer it.**

So `Scope` keeps its port, and the condition moves to *issuance*:

> The server **refuses to issue** a port-scoped grant unless the target device
> is `trusted` tier running firmware that (a) gates
> `/switch/set_active{,_prev,_next}` behind a `port.switch` capability, and
> (b) has the `MagicHandler` channel bindings **gutted** (D-008 — they are a GL
> convenience feature, and they are an ungateable path to the same operation).

Fail closed on the grant, not advisory on the enforcement. A Comet X on
`legacy` tier is **one device with four ports, not four scopes**, and is marked
as such in the UI and audit.

Enforcement, where it exists, is an **interlock**: the session's grant is
checked against the *currently active channel*, and the connection is torn down
when the channel moves. That is stateful, and it is a different mechanism from
the endpoint filtering the rest of this spec describes.

**Note the class of the finding.** The mux moves with no API call and no route
to gate. That is the same class as `/streamer`: *enforcement points that live at
routes cannot see operations that do not traverse routes.* Any capability whose
operation has a non-route path needs an enforcement point that is not a route.

## Enforcement — the load-bearing rule
Enforce at the **tunnel/stream layer, not the UI.** A session that lacks
`view` + `hid.input` (what "screen.control" meant) must get a connection that
physically cannot carry the video stream or HID — not merely a hidden button.
(The firmware `/streamer`-bypasses-the-API finding is the warning: hiding a
control is not enforcing a permission.)

**The decision is the check result, never the path the request took.**

### One construction function, not three enforcement points

There is no layer on the device that every path to a given operation crosses
(`permissions-capabilities.md` §0 measures three disjoint planes). That is an
argument for *building* one on the kazbek side, not for scattering three
independent checks — three places to remember is how `/streamer` happened.

Every device-bound path constructs its session through **one** function that:

1. resolves the **subject** (see below — today there isn't one),
2. resolves the subject's **capability set** for the target, **once**, at
   session establishment,
3. returns a connection with **only the permitted channels demuxed** — the
   video and HID frame arms are absent from the session, not disabled in it.

There is deliberately **no re-check API**: a session cannot acquire a capability
it was not constructed with.

> **If a route can obtain a device connection without going through that
> function, that route is the next bypass.** Adding one is a trust-boundary
> change and stops for review (rule 10).

### Resolving a subject is the first phase, not a prerequisite

`internal/server/user.go`'s `handleUserConnection` binds a user to a device
console with **no principal in scope at all**, and `httpAuth`
(`internal/server/api.go`) returns a bool without ever resolving *which* user.
You cannot authorize without a principal. Getting one onto the tunnel path is
**Phase 1 work, budgeted as work** — not a gap in the plan to be noted and
skipped.

## Threat model delta
Bounds what a *granted* subject can do; does not bound intent. A trusted operator
is trusted — constraints add presence/approval for the dangerous few.

## Design notes
Check GL's `glkvm-cloud` `policy-engine` and KVM Fleet's (Apache-2.0) constraint
engine (time-of-day / require-MFA / max-sessions / approval) before writing one —
adopt if they fit.

## Tests
- capability check allows/denies correctly per grant/scope
- port scope: the server REFUSES to issue a port-scoped grant for a device that
  is not trusted-tier with `port.switch` gating and the chord bindings gutted
  (fail closed at issuance)
- port scope enforced on a trusted-tier Comet X: a grant on port 1 does not
  reach port 3, AND the session is torn down when the mux moves under it
- the magic-chord path (`MagicHandler` / localhid) cannot move the mux on a
  device where port scope is in force
- **stream-layer enforcement**: a session without `screen.control` cannot pull
  video even by hitting the stream endpoint directly (the bypass test)
- constraint: `requires_presence` blocks without the ceremony; `time_window`
  outside hours denies; approval pends
