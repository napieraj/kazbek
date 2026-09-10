# Work that belongs to `glkvm-debloat`, not kazbek

Findings from kazbek's item-1 Phase 0 whose fix is on the firmware side. Each
names the enforcement kazbek needs and why the server cannot do it alone.

Every `file:line` is in the `glkvm-debloat` tree and was read while writing
this. Re-derive before acting (rule 1) — this list will go stale.

---

## 1. Gate the port switch, and gut the chord bindings

**Blocks:** port-scoped grants entirely. kazbek refuses to issue one until this
exists (`docs/modules/permissions.md`, "Port scope").

Two paths move the mux, and only one is a route:

- `POST /switch/set_active`, `/switch/set_active_prev`, `/switch/set_active_next`
  (`kvmd/apps/kvmd/api/switch.py:56,61,66`). Needs to sit behind a
  `port.switch` capability.
- **A keystroke, with no API call at all.** kvmd-vnc's `MagicHandler` binds
  arrows and digits (`kvmd/apps/vnc/server.py:134-143`) to
  `__on_magic_switch_prev/next/port` (`:361,367,373`), which call
  `switch.set_active_prev/next/set_active`. kvmd-localhid does the same
  (`kvmd/apps/localhid/server.py:70-75,169,174,179`).

The second is the one that matters: **a subject granted `view` + `hid.input` on
port 1 can type their way to port 3.** No route exists to gate, so no
server-side check can see it.

**Action: gut the chord bindings** (D-008 — they are a GL convenience feature,
and their presence is the vulnerability). Masking them is not enough; presence
is the security property.

Note the class, because it will recur: *enforcement points that live at routes
cannot see operations that do not traverse routes.*

## 2. `skip_verify` must not exist

**Blocks:** nothing formally, but it is the negation of an invariant already
committed to (D-005/D-007: artifacts verify against a pinned anchor, and a
compromised server cannot forge them).

`POST /upgrade/start?skip_verify=1` skips firmware signature verification with
a log warning and nothing else:

```python
# kvmd/apps/kvmd/api/upgrade.py:729-743
skip_verify = request.query.get("skip_verify")
should_skip_verify = skip_verify_value in ["true", "1"]
...
if should_skip_verify:
    get_logger(0).warning("Skipping firmware signature verification as requested")
else:
    signature_result = await self.__update_engine.verify_firmware_signature()
```

**Caller-selectable verification is not verification.** Whoever can reach the
route decides whether signatures matter. This should be removed now rather than
waiting for roadmap item 2 — item 2 designs the trust anchor, but no anchor
design survives a parameter that turns it off.

**Action: remove the parameter and the branch.** If an unsigned-image path is
genuinely needed for development, it belongs behind a build flag or a physical
path (U-Boot failsafe, which `docs/modules/migration.md` already documents as
requiring physical possession), not a query string.

## 3. Path-scope `serial`, or it dominates `atx.*`

`/serial/ws` accepts any path under `/dev/` — the whole check is:

```python
# kvmd/apps/kvmd/api/serial.py:480-481
if not dev.startswith("/dev/"):
    raise BadRequestError(f"Invalid device path: {dev}")
```

and the ATX relay is `/dev/ttyACM0` (`kvmd/plugins/atx/glatx.py`, `__device`).

So a `serial` grant reaches the ATX relay directly, which means it **dominates**
`atx.soft` / `atx.hard` / `atx.reset` and **silently voids their constraints** —
four-eyes on `atx.hard` is worth nothing to a subject holding `serial`.

kazbek will impose an allowlist at the tunnel regardless
(`docs/modules/permissions.md`), because it must hold for legacy-tier devices
too. But the firmware should narrow it as well: defence in depth, and the
firmware knows which paths are real.

**Action:** allowlist the serial device paths the product actually exposes.

## 4. Ungated operations that need capabilities

From `docs/modules/permissions-capabilities.md` §5. These are not firmware bugs
— they are operations kazbek must be able to name. Listed here because the
firmware side must expose them distinguishably.

- `atx.power?action=on` (`kvmd/apps/kvmd/api/atx.py:52`) — `atx.soft/hard/reset`
  cover only *off* and *reset*. Powering a host **on** was unnamed.
- fingerbot (`kvmd/apps/kvmd/api/fingerbot.py:229,268,302`) — a BLE actuator
  that **physically presses the target's power button**. Same outcome as
  `atx.*`, by a path no ATX capability touches. `POST /fingerbot/upgrade`
  (`:414`) also flashes its firmware.

## 5. Enumerate what actually listens on loopback (needs a real unit)

**Blocks:** the port allowlist for the `/web` replacement, and the residual-risk
answer for the interim narrowing (`docs/modules/web-proxy-disposition.md`).

`/web` is now loopback-only, which removes the managed segment from its reach
but not the device's own loopback — where a box's unauthenticated internal
services live, gated by nothing but "you are already on this box".

The source read says this is probably small on this firmware: kvmd, the
streamer and pst use **unix sockets** (`configs/nginx/kvmd.ctx-http.conf:2,6`),
and the TCP services bind on all interfaces anyway. But a shipped image runs
binaries absent from this tree — `webrtc_client`, `gl-pion`, `ustreamer`,
`atxpower`, `fingerbot` — plus the closed upstream userland.

**Action:** `ss -ltnp` on a real unit, in the shipped configuration. Record
every listener, its bind address, and the process. That single enumeration
yields both the residual-risk answer and the **named-service list** the
replacement channel needs, so it is worth doing once and properly rather than
guessing twice.

Until it exists, the `/web` port allowlist is a blocked measurement, not a
judgement call.

---

## The membership rule for this list — read before adding to it

An item belongs here **only if kazbek cannot reach it from the server side.**
That is a narrower test than "it is a bypass", and the difference is worth
stating because the next reader will otherwise see an inconsistency and
helpfully add `/streamer` back.

**`/streamer` is contained by architecture, not by a firmware fix.** Under
D-011, a session is constructed with only its permitted channels demuxed — a
session lacking `view`/`hid.input` gets a connection with no video arm wired at
all. `/streamer` is then **unreachable** through anything kazbek builds, not
merely ungated. There is nothing for the firmware to fix on kazbek's account.

The four items above fail that test for a specific reason: **each is an
operation that never crosses a connection kazbek constructs.** The mux moves on
a keystroke inside a VNC session; `skip_verify` is a parameter on a route the
device serves; `serial` widens to `/dev/*` inside the device; the fingerbot
presses a physical button. No session-construction discipline on the server can
see any of them, so the enforcement has to be on the device.

So the test is: *would this still happen if every kazbek session were
constructed with exactly the right channels and nothing else?* If yes, it goes
here. If no, it is contained already.

## Not on this list

The `/streamer` bypass, the `gui_*` peer-exe routes, `/auth/two_step_approve`
being `auth_required=False`, and the rest of the bypass index in
`permissions-capabilities.md` §3 — all contained by the rule above, and all
arguments for the trusted tier rather than a firmware backlog.

One caveat on `/auth/two_step_approve`: it is contained *as an authentication
bypass*, but if `requires_presence` is ever built on the firmware's two-step
approval, this becomes a first-class item on this list. Presence that the
device can self-assert is not presence. Flagged now so the constraint work does
not discover it later.
