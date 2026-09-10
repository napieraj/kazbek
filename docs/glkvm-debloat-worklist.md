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

---

## Not on this list

The `/streamer` bypass, the `gui_*` peer-exe routes, `/auth/two_step_approve`
being `auth_required=False`, and the rest of the bypass index in
`permissions-capabilities.md` §3. Those are real, but they are the reason
kazbek does not trust the device's own auth plane at all — they are arguments
for the trusted tier, not a firmware backlog. The four items above are
different: each one is a thing kazbek **cannot** enforce from the server side,
so the firmware has to.
