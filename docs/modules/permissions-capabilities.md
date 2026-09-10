# permissions — capability ↔ operation map

**Companion to:** `docs/modules/permissions.md` (item 1, the authorization spine)
**Status:** data/contract artifact. This is the authoritative list of what each
capability actually authorizes on a real device.
**Derived from:** the working tree of the sibling firmware repo `glkvm-debloat`
(a kvmd fork) as checked out at `/home/user/glkvm-debloat`, read on 2026-09-10.

Every `file:line` below was opened and read while writing this. Where something
could not be found, the row says **absent, searched `<pattern>` in `<path>`**
rather than guessing. Facts read from source are stated plainly; anything
inferred is marked *(inference)*.

---

## 0. How to read this

Three things must be separated, and the spec currently blurs them:

1. **The capability** — a name in a grant.
2. **The operation** — a concrete state change or data flow at the device.
3. **The enforcement point** — the place a request can actually be refused.

The spec's load-bearing rule ("enforce at the tunnel/stream layer, not the UI")
is right, but it is not sufficient, because on this firmware there is *no single
layer* where every path to a given operation passes. Enforcement has to be
placed per-operation, and for several capabilities that means more than one
place. The tables below name every place found.

### The three enforcement planes on the device

| Plane | What sits there | Auth it applies today |
|---|---|---|
| **A — nginx** | `configs/nginx/kvmd.ctx-server.conf` | `auth_request /auth_check` at file:5 → `/auth/check`; every `location` for `/api*` sets `auth_request off` and lets kvmd do it (file:53–116). `location /streamer` (file:118–125) does **not** turn it off, so it is gated by session-cookie validity **only**. |
| **B — kvmd HTTP/WS** | `kvmd/apps/kvmd/api/*.py`, `kvmd/apps/kvmd/server.py` | `check_request_auth` at `kvmd/apps/kvmd/api/auth.py:162–171`. It is **binary**: authenticated or not. There is no per-user, per-action, or per-port check anywhere in it. |
| **C — out-of-band** | kvmd-vnc, kvmd-ipmi, gl-pion/webrtc_client, ustreamer's own socket, sysfs/configfs | Each has its own credential store, or none. `HttpServer._check_request_auth` at `kvmd/htserver.py:522–523` is a bare `pass` — any kvmd-derived server that does not override it (kvmd-media does not) authenticates nobody. |

The consequence for kazbek: **plane B alone cannot enforce any capability in this
list.** kazbek's enforcement must sit in front of, or in place of, planes A and C
too — which is exactly what "at the tunnel, not the UI" has to be read to mean.

### Consequence classes

- **reversible** — no lasting effect on the managed host; undone by stopping.
- **disruptive** — interrupts or destroys running state on the managed host.
- **boot-media** — changes what the host will execute at next boot. Strictly
  worse than disruptive: it is code execution on the target, deferred.

---

## 1. Master table

| capability | kind | primary enforcement point (file:line in `/home/user/glkvm-debloat`) | port-scopable on rm4pe | consequence | constraints implied | bypass paths found |
|---|---|---|---|---|---|---|
| `view` | device | nginx `configs/nginx/kvmd.ctx-server.conf:118` → ustreamer `/stream` (`kvmd/clients/streamer.py:184`) | **no — time-multiplexed only** | reversible | `time_window` | 5 |
| `screenshot` | device | `kvmd/apps/kvmd/api/streamer.py:54` | **no — same** | reversible | `time_window` | 4 |
| `screen.control` | device | **no single point — absent as an operation** | n/a | reversible | — | n/a (composite) |
| `hid.input` | device | `kvmd/apps/kvmd/api/hid.py:283`/`214` (ws) + `:343–393` (http) | **no — one OTG gadget** | disruptive | `time_window` | 4 |
| `atx.soft` | device | `kvmd/apps/kvmd/api/atx.py:47` (`action=off`) / `:59` (`button=power`) | **no — stub on this build** | disruptive | `requires_presence` | 4 |
| `atx.hard` | device | `kvmd/apps/kvmd/api/atx.py:47` (`action=off_hard`) / `:59` (`button=power_long`) | **no — stub** | disruptive | `requires_presence`, four-eyes | 4 |
| `atx.reset` | device | `kvmd/apps/kvmd/api/atx.py:47` (`action=reset_hard`) / `:59` (`button=reset`) | **no — stub** | disruptive | `requires_presence` | 4 |
| `msd.mount` | device | `kvmd/apps/kvmd/api/msd.py:92` → `kvmd/plugins/msd/otg/__init__.py:416,435` | **no — one gadget** | **boot-media** | `requires_presence`, four-eyes | 3 |
| `serial` | device | `kvmd/apps/kvmd/api/serial.py:452` | no (device-global) | disruptive | `requires_presence` | 2 |
| `plugin.install` | management | **absent on device** (searched `exposed_http` ∩ `install\|plugin\|extension\|addon` in `kvmd/`) — nearest is `kvmd/apps/kvmd/api/upgrade.py:665,721` | no | **boot-media** | four-eyes | 2 |
| `iso.mount` | management | `kvmd/apps/kvmd/api/msd.py:219,248,78` | no | **boot-media** (as staging) | four-eyes | 2 |
| `device.admin` | management | ~90 routes across `system.py`, `upgrade.py`, `tailscale.py`, `zerotier.py`, `netbird.py`, `astrowarp.py`, `cloudflare.py`, `ap.py`, `repeater.py`, `init.py`, `twofa.py` | no | **boot-media** | four-eyes | many |

---

## 2. Per capability

### 2.1 `view` — live video of the target console

**Operation.** Continuous MJPEG or H.264 frames from the single HDMI capture.

**Enforcement points (read from source).**
- nginx `configs/nginx/kvmd.ctx-server.conf:118–125`: `location /streamer` rewrites
  `^/streamer/(.*)$ → /$1` and `proxy_pass http://ustreamer`. The upstream is
  `unix:/run/kvmd/ustreamer.sock` (`configs/nginx/kvmd.ctx-http.conf:5–7`).
  This block does **not** carry `auth_request off`, so it inherits the
  server-level `auth_request /auth_check` at `kvmd.ctx-server.conf:5` — i.e. a
  valid session cookie and nothing else.
- The video path itself is ustreamer's `/stream`, confirmed by the client that
  reads it at `kvmd/clients/streamer.py:184` (`url="/stream"`), and by the web UI
  which fetches `${ROOT_PREFIX}streamer/stream?key=...` at
  `web/share/js/kvm/stream_mjpeg.js:143`. (`key` is `tools.makeRandomId()` at
  `stream_mjpeg.js:35` — a client-side stream identifier, **not** a credential.)
- kvmd's own `/streamer` route (`kvmd/apps/kvmd/api/streamer.py:50`) returns
  *state only*. **kvmd never sees a video byte.**

**Kind.** Device operation.

**Port-scopable.** **No, not in the sense the spec assumes.** Justified from
`kvmd/apps/kvmd/switch/sysfs_device.py`:
- `__channel_count = 4` (line 26) but there is exactly one capture path: the
  four channels are an i2c mux, selected by writing a single sysfs file
  `CHANNEL_FILE = /sys/bus/i2c/devices/3-0058/channel` (lines 30–31), written at
  line 396 (`self.CHANNEL_FILE.write_text(str(ch))`) and in the camera path via
  `_async_switch_channel_mux_only` (line 269, called at line 475).
- `request_state` (line 565) reports one `active_port` (lines 569–574) plus
  per-channel *link presence* only (`state["video"]["links"]`, line 581).

So a port is a **time slice of one video pipe**, not an addressable stream. A
grant of `view` on port 1 does not constrain what a port-1 session sees: it sees
whatever channel is active at that instant, and any other actor switching the
mux redirects it. Enforcing `view@port1` requires **interlocking the grant with
the active-channel state**, not filtering a per-port endpoint — because no
per-port endpoint exists. *(This is the single most important structural finding
for D-009; see §4.1.)*

**Consequence.** reversible (read-only), but confidentiality-bearing: the console
of a server shows credentials, key material, and the contents of any session.

**Constraints implied.** `time_window` is meaningful. `requires_presence` and
four-eyes are not proportionate — this is the base capability of a KVM.

**BYPASS RISK — five parallel paths, all real:**
1. **`GET /streamer/stream` direct** (the canonical finding). nginx serves it
   from ustreamer without kvmd in the path at all. A UI that hides the video
   pane changes nothing.
2. **`GET /streamer/snapshot` in a loop** — ustreamer's own snapshot endpoint via
   the same nginx block, reconstructing video at whatever rate the client polls.
3. **WebRTC / `gl_webrtc` adaptive mode.** `POST /streamer/set_params?gl_webrtc=1`
   (`kvmd/apps/kvmd/server.py:507`, parsed at `:512–514`) causes
   `__enter_adaptive_mode` (`server.py:361–364`) to **kill janus and ustreamer**
   and launch `/usr/bin/webrtc_client` (`server.py:294`). Video then leaves the
   device over WebRTC to a TURN server whose config is served by
   `kvmd/apps/kvmd/api/turn.py:179`. kvmd mediates none of it, and
   `webrtc_client` is a closed binary not present in this tree.
4. **Janus.** `configs/janus/janus.plugin.ustreamer.jcfg` binds
   `sink = "kvmd::ustreamer::h264"` — a shared-memory sink, read without HTTP.
   The same sink class is read in-process by `MemsinkStreamerClient`
   (`kvmd/clients/streamer.py:247`).
5. **kvmd-vnc.** `kvmd/apps/vnc/server.py` serves the framebuffer on TCP 5900
   (`kvmd/apps/__init__.py:872`) under a *different* credential:
   `_on_authorized_vncpass` (`vnc/server.py:348–350`) opens a kvmd session with
   **empty user and password**. A VNC-password holder is an anonymous kvmd user.

---

### 2.2 `screenshot` — a single still frame

**Operation.** One JPEG of the current console.

**Enforcement points.**
- `kvmd/apps/kvmd/api/streamer.py:54` — `GET /streamer/snapshot`, calling
  `Streamer.take_snapshot` (`kvmd/apps/kvmd/streamer.py:428`) which fetches
  ustreamer's `/snapshot` over the unix socket (`kvmd/clients/streamer.py:127`).
- `kvmd/apps/kvmd/api/streamer.py:95` — `DELETE /streamer/snapshot` clears the
  saved frame.

**Kind.** Device operation.

**Port-scopable.** No — same single-capture argument as `view` (§2.1).

**Consequence.** reversible.

**Constraints implied.** `time_window`.

**BYPASS RISK — four:**
1. **nginx `/streamer/snapshot`** reaches ustreamer's snapshot endpoint directly,
   never touching `api/streamer.py`. Identical to the `view` bypass.
2. **`?load=true`.** `take_snapshot` at `kvmd/apps/kvmd/streamer.py:429–430`
   returns `self.__snapshot` immediately when `load` is set, with **no hardware
   access and no freshness check**. A frame saved earlier under someone else's
   grant (`save=true`, stored at `streamer.py:436–437`) is served to anyone who
   asks. A grant revoked after a save does not un-serve the frame.
3. **`?ocr=true`.** The same handler (`api/streamer.py:62–79`) returns
   **recognised text** of the screen instead of pixels. A policy that gates
   images but not this yields the same secrets in a cheaper form.
4. **`POST /recorder/start`** (`kvmd/apps/kvmd/api/recorder.py:177`) writes a
   video file, from which frames are trivially extracted.

---

### 2.3 `screen.control` — **1:1 FAILS. Not an operation.**

**Searched:** `grep -rn "screen.control\|screen_control" --include=*.py
/home/user/glkvm-debloat/kvmd/` → **absent**. There is no firmware route,
plugin method, or state field by this name or shape.

Reading `permissions.md:28–29` ("A session that lacks `screen.control` must get a
connection that physically cannot carry the video stream or HID"),
`screen.control` is not a peer of `view` and `hid.input` — it is a **statement
about session construction** that is satisfied by simultaneously withholding
`view` and `hid.input`. It is a *derived* property, not a grantable operation.

Keeping it as a sibling capability creates a real ambiguity: what does
`screen.control` denied + `view` granted + `hid.input` granted mean? Nothing
enforceable. **Recommendation: delete `screen.control` from the capability list
and restate it as the enforcement requirement it is** (see §4.2).

---

### 2.4 `hid.input` — keyboard / mouse / touch injection

**Operation.** Writes to the USB HID gadget functions `hid.usb0/1/2`
(`kvmd/apps/kvmd/api/system.py:961–963`).

**Enforcement points — plural, in three shapes:**
- **WebSocket JSON events**: `kvmd/apps/kvmd/api/hid.py:283` (`key`), `:293`
  (`mouse_button`), `:302` (`mouse_move`), `:311` (`mouse_relative`), `:315`
  (`mouse_wheel`), `:319` (`touch`).
- **WebSocket binary events**: `kvmd/apps/kvmd/api/hid.py:214, 227, 240, 250,
  254, 258` (`@exposed_ws(1)`…`(6)`) — the same injection, different encoding.
- **Plain HTTP**: `kvmd/apps/kvmd/api/hid.py:343` (`send_shortcut`), `:356`
  (`send_key`), `:367`, `:378`, `:385`, `:389`, `:393`. Each is a complete
  keystroke-injection primitive on its own, no websocket required.
- **Bulk paste**: `kvmd/apps/kvmd/api/hid.py:169` — `POST /hid/print` types an
  arbitrary body as keystrokes. nginx gives it its own `location` with
  `auth_request off` at `configs/nginx/kvmd.ctx-server.conf:62–69`.

**Kind.** Device operation.

**Port-scopable.** **No.** From `kvmd/apps/kvmd/switch/sysfs_device.py`: there is
one USB gadget (`GADGET_DIR = /sys/kernel/config/usb_gadget/rockchip`, line 41)
with one set of HID devices (`HID_DEVICE_NAMES = ("hidg0".."hidg3")`, line 47).
Switching channels **tears the gadget down and rebuilds it** — `_set_hid_suspended`
(line 105), then USB/DWC3 unbind at lines 408 and 414, and in the camera path
`_set_hid_suspended(True)` at line 462 with `_async_wait_hid_fds_released` at
line 464. HID follows the mux; it is not addressable per port.

**Consequence.** disruptive. Keystrokes into a live console are arbitrary command
execution on the target from the target's own perspective.

**Constraints implied.** `time_window`. `requires_presence` is worth considering
for `/hid/print` specifically (bulk unattended injection), which is a materially
different act from interactive typing.

**BYPASS RISK — four:**
1. **`/hid/ws`** (`kvmd/apps/kvmd/server.py:578`) — a second HID websocket, gated
   by `allowed_exe_paths=["/usr/bin/gl-pion"]`. That check
   (`kvmd/apps/kvmd/api/auth.py:146–159`) reads `SO_PEERCRED` and
   `/proc/<pid>/exe` (`kvmd/htserver.py:331,341–347`) and, on match, **returns
   before any token check** (`auth.py:163–164`). So gl-pion injects HID with no
   user identity at all — and gl-pion's input comes from a **WebRTC data
   channel** (comment at `server.py:574–577`). Any HID that arrives this way is
   invisible to kvmd's auth and to any capability check placed on `/ws`.
2. **HTTP `/hid/events/send_*`** — if enforcement is put on the websocket
   handlers only (the obvious place, since that is what the UI uses), the seven
   HTTP routes at `hid.py:343–393` remain a complete bypass.
3. **kvmd-vnc.** `_on_key_event` at `kvmd/apps/vnc/server.py:357–359` feeds keys
   in over RFB, authenticated by the VNC password path described in §2.1.
4. **kvmd-localhid.** `kvmd/apps/localhid/server.py` injects from a keyboard
   physically plugged into the KVM (`is_grabbed()` at line 110/160). *Caveat,
   read from source:* there is **no `kvmd-localhid` console_script in
   `setup.py:116–136` and no `kvmd-localhid` unit in `configs/os/services/`** —
   the code ships but is not installed as shipped. Presence is still a
   liability under D-008 ("gut, not mask").

---

### 2.5 – 2.7 `atx.soft` / `atx.hard` / `atx.reset`

Treated together because they share every enforcement point and every bypass;
they differ only in the `action`/`button` query value.

**Operations.** Via `kvmd/plugins/atx/glatx.py`, each shells out to
`/usr/sbin/atxpower /dev/ttyACM0 <verb>` (device at `glatx.py:17`, binary at
`glatx.py:18`, invocation at `glatx.py:149`):

| capability | route + arg | `BaseAtx` method | atxpower verb |
|---|---|---|---|
| `atx.soft` | `/atx/power?action=off` (`api/atx.py:47,53`) or `/atx/click?button=power` (`:59,64`) | `power_off` / `click_power` | `power_off` (`glatx.py:125`) / `click_power_short` (`:136`) |
| `atx.hard` | `/atx/power?action=off_hard` (`:54`) or `/atx/click?button=power_long` (`:65`) | `power_off_hard` / `click_power_long` | `power_off_hard` (`:128`) / `click_power_long` (`:139`) |
| `atx.reset` | `/atx/power?action=reset_hard` (`:55`) or `/atx/click?button=reset` (`:66`) | `power_reset_hard` / `click_reset` | `power_reset` (`:131`) / `click_reset` (`:142`) |

Note `power_on` (`api/atx.py:52`) maps to none of the three capabilities — see
the gap list, §5.

**Kind.** Device operations.

**Port-scopable.** **No on this build, and the reason matters.** `SwitchApi`
exposes per-port ATX at `kvmd/apps/kvmd/api/switch.py:155` (`/switch/atx/power`)
and `:167` (`/switch/atx/click`), routed through `Switch.__inner_atx_cp` /
`__inner_atx_cr` (`kvmd/apps/kvmd/switch/__init__.py:195–204`) into
`Chain.click_power` / `Chain.click_reset`. On the rm4pe the `Chain` in use is
the sysfs one — `from .sysfs_chain import Chain` at
`kvmd/apps/kvmd/switch/__init__.py:50` (the serial `from .chain import Chain` is
commented out at line 49) — and in that Chain:

```
kvmd/apps/kvmd/switch/sysfs_chain.py:117   def click_power(self, port, delay, if_powered) -> None:
kvmd/apps/kvmd/switch/sysfs_chain.py:118       pass
kvmd/apps/kvmd/switch/sysfs_chain.py:120   def click_reset(self, port, delay, if_powered) -> None:
kvmd/apps/kvmd/switch/sysfs_chain.py:121       pass
```

and underneath, `kvmd/apps/kvmd/switch/sysfs_device.py:609–613`
(`request_atx_cp`, `request_atx_cr`) `return 0` without touching hardware.

**So `/switch/atx/*` on an rm4pe returns HTTP 200 and does nothing.** Per-port ATX
is *presented* by the API and *unimplemented* by the driver. Any kazbek UI or
recipe that grants `atx.hard@port3` and calls `/switch/atx/power` will report
success and not power anything off. (Whether this is a debloat regression or the
stock GL behaviour is not determinable from this tree — but the code as it stands
is what runs.)

**Consequence.** All three are **disruptive**. `atx.soft` asks the OS; `atx.hard`
and `atx.reset` cut it mid-write. Filesystem and database corruption is the
expected outcome of the latter two.

**Constraints implied.**
- `atx.soft`: `requires_presence`. It is destructive to sessions, recoverable for
  data.
- `atx.hard`: `requires_presence` **and** four-eyes. This is the spec's own named
  example and it is the right one.
- `atx.reset`: `requires_presence`. Four-eyes is defensible; it is the standard
  "it's wedged, cycle it" action and gating it behind a second human at 3am is
  exactly the kind of control that gets disabled. *(inference — a judgement call,
  not a source fact.)*

**BYPASS RISK — four, one of them severe:**
1. **`/serial/ws?dev=/dev/ttyACM0` — severe.** `GET /serial/ws`
   (`kvmd/apps/kvmd/api/serial.py:452`) takes the device path from the query
   string (`:465`) and validates it with exactly one rule:
   `if not dev.startswith("/dev/")` (`:480–481`). `/dev/ttyACM0` is precisely the
   device the ATX relay speaks on (`glatx.py:17`). **A holder of `serial` can
   drive the power relay directly**, bypassing `/atx/*` and every constraint
   attached to `atx.hard`. `requires_presence` on `atx.hard` is worth nothing if
   `serial` is granted without it.
2. **Redfish.** `POST /redfish/v1/Systems/0/Actions/ComputerSystem.Reset`
   (`kvmd/apps/kvmd/api/redfish.py:125`) dispatches into the *same* `BaseAtx`
   object via the map at `redfish.py:57–64`: `ForceOff→power_off_hard`,
   `GracefulShutdown→power_off`, `ForceRestart→power_reset_hard`,
   `PushPowerButton→click_power`. All three capabilities, one un-obvious route.
   nginx gives `/redfish` its own `location` with `auth_request off`
   (`kvmd.ctx-server.conf:127–131`).
3. **IPMI.** `kvmd/apps/ipmi/server.py:148–157` maps IPMI chassis-control codes
   `0/1/3/5` to `off_hard/on/reset_hard/off` and calls kvmd's `atx.switch_power`
   over the unix socket. Different port (UDP 623, `kvmd/apps/__init__.py:843`),
   different password file (`/etc/kvmd/ipmipasswd`, `kvmd.install:22`), and
   `kvmd-ipmi.service` ships in `configs/os/services/`.
4. **fingerbot — a physical finger.** `GET /fingerbot/click`
   (`kvmd/apps/kvmd/api/fingerbot.py:229`), `/fingerbot/push` (`:268`),
   `/fingerbot/pull` (`:302`) each exec `/usr/sbin/fingerbot set-action <push>
   <press> <pull>` (`:245–253`). This is a BLE actuator that *physically presses
   the target's power button*. It produces the same outcome as `atx.soft` /
   `atx.hard` and is covered by **no capability in the list at all**. See §5.

---

### 2.8 `msd.mount` — attach virtual media to the target

**Operation.** Write an image path into the USB mass-storage gadget's LUN, so the
target sees a disk/CD at its next enumeration.

**Enforcement points.**
- `kvmd/apps/kvmd/api/msd.py:92` — `POST /msd/set_connected` →
  `kvmd/plugins/msd/otg/__init__.py:416`, which sets rw/cdrom flags (`:431–432`)
  and then `self.__drive.set_image_path(self.__state.vd.image.path)` (`:435`).
  `Drive.set_image_path` (`kvmd/plugins/msd/otg/drive.py:54–60`) writes the
  configfs `file` attribute of `mass_storage.<instance>/lun.<lun>`
  (`drive.py:40,44`).
- `kvmd/apps/kvmd/api/msd.py:78` — `POST /msd/set_params?image=` selects *which*
  image (`plugins/msd/otg/__init__.py:387,400`).
- `kvmd/apps/kvmd/api/msd.py:120` — `GET /msd/partition_connect` attaches a whole
  **block partition**, a separate mechanism from image mounting.

**Kind.** Device operation.

**Port-scopable.** **No.** One gadget (`sysfs_device.py:41`), two mass-storage
instances (`plugins/msd/otg/__init__.py:226–227`: instance 0 = cdrom drive,
instance 1 = partition drive) — both attached to whichever channel the mux is on.
Switching channels rebuilds the gadget (`sysfs_device.py:408,414`).

**Consequence.** **boot-media.** This is the capability that turns console access
into code execution on the target.

**Constraints implied.** `requires_presence` **and** four-eyes. The spec names it
already; the reason to hold that line is that this is the only entry in the list
whose consequence class is boot-media *and* whose normal use is routine.

**1:1 note.** `msd.mount` is **not a single operation** — see §4.3.

**BYPASS RISK — three:**
1. **`POST /system/otg_functions`** (`kvmd/apps/kvmd/api/system.py:998`). The map
   at `system.py:960–969` includes `start_cdrom → mass_storage.0` and
   `start_flash → mass_storage.1`. This route **links and unlinks the mass-storage
   gadget functions directly** via `kvmd-otgconf`, bypassing `BaseMsd` entirely.
   The same map also carries `enable_keyboard/mouse/mouse_alt → hid.usb0/1/2`,
   making it a `hid.input` availability control too.
2. **`GET /msd/partition_connect`** (`api/msd.py:120`) — attaches a partition
   rather than an image. A check placed on `set_connected` alone misses it. Its
   pair `partition_disconnect` is at `:135`, and `POST /msd/switch_partition`
   at `:150`.
3. **`POST /system/reinit_udc`** (`api/system.py:2441`) rebuilds the gadget; a
   mount whose state is held only in kvmd's memory can be re-asserted or dropped
   out from under a policy decision. *(inference from the rebuild path at
   `system.py:2443–2444`.)*

---

### 2.9 `serial` — serial console to the target

**Operation.** A bidirectional byte bridge between a websocket and a tty.

**Enforcement points.**
- `kvmd/apps/kvmd/api/serial.py:452` — `GET /serial/ws`. Opens the tty at `:493`
  (`os.open(dev, O_RDWR|O_NOCTTY|O_NONBLOCK)`), configures it at `:498`, then
  upgrades to a websocket at `:509–510` and pumps both directions.
- `kvmd/apps/kvmd/api/serial.py:412` — `GET /serial/check` is the same primitive
  as a pre-flight: the identical one-rule path check at `:432–433`, then
  `os.open` at `:437`, `_configure_serial` at `:438`, close in `finally` at
  `:444–449`.

**Kind.** Device operation.

**Port-scopable.** No — serial is a device-global resource here, unrelated to the
HDMI/USB mux. `/serial/list` (`:401`) enumerates external USB serial adapters
(`_scan_external_serial`, `:355–372`), which is a *different* set of devices from
what `/serial/ws` will open.

**Consequence.** disruptive — a serial console is a root shell on most targets,
and on a BMC or a switch it is the management plane itself.

**Constraints implied.** `requires_presence`, because of the finding below:
`serial` is not a peer of `atx.*`, it **dominates** them.

**1:1 note.** `serial` is **not a single operation** — see §4.4.

**BYPASS RISK — two, one of them the inverse of the usual concern:**
1. **`serial` is itself the bypass for `atx.*`.** `/serial/ws?dev=/dev/ttyACM0`
   reaches the ATX relay (`glatx.py:17`). The path validation is `startswith
   ("/dev/")` and nothing else (`serial.py:480–481`); the driver-based filtering
   in `_is_external_serial` applies only to the `/serial/list` enumeration
   (`serial.py:361–371`), never to what `/serial/ws` will open. Any character
   device the kvmd process can open is reachable: the ATX relay, the cellular
   modem, `/dev/mem`-adjacent character devices, anything.
2. **`POST /modem/at`** (`kvmd/apps/kvmd/api/modem.py:104`) passes an arbitrary
   `AT` string to `ubus_call_async("modem", "at", ...)` (`:117`) — a second,
   narrower arbitrary-command channel to a serial-attached device.

**No other parallel serial path found** — searched `ttyS[0-9]\|ttyACM` across
`kvmd/` (6 hits, all accounted for above) and `exposed_http.*serial` in
`kvmd/apps/kvmd/api/`.

---

### 2.10 `plugin.install` — management

**Operation on the device: absent.** Searched `exposed_http` intersected with
`install|plugin|extension|addon` across `/home/user/glkvm-debloat/kvmd/` —
**no matches**. `kvmd/plugins/` (atx, auth, hid, msd, ugpio) is a *build-time*
plugin namespace resolved by config (`get_hid_class` etc. at
`kvmd/apps/kvmd/__init__.py:84`), with no runtime install path.

**Nearest real operation** — and what a device-plugin push would necessarily
resemble — is firmware upload:
- `kvmd/apps/kvmd/api/upgrade.py:665` — `POST /upgrade/upload`, multipart, writes
  to a fixed path regardless of the client's filename (`:686–695`).
- `kvmd/apps/kvmd/api/upgrade.py:721` — `POST /upgrade/start`, then
  `__delayed_reboot` (`:772–775`).

**Kind.** Management operation.

**Port-scopable.** No.

**Consequence.** **boot-media** — strictly, whole-device code replacement.

**Constraints implied.** four-eyes, unconditionally. This is the capability whose
misuse is unrecoverable without physical access.

**BYPASS RISK — two:**
1. **`skip_verify`.** `POST /upgrade/start?skip_verify=1`
   (`upgrade.py:729–731`) sets `should_skip_verify`, and at `:742–743` the
   **signature check is skipped entirely** with only a log warning
   (`"Skipping firmware signature verification as requested"`). Only the
   structural `validate_firmware()` still runs (`:751`). A signed-artifact policy
   that any authenticated caller can turn off with a query parameter is not a
   policy. *This is directly relevant to item 2 (Signer/TrustStore) and item 5
   (Plugins): the lesson is that verification must not be a caller-supplied
   option.* Additionally `self.__model == "rmq1"` short-circuits the whole check
   block at `:734–735`.
2. **`GET /upgrade/reset_default`** (`upgrade.py:781`) runs
   `/usr/sbin/reset_default.sh` (`:792`) — factory reset, i.e. removal of
   whatever kazbek installed, from a **GET**.

---

### 2.11 `iso.mount` — management

**Operation.** Get an image into the device's storage and select it. This is the
staging half of what `msd.mount` then attaches.

**Enforcement points.**
- `kvmd/apps/kvmd/api/msd.py:219` — `POST /msd/write` (upload). nginx gives it a
  dedicated `location` with `auth_request off` at
  `configs/nginx/kvmd.ctx-server.conf:91–98`.
- `kvmd/apps/kvmd/api/msd.py:248` — `POST /msd/write_remote?url=` — **the device
  fetches a URL itself** (`htclient.download` at `:265`), with
  `insecure=` disabling TLS verification (`:252`, passed as `verify=(not insecure)`
  at `:267`). Own nginx `location`, `auth_request off`,
  `kvmd.ctx-server.conf:81–89`.
- `kvmd/apps/kvmd/api/msd.py:78` — `POST /msd/set_params?image=` (select).
- `kvmd/apps/kvmd/api/msd.py:327` — `POST /msd/remove`.

**Kind.** Management operation *(with a device-side effect: it consumes device
storage and, via `write_remote`, makes the device an HTTP client of an
operator-chosen origin).*

**Port-scopable.** No — one image store.

**Consequence.** **boot-media, deferred.** An uploaded ISO is inert until
`msd.mount` attaches it, but treating `iso.mount` as merely "file management" is
the mistake: the two capabilities compose into arbitrary code on the target, and
granting them to the same subject is equivalent to granting `msd.mount` with
attacker-chosen content.

**Constraints implied.** four-eyes on `write_remote` specifically (it is an SSRF
primitive: the device fetches an operator-supplied URL from *inside* the
management segment, and `insecure=1` strips TLS verification). A `time_window` on
uploads is weak but cheap.

**BYPASS RISK — two:**
1. **`GET /msd/read`** (`api/msd.py:171`) is the read direction — it streams an
   image *out*, with optional lzma/zstd compression (`:174–178`). Its own nginx
   `location` with `auth_request off` and a 7-day read timeout
   (`kvmd.ctx-server.conf:71–79`). Relevant because the MSD store is also where
   `/recorder` writes session recordings (`api/recorder.py` takes `msd: BaseMsd`
   at `:53`), so `/msd/read` is an exfiltration path for recorded console video.
2. **`GET /msd/partition_format?path=`** (`api/msd.py:159`) formats a partition
   — a destructive management op on the same subsystem, reachable via **GET**.

---

### 2.12 `device.admin` — management

**Operation: not one operation. A residual bucket of roughly ninety routes.**
Counted from the working tree, the routes that are neither a console operation
nor media handling include, at minimum:

| area | representative routes (file:line) |
|---|---|
| system config | `api/system.py:829` `set_param`, `:1458` `set_config`, `:1506` `set_firewall_config`, `:1581` `set_hostname`, `:526` `set_network_config` |
| credentials on the device | `api/system.py:1672` `POST /system/ssh_key`, `:2116` `POST /system/ssl_cert`, `api/init.py:92` `change_password`, `api/twofa.py:42,94` 2FA create/delete |
| time | `api/system.py:1235` `POST /system/time`, `:1398` timezone, `:2499` `POST /system/ntp` |
| USB gadget shape | `api/system.py:998` `otg_functions`, `:2441` `reinit_udc` |
| firmware | `api/upgrade.py:665,716,721,781,851` (upload / reboot / start / factory reset / EDID flash) |
| session control | `api/system.py:243` `DELETE /system/clients/{client_id}` |
| **remote-access fabric** | `api/tailscale.py:262,293,590`; `api/zerotier.py:219,255,289`; `api/netbird.py:175,208,244,328`; `api/cloudflare.py:86,147`; `api/astrowarp.py:95,134` |
| radio / network exposure | `api/ap.py:73`, `api/repeater.py:85,123`, `api/rndis.py:27`, `api/modem.py:73,104` |
| physical indicators | `api/custom_screen.py:162,259` (front-panel screen content) |

**Kind.** Management.

**Port-scopable.** No.

**Consequence.** **boot-media** at the top of the range (`/upgrade/start`), and
several routes are *worse than boot-media in effect*:
`GET /astrowarp/enable?enable=true` (`api/astrowarp.py:95`) rewrites
`ASTROWARP_CONFIG_PATH` and restarts the GL cloud agent (`:104–105`), re-binding
the device to the vendor cloud — the exact trust inversion D-002/D-003 exist to
remove. `POST /tailscale/start`, `/zerotier/start`, `/netbird/start` and
`/cloudflare/start` each attach the device to a new overlay network from a single
authenticated request.

**Constraints implied.** four-eyes on the fabric-changing and firmware subsets.

**1:1 note.** `device.admin` is **not a single operation** — see §4.5.

**BYPASS RISK.** The dominant one is structural rather than a specific route:
`allowed_exe_paths` creates **paired routes** that skip authentication entirely.
`_check_exe_path` (`api/auth.py:146–159`) returns true — and
`check_request_auth` returns immediately (`auth.py:163–164`) — for any request
whose peer `/proc/<pid>/exe` matches, **before** any token check. The pairs found:

```
/system/get_param        ↔ /system/gui_get_param        (system.py:785  / :824)
/system/set_param        ↔ /system/gui_set_param        (system.py:829  / :952)
/tailscale/{start,stop,config,status,login_url,login_status,logout}
                         ↔ /tailscale/gui_*             (tailscale.py:210,289,320,401,490,525,712,731)
/zerotier/{start,stop,set_token,leave,auth,status}
                         ↔ /zerotier/gui_*              (zerotier.py:215,250,285,361,438,461)
/netbird/{start,stop,login,logout,config,get_info}
                         ↔ /netbird/gui_*               (netbird.py:204,240,290,308,324,372,459)
/upgrade/compare         ↔ /upgrade/gui_compare         (upgrade.py:697 / :702)
/system/clients          — exe-only                     (system.py:163)
DELETE /system/clients/{id} — exe-only                  (system.py:243)
/auth/two_step_{pending,approve,reject,login}           (auth.py:287,295,310,325,332)
```

Every `gui_*` route is a full-privilege duplicate of an admin route reachable by
any local process that can (a) connect to `/run/kvmd/kvmd.sock` and (b) present
the right `/proc/<pid>/exe`. **Note especially `/auth/two_step_approve`
(`auth.py:295`, `auth_required=False`): the device's own two-step approval — the
firmware's nearest thing to a presence ceremony — is granted by a local process
identity, not by a human.** If kazbek's `requires_presence` is ever implemented
on top of that mechanism, this is where it fails.

---

## 3. Bypass-risk index (one line each)

| # | capability(s) | parallel path | why it evades the obvious check |
|---|---|---|---|
| B1 | `view`, `screenshot` | `GET /streamer/*` via nginx `kvmd.ctx-server.conf:118` | never reaches kvmd; only gate is session-cookie validity |
| B2 | `view`, `hid.input` | `gl_webrtc=1` → `webrtc_client` (`server.py:507,294,361`) + gl-pion `/hid/ws` (`server.py:578`) | media and input leave via WebRTC; kvmd mediates neither |
| B3 | `view`, `hid.input` | kvmd-vnc TCP 5900 (`vnc/server.py:348`) | separate credential; vncpass yields an **empty-user** kvmd session |
| B4 | `atx.*` | `/serial/ws?dev=/dev/ttyACM0` (`serial.py:452,480`) | `serial` reaches the ATX relay device directly |
| B5 | `atx.*` | Redfish `ComputerSystem.Reset` (`redfish.py:125,57–64`) | second route into the same `BaseAtx` object |
| B6 | `atx.*` | IPMI chassis control (`ipmi/server.py:148`) | different protocol, different password file, UDP 623 |
| B7 | `atx.soft`, `atx.hard` | fingerbot (`fingerbot.py:229,268,302`) | a physical finger; no capability covers it at all |
| B8 | `msd.mount`, `hid.input` | `POST /system/otg_functions` (`system.py:998,960–969`) | links/unlinks the gadget functions under the plugins |
| B9 | `msd.mount` | `/msd/partition_connect` (`msd.py:120`) | a second attach mechanism, not `set_connected` |
| B10 | `plugin.install` | `?skip_verify=1` (`upgrade.py:729–743`) | signature verification is a caller-supplied option |
| B11 | `screenshot` | `?load=true` (`streamer.py:429–430`) | serves a cached frame with no hardware access or freshness check |
| B12 | `screenshot` | `?ocr=true` (`api/streamer.py:62–79`) | returns screen *text*, sidestepping any image-shaped policy |
| B13 | `device.admin` | `gui_*` / `allowed_exe_paths` pairs (`auth.py:146–164`) | peer-exe identity returns **before** any token check |
| B14 | **port scope, all caps** | VNC magic chord (`vnc/server.py:361,367,373`), localhid magic chord (`localhid/server.py:169,174,179`) | a *keystroke inside the session* switches the mux to another port |
| B15 | `view`, `screenshot` | memsink / janus h264 sink (`clients/streamer.py:247`, `configs/janus/janus.plugin.ustreamer.jcfg`) | shared memory, no HTTP, no auth |

---

## 4. Where the spec's 1:1 claim fails

`permissions.md:15–16` says a capability "maps 1:1 to an enforceable device
operation." Five of the twelve do not. These are findings the spec needs, not
things to paper over.

### 4.1 Port scope is not a partition of anything — it is a mode of one device

**The most consequential finding.** D-009 says scope may be "a **port** on a
multi-channel device," and `permissions.md:44` tests that "a grant on port 1 does
not reach port 3." On the rm4pe as implemented, **there is nothing to reach**:
one HDMI capture, one USB gadget, selected by writing one sysfs file
(`switch/sysfs_device.py:30–31`, written at `:396`). Ports are a *time
multiplex*, not four addressable devices.

Three concrete consequences:

- **A per-port grant cannot be enforced by endpoint filtering** — there is no
  per-port endpoint to filter. It can only be enforced as an **interlock**: the
  session's grant must be checked against the *currently active channel*, and
  the connection torn down when the channel changes out from under it. That is a
  different mechanism from what the spec describes, and it is stateful.
- **`/switch/set_active` is the real port-scope boundary and has no capability.**
  `POST /switch/set_active` (`api/switch.py:66`), `set_active_prev` (`:56`),
  `set_active_next` (`:61`). Whoever can call these controls which host every
  video and HID path is attached to. Not in the capability list. See §5.
- **The mux can be moved from inside a session by a keystroke.** VNC:
  `MagicHandler` at `vnc/server.py:134–143` binds arrow keys and digits to
  `__on_magic_switch_prev/next/port` (`:361,367,373`), which call
  `switch.set_active_prev/next/set_active` (`:365,371,385`). kvmd-localhid does
  the same at `localhid/server.py:70–75,169,174,179`. **A subject granted
  `view`+`hid.input` on port 1 can type their way to port 3.** No API call, no
  route to gate, no audit entry beyond a log line.

**Recommendation:** either add a `port.switch` capability and make the interlock
explicit, or state in the spec that port scope on this hardware is advisory
until the interlock exists — do not ship the D-009 test as written, because it
tests a partition that the hardware does not have.

### 4.2 `screen.control` is not an operation

See §2.4. It has no firmware referent (`grep -rn "screen.control\|screen_control"
--include=*.py /home/user/glkvm-debloat/kvmd/` → absent) and is satisfiable only
as the conjunction of `view` and `hid.input`. Restate it as the enforcement rule
in `permissions.md:26–30` and remove it from the capability list.

### 4.3 `msd.mount` is at least three operations

Attaching virtual media requires `set_params?image=` (`api/msd.py:78`) **plus**
`set_connected` (`:92`); a whole-partition attach is a *different* mechanism
(`partition_connect`, `:120`); and the gadget function itself can be linked and
unlinked out from under both (`system.py:998`). A single capability name over
these is fine as a *policy* grouping, but the enforcement point is not one place
— it is a set, and every member needs the check.

### 4.4 `serial` is not "the serial console"

`/serial/ws` opens **any path under `/dev/`** (`serial.py:465,480–481`). The
capability as granted is "open and drive an arbitrary character device as the
kvmd user," which includes the ATX relay (`glatx.py:17`). Either the spec
narrows `serial` to an allowlist of device paths — which the firmware does not
currently provide and kazbek would have to impose at the tunnel — or the model
must record that `serial` **dominates** `atx.soft`, `atx.hard` and `atx.reset`,
and that granting it silently voids their constraints.

### 4.5 `device.admin` is ~90 operations in a trench coat

§2.12. Everything from "set the NTP server" to "flash unsigned firmware" to
"re-bind this device to the vendor cloud" lands in one grant. It needs at
minimum a split along the consequence boundary — a `device.config` (reversible /
disruptive) versus a `device.trust` (boot-media: firmware, ssl_cert, ssh_key,
overlay-network enrolment, astrowarp bind, factory reset). Four-eyes on the
whole of `device.admin` will be turned off; four-eyes on `device.trust` will
survive.

---

## 5. Gap list — device operations with no capability that arguably need one

Ordered by consequence. Every row was read in the tree.

| operation | file:line | consequence | why it needs a capability |
|---|---|---|---|
| **switch the active port** | `api/switch.py:56,61,66` | disruptive | **The port-scope boundary itself.** Ungated, every per-port grant is advisory (§4.1). |
| **`atx.power` = power ON** | `api/atx.py:52` (`"on": self.__atx.power_on`) | disruptive | `atx.soft/hard/reset` cover only *off* and *reset*. Powering a host **on** is a real act (a host deliberately kept down; a compromised host returned to the network) and no capability names it. |
| **fingerbot physical press** | `api/fingerbot.py:229,268,302` | disruptive | A BLE actuator that physically presses the target's power button — the same outcome as `atx.*` by a path no ATX capability touches. Also `POST /fingerbot/upgrade` (`:414`) flashes its firmware. |
| **firmware flash** | `api/upgrade.py:665,721` | boot-media | Currently swept into `device.admin`. Deserves its own name, and `skip_verify` (`:729–743`) must not exist. |
| **factory reset** | `api/upgrade.py:781,792` | boot-media | Removes kazbek's own enrolment. Reachable via **GET**. |
| **EDID flash** | `api/upgrade.py:851` and `/switch/edids/*` (`api/switch.py:125,132,147`) | disruptive | Changes what resolutions the target believes exist; a wrong EDID makes a host headless-unusable. |
| **overlay-network enrolment** | `api/tailscale.py:262`; `api/zerotier.py:219,289`; `api/netbird.py:175,244`; `api/cloudflare.py:86,147`; `api/astrowarp.py:95,134` | boot-media (trust) | Each attaches the device to a new network or re-binds it to the vendor cloud. Directly contradicts the D-002/D-003 trust model if ungated. |
| **on-device credential change** | `api/system.py:1672` (ssh_key), `:2116` (ssl_cert), `api/init.py:92` (password), `api/twofa.py:42,94` | boot-media (trust) | Changes who can reach the device out of band. |
| **kill another user's session** | `api/system.py:243` | disruptive | Session control is an authorization act; today it is exe-path-gated only. |
| **OTG gadget shape** | `api/system.py:998`, `:2441` | boot-media | Links/unlinks mass-storage and HID functions beneath both `msd.mount` and `hid.input` (B8). |
| **MSD partition format** | `api/msd.py:159` | disruptive (destructive) | Destroys the image store. Via **GET**. |
| **MSD image read-out** | `api/msd.py:171` | reversible (exfiltration) | Streams images — and, since `/recorder` writes into MSD storage (`api/recorder.py:53`), recorded console video — off the device. |
| **session recording** | `api/recorder.py:177,184` | reversible (privacy) | Records the console to a file. A recording capability is *not* `screenshot`: it persists, and it survives the grant. |
| **bulk keystroke paste** | `api/hid.py:169` | disruptive | `/hid/print` types an arbitrary body. Materially different from interactive `hid.input`; deserves its own constraint even if it shares the name. |
| **arbitrary modem AT** | `api/modem.py:104` | disruptive | Arbitrary command channel to the cellular modem. |
| **user GPIO** | `api/ugpio.py:47,55` | depends on wiring | `/gpio/switch` and `/gpio/pulse` drive whatever the operator wired — commonly a power relay. Consequence class is set by the deployment, which is itself an argument for a capability. |
| **Wake-on-LAN** | `api/wol.py:136` | disruptive | Powers on an arbitrary MAC on the segment — a power operation on hosts this KVM is not even attached to. |
| **front-panel screen** | `api/custom_screen.py:162,236,259` | reversible (physical) | Controls what a person standing at the rack sees. If `requires_presence` is ever implemented via the device's screen, this route can lie to the human performing the ceremony. |
| **stream parameter / mode change** | `server.py:507,536` | reversible | `gl_webrtc` flips the entire media path (B2). Not a "setting". |
| **AP / repeater / RNDIS** | `api/ap.py:73`, `api/repeater.py:85,123`, `api/rndis.py:27` | disruptive | Each changes the device's network exposure. |

---

## 6. What this implies for the module (short)

1. **Enforce below plane B.** `check_request_auth` (`api/auth.py:162–171`) is the
   only chokepoint kvmd has and it is binary. Any capability check kazbek adds
   *inside* kvmd is bypassed by B1, B2, B3, B6, B15 — all of which never enter
   kvmd. The enforcement point has to be the kazbek-side tunnel, and the tunnel
   has to be the *only* way to reach the device. That is a statement about
   network isolation as much as about code, and it matches THREAT-MODEL's
   "management segment isolation is load-bearing."
2. **Test at the parallel path, not the primary one.** For each capability the
   mutation test (AGENTS.md rule 4) should exercise the *bypass* route: fetch
   `/streamer/stream` for `view`; `POST /hid/events/send_key` for `hid.input`;
   `/redfish/.../ComputerSystem.Reset` for `atx.hard`; `/serial/ws?dev=/dev/ttyACM0`
   for the `serial`-dominates-`atx` case; `/system/otg_functions` for
   `msd.mount`. A test that only exercises the documented route proves nothing.
3. **The `gui_*` / `allowed_exe_paths` surface (B13) is a trust-boundary
   question, not a permissions question.** It should be raised as a stop-and-report
   design step (AGENTS.md rule 10), not absorbed into this module.

---

## 7. Provenance

Files opened and read in `/home/user/glkvm-debloat` while producing this
document:

```
configs/nginx/kvmd.ctx-server.conf     configs/nginx/kvmd.ctx-http.conf
configs/nginx/loc-proxy.conf           configs/nginx/loc-login.conf
configs/janus/janus.plugin.ustreamer.jcfg
kvmd/htserver.py                       kvmd/clients/streamer.py
kvmd/apps/__init__.py                  kvmd/apps/kvmd/__init__.py
kvmd/apps/kvmd/server.py               kvmd/apps/kvmd/streamer.py
kvmd/apps/kvmd/api/auth.py             kvmd/apps/kvmd/api/atx.py
kvmd/apps/kvmd/api/streamer.py         kvmd/apps/kvmd/api/hid.py
kvmd/apps/kvmd/api/msd.py              kvmd/apps/kvmd/api/serial.py
kvmd/apps/kvmd/api/switch.py           kvmd/apps/kvmd/api/redfish.py
kvmd/apps/kvmd/api/ugpio.py            kvmd/apps/kvmd/api/recorder.py
kvmd/apps/kvmd/api/wol.py              kvmd/apps/kvmd/api/fingerbot.py
kvmd/apps/kvmd/api/system.py           kvmd/apps/kvmd/api/upgrade.py
kvmd/apps/kvmd/api/modem.py            kvmd/apps/kvmd/api/astrowarp.py
kvmd/apps/kvmd/api/turn.py
kvmd/apps/kvmd/switch/__init__.py      kvmd/apps/kvmd/switch/sysfs_chain.py
kvmd/apps/kvmd/switch/sysfs_device.py
kvmd/plugins/atx/glatx.py              kvmd/plugins/msd/otg/__init__.py
kvmd/plugins/msd/otg/drive.py
kvmd/apps/vnc/server.py                kvmd/apps/vnc/__init__.py
kvmd/apps/ipmi/server.py               kvmd/apps/localhid/server.py
kvmd/apps/media/server.py              kvmd/apps/media/__init__.py
web/share/js/kvm/stream_mjpeg.js
setup.py  PKGBUILD  kvmd.install  apply_to_glkvm.sh  configs/os/services/
```

**Deployment caveats, stated because they bound several claims above.**
- `configs/os/services/` contains systemd units including `kvmd-vnc.service` and
  `kvmd-ipmi.service`; `kvmd.install` does not enable or mask either. The GLKVM
  target, however, uses busybox init — the tree references `/etc/init.d/S99rkipc`
  (`switch/sysfs_device.py:469,483`), `/etc/init.d/S99gl-pion`
  (`api/system.py:320`), `/etc/init.d/S99tailscale` (`api/tailscale.py:272`) —
  and `apply_to_glkvm.sh` deploys only the Python package. **Whether kvmd-vnc and
  kvmd-ipmi run on a given GLKVM is a deployment fact this tree cannot settle.**
  Treat B3 and B6 as present-unless-proven-absent, per AGENTS.md rule 8.
- `kvmd-localhid` and `kvmd-media` have **no** `console_scripts` entry in
  `setup.py:116–136` and no unit in `configs/os/services/` — the code ships
  uninstalled. B15's kvmd-media leg is therefore latent, not live; the janus
  memsink leg is live (`kvmd-janus.service` ships).
- `webrtc_client`, `gl-pion`, `atxpower`, `fingerbot`, `reset_default.sh`,
  `kvmd-otgconf` and `ustreamer` are **binaries outside this tree**. Their
  behaviour is inferred from their invocation sites only, which are cited. Under
  the THREAT-MODEL's "closed upstream userland is not audited by kazbek" caveat,
  every one of them is a place where an enforcement assumption can be wrong.
