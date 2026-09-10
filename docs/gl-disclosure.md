# Coordinated disclosure to GL.iNet — draft

**Status:** draft, not sent. Findings below were measured against public
repositories (`gl-inet/glkvm-cloud` at v2.8.0, and the GLKVM kvmd tree). None
required a device, an account, or any access that was not already public.

Two reasons to send this together rather than piecemeal: the findings share
root causes, and a single coordinated report is also the natural moment to ask
about the licence (§5) — which is a request, not a condition, and must not read
as leverage.

---

## 1. A working TLS private key is committed to the public repository

**Severity: high. Act on this one first — it needs revocation, not a patch.**

`docker-compose/certificate/glkvm.key` is a genuine 256-bit EC private key.
`docker-compose/certificate/glkvm.cer` is its matching **Let's Encrypt**
certificate for `CN = clanxie.life` (notBefore 2025-07-28, notAfter
2025-10-26). Both are world-readable in the public repo, and were introduced in
the repository's initial import.

They are not sample data. `docker-compose.yml:69-70` bind-mounts them to
`/home/certificate/glkvm_{cer,key}`, and `xconfig/config.go:121-122` hardcodes
exactly those paths as `SslCert` / `SslKey`. **The shipped default deployment
terminates TLS with a private key anyone can read out of the repository.**

- The certificate is expired, which bounds but does not undo the exposure.
- It was **findable before it was found**: the certificate is in Certificate
  Transparency logs, so the domain and validity window are a matter of public
  record and only the key needed retrieving.
- Whoever controls `clanxie.life` should **revoke**, and should treat the key
  as compromised for its whole validity window rather than rotating quietly.
- Removing the file from HEAD does not unpublish it — it remains in history.

We have removed both files downstream and replaced them with operator-supplied
material. We checked our history: this key appears once, against this one
certificate, with no reuse elsewhere.

## 2. `skip_verify` makes firmware signature verification caller-selectable

`POST /upgrade/start?skip_verify=1` skips signature verification with a log
warning:

```python
# kvmd/apps/kvmd/api/upgrade.py:729-743
if should_skip_verify:
    get_logger(0).warning("Skipping firmware signature verification as requested")
else:
    signature_result = await self.__update_engine.verify_firmware_signature()
```

Verification that the caller can switch off is not verification: whoever
reaches the route decides whether signatures matter. Suggested fix is removal
of the parameter and the branch. A genuine unsigned-image path for development
belongs behind a build flag or a physical path (the U-Boot failsafe flow
already requires physical possession), not a query string.

## 3. `serial` reaches the ATX relay, defeating power-control policy

`/serial/ws` accepts any path under `/dev/`; the entire check is:

```python
# kvmd/apps/kvmd/api/serial.py:480-481
if not dev.startswith("/dev/"):
    raise BadRequestError(f"Invalid device path: {dev}")
```

The ATX relay is `/dev/ttyACM0` (`kvmd/plugins/atx/glatx.py`). So serial access
**dominates** ATX power control: any policy applied to power actions is void
for anyone who can open a serial websocket. Suggested fix is an allowlist of
the device paths the product actually exposes.

## 4. The port mux can be moved without an API call

`kvmd-vnc`'s `MagicHandler` binds arrow keys and digits to port switching
(`kvmd/apps/vnc/server.py:134-143` → `:361,367,373`), calling
`switch.set_active_prev/next/set_active`; `kvmd-localhid` does the same
(`kvmd/apps/localhid/server.py:169,174,179`).

For GL this is a convenience feature. For anyone building per-port access
control on top — which the four-channel hardware invites — it means a user with
keyboard input on one port can reach another port with no request to authorize
and no audit record beyond a log line. Worth documenting prominently even if
the bindings stay.

Related: `/switch/set_active{,_prev,_next}` (`kvmd/apps/kvmd/api/switch.py:56,
61,66`) is the port boundary itself and is not distinguished from other
operations in the auth model.

## 5. A licence question (a request, not part of the report)

`glkvm-cloud`'s `LICENSE` is Business Source License 1.1 with an Additional Use
Grant limited to non-production use until 2030-01-01. We maintain a fork
(`kazbek`) that replaces the device-trust core with pinned mutual TLS and is
self-hosted by design, which appears to be production use under any ordinary
reading.

**We would like to ask whether GL would grant production use for self-hosted,
non-commercial deployments of derivative works.** We are asking, not asserting
an entitlement, and this request is independent of §§1-4 — those should be
fixed regardless of the answer, and we will not treat the two as linked.

Separately, and offered as an observation rather than a claim: nine Go files in
the repository carry a verbatim MIT grant naming Jianhui Zhao (`rttys`, the
upstream `glkvm-cloud` derives from) while the repository's `LICENSE` is
BUSL-1.1, and four further files derived from `rttys`'s `main.go` appear to
have had that attribution removed. We are not lawyers and are not asserting a
violation — we raise it because it is more easily resolved by GL than by anyone
downstream.

---

## Handling

Findings 2-4 are in shipped firmware and warrant an embargo before public
write-up. Finding 1 is different in kind — the material is already public and
the remedy is revocation — so it should go to GL immediately and separately if
that speeds it up.

Nothing here depends on the unauthenticated `init`-claim race described in
`docs/modules/migration.md`; that remains isolated-network-only and is
deliberately excluded from this report and from any public artifact.
