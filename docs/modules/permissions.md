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
  `view`, `screenshot`, `screen.control`, `hid.input`,
  `atx.soft`, `atx.hard`, `atx.reset`, `msd.mount`, `serial`, plus management
  capabilities (`plugin.install`, `iso.mount`, `device.admin`).
- **scope:** device | device-group | **port** (a channel on a Comet X).
- **constraints:** `requires_presence` (ceremony tap), `time_window`, approval
  (four-eyes) — for high-consequence capabilities (`atx.hard`, `msd.mount`).

Effective capabilities = union of group grants + direct grants, minus explicit
denies.

## Enforcement — the load-bearing rule
Enforce at the **tunnel/stream layer, not the UI.** A session that lacks
`screen.control` must get a connection that physically cannot carry the video
stream or HID — not merely a hidden button. (The firmware `/streamer`-bypasses-
the-API finding is the warning: hiding a control is not enforcing a permission.)

## Threat model delta
Bounds what a *granted* subject can do; does not bound intent. A trusted operator
is trusted — constraints add presence/approval for the dangerous few.

## Design notes
Check GL's `glkvm-cloud` `policy-engine` and KVM Fleet's (Apache-2.0) constraint
engine (time-of-day / require-MFA / max-sessions / approval) before writing one —
adopt if they fit.

## Tests
- capability check allows/denies correctly per grant/scope
- port scope enforced on a Comet X (grant on port 1 does not reach port 3)
- **stream-layer enforcement**: a session without `screen.control` cannot pull
  video even by hitting the stream endpoint directly (the bypass test)
- constraint: `requires_presence` blocks without the ceremony; `time_window`
  outside hours denies; approval pends
