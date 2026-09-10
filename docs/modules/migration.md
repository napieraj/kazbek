# Module: migration (stock device → glkvm-debloat)

**Mode:** both (local operator action; kazbek assists)
**Core dependency:** provisioning (issues the new pinned cert post-flash),
`TrustStore`, the audit contract tests
**Status:** planned (late roadmap item — RESEARCH-GRADE)

## Purpose
Adopt a stock PiKVM/GLKVM device and convert it to the trusted tier by flashing
`glkvm-debloat`. This is *no-frills adoption*: point kazbek at a stock device,
it onboards and migrates it, and the device comes out pinned and hardened.

## Framing: this is administration, not exploitation
The stock GLKVM grants root to the local network **by design** — the browser
web-shell (`ttyd`) is a shipped feature, and U-Boot failsafe flashes any image
with no signature check (GL's own docs: "you can upload whatever you want").
Using these sanctioned access paths to install better firmware is device
administration, the same as `apply_to_glkvm.sh`. It is not weaponizing a
memory-corruption bug. The one path that is genuinely a race (unauth `init`
claim before the owner sets a password) is carved out below for isolated-network
handling.

## The rootkit problem
A stock device adopted from unknown provenance may already be compromised, and
**you cannot trust the compromised OS to report its own compromise** — a rootkit
hides from the queries you'd run. Therefore: **do not detect, overwrite.** Flash
from below the running OS and attest the result. The device's history determines
how deep you flash.

## Three migration paths — cleanest first

### 1. U-Boot failsafe (PREFERRED for unknown-provenance devices)
Physical Reset+power → U-Boot web UI at a fixed address (`192.168.1.1`, client
`192.168.1.2/24`, direct Ethernet). Flashes firmware **from the bootloader,
before the OS boots** — so any rootfs/userland rootkit is not running and cannot
tamper with the flash. Requires **physical possession** (hold Reset while
powering on), which is the correct gate: it cannot be triggered remotely, so
this path is not a network attack.
- **Cleans:** rootfs / userland / OS-level implants.
- **Does NOT clean:** U-Boot itself. GL does not reflash the bootloader here
  ("we do not provide separate U-Boot upgrades"). A bootloader-level implant
  survives, and the failsafe flasher you're using *is* that (possibly
  compromised) U-Boot.

### 2. maskrom / rkdeveloptool (DEEPEST — for a suspected bootloader implant)
The Rockchip SoC boot ROM, below U-Boot. Writes the **full eMMC including the
bootloader partitions** — the only path that cleans a U-Boot-level implant.
Needs USB + physical access. Use when the threat model includes a compromised
bootloader.
- **Cleans:** everything on eMMC, boot chain included.
- **Does NOT clean:** peripheral controller firmware (eMMC/USB controller) —
  nation-state territory, out of scope, documented.

### 3. Root-shell / web-shell (CONVENIENCE — network, for TRUSTED devices only)
The sanctioned admin access, usable remotely. Fine for a device you know is
clean (fresh from GL, your own). But it flashes **through the running OS**, so a
rootkit could interfere or fake success. Use only when you accept that the device
isn't compromised.

## Config is not cleaned by a firmware flash
GL retains config across a flash unless a config error forced recovery. A rootkit
resident in *config* (a malicious cron entry, an `authorized_keys` line) can
survive a config-retaining flash. **Migration MUST force config to defaults / wipe
config**, not inherit it. "Firmware replaced" is not "config clean."

## Post-flash attestation (mandatory, any path)
Trust the outcome you can verify, never the pre-migration device's word:
1. Device presents its **new pinned cert** (issued by the provisioning module).
2. Passes the **audit contract tests**: no `ssh_key` route, no web-shell, no
   `init/init`, header-trust fixed, etc. — the vulnerable routes are gone.
3. **Read-back hash** matches the debloat image that was flashed.
4. Config confirmed at defaults (no inherited cron/keys).
Only then does the device transition legacy → trusted.

## The tier model this feeds
- `trusted` — pinned-mTLS, debloat firmware, full capabilities. The default and
  the security story.
- `legacy` — stock device over native auth, **opt-in** (`allow_legacy_devices`,
  off by default), **capped capabilities** (no `msd.mount` / boot-media / ceremony-
  gated actions), **visibly marked** unpinned in UI and audit. A legacy device
  does not have pinned-key trust; treat it as you'd treat the vendor cloud.
Migration is the path from legacy → trusted, and the one-liner's "pinned-key
trust as the floor" holds for the trusted tier because legacy is a documented,
capped, opt-in exception.

## Publish/disclose note
The root-shell path (3) is sanctioned access, not an exploit. The `init`-claim
race and any path that depends on a specific finding should be handled as
isolated-network-only and, if kazbek is public, sequenced after coordinated
disclosure to GL — so kazbek is not the vehicle that publishes a working
claim-race against unpatched devices. The U-Boot and maskrom paths are physical
recovery mechanisms and carry no such concern.

## Tests
- U-Boot failsafe flash from a simulated-compromised rootfs → post-flash
  contract tests pass, read-back matches, config at defaults
- config-resident implant (planted cron/key) does NOT survive migration
- root-shell path refused / warns for a device not marked trusted-provenance
- legacy tier caps: a legacy device cannot be granted msd.mount / boot-media
- post-flash tier transition only on full attestation success
