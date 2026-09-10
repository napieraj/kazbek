# AGENTS.md — how work is done in this repo

This carries the working discipline from the `glkvm-debloat` build into kazbek.
It applies to every agent and every human. `CLAUDE.md` is a symlink to this.

## Naming convention
The project name is **kazbek**, always lowercase — including sentence-start
(like `git`, `kubectl`). Binary, module path, command, and prose all lowercase.
Do not capitalize it. Fix any inherited "kazbek" to "kazbek".

## The repo in one line
kazbek: self-hosted, modular fleet management for GLKVM/PiKVM devices. A small
trusted core (pinned-mTLS device connection + identity + module loader) plus
opt-in modules. Fork of `glkvm-cloud`; keep the management plane, replace the
device-trust core.

## Standing rules — non-negotiable

1. **Re-derive before trusting.** Line numbers, counts, and any statement in a
   doc or plan are stale until checked against the working tree. This applies to
   *these instructions* too — if a number here disagrees with the code, the code
   is right. Measure; never assert a number you didn't just check.

2. **Full environment only.** A partial test environment gives a FALSE green —
   on the firmware side, 9 real divergences hid behind missing config until the
   full container was reconstructed. "Passes" against an incomplete env proves
   nothing. State which env a pass was on.

3. **One commit per logical change.** Descriptive message saying *why*. A guard
   or smoke check green after each. Don't batch unrelated changes.

4. **Mutation-check silent-if-missed checks.** A security check that no test
   fails-on-removal is not verified — it might be dead. For each check that would
   fail silently if wrong, write a test and confirm it goes red when the check is
   removed. (This is how the firmware WebAuthn work found that the password path
   was structurally un-smuggleable, and caught the purpose-confusion bug.)

5. **Gut, not mask.** For code we own, remove unused features — don't disable
   them. Presence is a security property. Mask only closed upstream services a
   removal orphans.

6. **Modules declare their mode and dependency.** Every module states
   local-only / cloud-managed / both, and which core interface it registers
   against. It must not reach past its interface into the core, and must not load
   when disabled.

7. **Document non-obvious constraints where someone would undo them.** A
   comment at the code, not only in a design doc. (E.g. "per-device origin pin —
   do NOT relax to suffix matching, it's the only relay defense.")

8. **Verify as code, not as doc.** A safeguard described in a design doc but not
   present in the code is not a safeguard. Confirm guards exist and fire.

9. **Measure the sum, not the file.** When moving code between files, a single
   file's diff misleads — track the total. (Moving the identity helpers made one
   file diverge more and another less; the sum shrank.)

10. **Stop-and-report at design steps.** Mechanical work proceeds; a design
    decision (a new module's shape, a trust-boundary change, the first PR of a
    research-grade item) stops for review. Don't land a design step unreviewed.

## Where to look
- `docs/ARCHITECTURE.md` — core + modules, the boundary, the connection swap.
- `docs/DECISIONS.md` — settled calls; read before proposing a change to one.
- `docs/THREAT-MODEL.md` — the diode principle and per-adversary yields.
- `docs/ROADMAP.md` — the dependency-sequenced plan; items are cycles, not tasks.
- `docs/modules/` — one spec per module, mode + interface + tests.

## Build hazards recorded (don't rediscover)
- A non-zero-exiting linter in an `&&` chain short-circuits what follows — use
  `;`. (Bit the firmware build twice; once lost a working tree to a stash.)
- A local lint run is not a dead-code check — dead functions need the full tool
  (vulture/equivalent), not flake8-style import checks.

## The first work
Item 0 in the roadmap: fork, rebrand, and the device-auth swap (shared token →
pinned mutual TLS). It's contained (~100 lines behind a clean `net.Conn` seam);
the entire management plane above the seam is inherited. See ARCHITECTURE for the
exact swap and the tests it needs.
