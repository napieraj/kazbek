# Licensing — measured, not assumed

**This is a statement of facts about files. It is not legal advice, and nobody
who wrote it is a lawyer. The questions it raises are flagged, not answered.**

## The headline: the encumbrance lands on the expensive part

The hypothesis was that `glkvm-cloud` is itself a fork, so GL's BUSL might
cover only GL's additions over a permissive base. **That is true as stated and
inverted in effect.** The permissive base is real — and it is the part kazbek
already plans to replace. The expensive inherited management plane that
justified forking at all is GL-original, and it is the encumbered part.

## What the licences actually say

**This tree:** `LICENSE` is **Business Source License 1.1**. Licensor GL.iNet;
Licensed Work "GLKVM Cloud"; Additional Use Grant limited to *"non-production
purposes, including development, testing, personal, or academic use"*; Change
Date **2030-01-01**, on which it becomes GPLv3 (`LICENSE:1`, `:12`, `:14`).

BUSL restricts **use**, not only distribution. "Self-hosted fleet management
running your actual fleet" is a production-use claim by any ordinary reading.
That is the exposure, and it is not cured by never distributing anything.

**The upstream-upstream:** `zhaojh329/rttys` is **MIT** (`Copyright (c) 2019
Jianhui Zhao`). Its licence history is 4 commits — GPLv3 (2018-01) → LGPL-2.1
(2018-03) → **MIT (2019-05)** → current text (2019-09) — so it was MIT at the
fork point and is MIT at HEAD. No relicensing hazard.

**Fork point:** rttys v5.2.0–v5.3.0, around 2025-07. Established by scoring
exact git-blob matches of GL's root commit against all 68 rttys tags (peak at
v5.3.0); GL's carried `RttysVersion` constant says `5.2.0`.

> Method note worth keeping: GL's import is a 240-file whole-tree re-commit
> with zero renames, so `git log --follow` is a **false oracle** across that
> boundary. All ancestry below was established by content diffing against an
> extracted upstream tree, not by history.

## The map (Go, 106 files / 15,079 lines)

| bucket | files | lines |
|---|---|---|
| inherited from rttys, byte-identical | 2 | 144 |
| inherited from rttys, modified by GL | 13 | 3,380 |
| ambiguous (2 tiny files, flagged) | 2 | 20 |
| **GL-original** | **79** | **8,653** |
| kazbek-original (`internal/authz/fixtures/`) | 10 | 2,882 |

**Only ~23% of Go lines trace to MIT rttys**, and all of it sits in
`internal/server/`, `log/`, `utils/utils.go`, `xconfig/config.go`.

## Why that is the wrong 23%

`docs/DECISIONS.md` D-001 justifies forking because the management plane —
domain model, OIDC/LDAP, RBAC bones, groups, audit, notifications, UI — is
weeks of work unrelated to the connection model. **None of it comes from
rttys.** Zero rttys ancestry in `internal/domain/` (22 files / 1,157 lines),
`internal/http/` (25 / 2,550), `internal/store/` (14 / 2,321), `internal/pkg/`
(6 / 687), `internal/server/oidc.go` (524), or `model/`. rttys has no
persistence, RBAC, LDAP, OIDC or audit layer at all — its `user.go` is a
websocket terminal peer and its auth is a plaintext password comparison.

The UI is the same shape: 120 of 126 files and 12,862 of 14,350 lines are GL's,
imported from a separate GL frontend project (100 files carry GL author tags;
35 lines still reference `/kvm-cloud-frontend/`). Only the 6-file terminal
widget (1,488 lines) descends from rttys.

**So D-001's technical premise survives and its licence position does not.**
The `net.Conn` seam that roadmap item 0 swaps sits entirely inside the
MIT-inherited files — kazbek's own first work is on the clean part. Everything
D-001 called expensive is BUSL.

## The factual conflict, flagged not adjudicated

Nine Go files carry the **verbatim MIT grant naming Jianhui Zhao** inside a
repository whose LICENSE is BUSL-1.1:

```
internal/server/{api,command,device,http,rttys_stress_test,server,user}.go
utils/utils.go
xconfig/config.go
```

Separately, MIT attribution appears to have been **stripped** from four files
derived from rttys's `main.go`: `internal/server/{boot,panic,version}.go` and
`cmd/glkvm-cloud/main.go`.

Questions for someone qualified — deliberately not answered here: whether GL
could place BUSL terms over MIT-licensed files it did not author; what MIT's
notice-retention condition means for the four stripped files; and what any of
it implies for a downstream production deployment.

## Also unaudited

- `gl-web-main@1.0.2` is imported by 55 UI source files, has **`license: null`
  on npm**, no repository, and no LICENSE text anywhere in this tree.
- `ui/node_modules` is absent, so the wider npm licence surface is unmeasured.
- Zero SPDX headers anywhere in the tree.

## The options, and what each costs

1. **Ask GL for a grant.** Cheapest if it works. Nothing else is blocked while
   asking.
2. **Wait for 2030-01-01.** The Change Date converts everything to GPLv3. Not a
   plan, but it bounds the problem.
3. **Reopen D-001.** Note precisely what this means: the fork was justified by
   inheriting the management plane, and the management plane is the encumbered
   part. The BUSL finding does not weaken the *technical* argument for forking —
   the seam really is thin, the plane really is weeks of work — it attacks its
   premise from a different side. A clean-room management plane over the
   MIT-traceable transport is a different project than the one D-001 approved.

**No decision is recorded here.** `docs/DECISIONS.md` deliberately carries no
licence entry until one is taken — asserting an answer we have not established
would be the "verify as code, not as doc" failure the standing rules warn
about.

## Consequence for the README

The drafted kazbek README says *"GPLv3, inherited from `glkvm-cloud`."* That is
**wrong** and must not land: GPLv3 is the upstream's licence from 2030, not
now. The tree's current `README.md` is still upstream's and makes no licence
claim, so there is nothing to correct in place — but the line must be fixed
before the rebrand (roadmap item 0) lands it.
