# Permissions — Phase 0 measurement (roadmap item 1)

**Status:** design step — stop-and-report per AGENTS.md rule 10.
**Environment:** `go1.24.7 linux/amd64`; tree at branch
`claude/glkvm-stock-debloat-migration-0pibl7`. Every number below was re-derived
against the working tree in this session (rule 1). Commands are given so they
can be re-run.

Phase 0 asks two questions: **is there an engine worth adopting**, and **does
the enforcement point the spec requires already exist**. The second turned out
to be the load-bearing one.

---

## 1. The inherited engine (GL's, via the fork)

`docs/modules/permissions.md` says to check GL's `policy-engine` before writing
one. kazbek *is* the fork of `glkvm-cloud`, so GL's engine is already in this
tree — it is not an external dependency to go fetch.

It is three files:

```
$ wc -l internal/domain/permission/model.go internal/domain/permission/service.go \
        internal/store/memory/permission_repo.go
  38 internal/domain/permission/model.go
  20 internal/domain/permission/service.go
  44 internal/store/memory/permission_repo.go
 102 total
```

What it is, precisely: a hardcoded `map[identity.Role][]permission.Key`
(`internal/store/memory/permission_repo.go:16`), two roles
(`identity.RoleAdmin`, `identity.RoleUser` — `internal/domain/identity/`), and
14 permission keys (`grep -c 'Key = "' internal/domain/permission/model.go`).
The whole `Repository` interface is one read method,
`ListKeysByRole` (`internal/domain/permission/service.go:8-10`).

Measured against the target model in `docs/modules/permissions.md`:

| target model element | inherited engine |
|---|---|
| `subject` = user \| user-group | **absent** — subject is a *role*, not a subject; no per-user or per-group grant exists |
| `capability` 1:1 with a device operation | **absent** — all 14 keys are management CRUD (`device.read`, `user.write`, `notification.write`). Not one names a device operation. |
| `scope` = device \| device-group \| port | **absent** — a key is global; there is no scope field anywhere in the tuple |
| `constraints` (presence / time_window / four-eyes) | **absent** |
| union of grants **minus explicit denies** | **absent** — allow-only; no deny, so no precedence rule to inherit |
| grant persistence | **absent** — the map is compiled in; `Repository` has no write method |

`DefaultKeysForRole` (`internal/domain/permission/model.go:31`) is a stub with
elided bodies (`/* ... */`) — it is dead relative to the memory repo that
actually supplies the keys.

**This is not a policy engine.** It is a role→permission-key lookup table. There
is no resolution algorithm to adopt because there is nothing to resolve: the
answer is a set membership test (`internal/http/middleware/auth.go:105-120`).

---

## 2. The enforcement seam — the actual finding

The spec's load-bearing rule is: enforce at the **tunnel/stream layer, not the
UI**, and it cites the firmware `/streamer`-bypass as the warning. The
measurement is that **kazbek's management plane has the same shape of hole**,
and it is wider than the firmware one.

There are two disjoint route trees on the same gin engine:

**Tree A — `/api/*`, the management plane.** Mounted with
`api.Use(middleware.Auth(...))` (`internal/http/router.go:72`), and each route
carries `middleware.Require(permission.X)`.

```
$ grep -cE '^\s+(api|notifGroup)\.(GET|POST|PUT|DELETE)' internal/http/router.go
42
$ grep -c "middleware.Require" internal/http/router.go
41
```

41 of 42 guarded. The one exception is `api.GET("/script-info", ...)`
(`internal/http/router.go:75`) — authenticated, unguarded, and benign as far as
I read it. Coverage here is essentially complete.

**Tree B — the device tunnel.** Three routes, on a *different* group
(`authorized`, `internal/server/api.go:203`):

```
$ grep -nE '^\s+authorized\.' internal/server/api.go
214:	authorized.GET("/connect/:devid", ...)      # websocket to the device console
240:	authorized.POST("/cmd/:devid", ...)         # command execution on the device
263:	authorized.Any("/web/:devid/:proto/:addr/*path", ...)  # generic HTTP proxy INTO the device
```

**`middleware.Require` appears zero times on these routes.** The `permission`
package is imported by `internal/http/router.go`,
`internal/http/middleware/auth.go`, `internal/store/memory/permission_repo.go`
and `internal/server/api.go` — but in `internal/server/api.go` it is not used to
guard any of the three (`grep -rln domain/permission --include=*.go .`).

Their entire gate is `httpAuth` (`internal/server/api.go:408-427`), which is
**authentication only**:

- `if !cfg.LocalAuth && isLocalRequest(c) { return true }` (`:409`) — a local
  request is admitted with no credential at all when `LocalAuth` is off.
- `if cfg.Password == "" { return true }` (`:414`) — explicitly commented
  "Keep legacy behavior: if password is not set, no auth required".
- otherwise: a `sid` cookie that resolves in `sessionStore` (`:418-426`).

That is the whole check. It does not resolve *which* user, does not read a role,
does not consult a permission key, and does not consult the device.

`handleUserConnection` (`internal/server/user.go:72`) — the function that
actually binds a user to a device console — upgrades the websocket
(`:74`), reads `devid` from the path (`:81`), fetches the device (`:92`) and
binds. There is no principal in that function at all; it never asks who is
connecting.

And the user↔device-group relations that *would* express scope are never
consulted on this path:

```
$ grep -rn "Relations\|relation" --include=*.go internal/server/ | grep -v _test
internal/server/api.go:98:	relationsRepo := sqlite.NewRelationsRepo(appDB.Gorm())
internal/server/api.go:119:		RelationsRepo:     relationsRepo,
```

Construction and wiring only — no call site in the device path.

### What that means concretely

Any authenticated session — including `identity.RoleUser`, which is granted only
`me.read`, `auth.write`, `device.read`, `device_group.read`, `user_group.read`
(`internal/store/memory/permission_repo.go:33-37`) — can `POST /cmd/:devid`
against **any device id in the fleet** and have it executed, and can open a
console websocket to any device. `device.read` is a *read* key; the tunnel does
not check even that.

`/web/:devid/:proto/:addr/*path` is the sharpest edge: it is a generic HTTP
proxy into the device parameterised by protocol and address, so it reaches the
device's own HTTP surface — the firmware streamer included — without passing any
kazbek capability check. This is the `/streamer`-bypass, one layer up: gating
`/connect` alone would leave `/web` as the parallel path.

The only authorization-shaped thing on these routes is `callUserHookUrl`
(`internal/server/api.go:353`), an **optional external webhook**
(`internal/server/api.go:215`, `:241`, `internal/server/http.go:286` — all three
routes do call it). It is off unless configured, it is an out-of-process
decision, and it is not a capability model.

### Consequence for the plan

`docs/ARCHITECTURE.md` lists "capability enforcement points" as part of the
core, and `docs/modules/permissions.md` declares the module's core dependency to
be exactly that. **That core interface does not exist.** Phase 2 was scoped as
"tunnel enforcement" against a seam that is currently three unguarded closures
in `internal/server/api.go`.

This is a design-step addition per rule 10 and is the reason this report stops
here: introducing a capability enforcement point into the device-connection core
is a trust-boundary change, and the roadmap places it in the core, not in the
module.

---

## 3. What Phase 1 can and cannot reuse

Reusable, and worth keeping:

- **The `permission.Key` string namespace** and the `Require`-style middleware
  shape (`internal/http/middleware/auth.go:105`) — for the *management*
  capabilities (`plugin.install`, `device.admin`). The 42 `/api` routes are
  already threaded and should not be re-plumbed.
- **The `Repository` seam** (`internal/domain/permission/service.go:8`) — the
  right shape, one method short of useful. It needs grant reads by subject, not
  keys by role.
- **`identity.Role`** as a *default-grant template*, not as the authorization
  primitive. Roles become a way to seed grants, not a way to decide them.

Not reusable: the resolution logic (there isn't any), the storage (compiled-in
map, no writes), the scope model (none), the constraint model (none).

## 4. The constraint engine — KVM Fleet

`github.com/KVMFleet/policy-engine` @ `8841f37e` (v0.2.1), Python, 283 code
lines across 10 files, 29 tests. Five constraints: `time_of_day`,
`require_mfa`, `max_concurrent_sessions`, `approval_required`, `ip_allowlist`.
No `requires_presence` — the one the spec most wants for a KVM.

**It has no grant model.** Searched the package for `subject`, `user_id`,
`principal`, `role`, `group`, `scope`, `device_id`: zero hits for every one.
Its `EvalContext` carries no identity; targeting is a tag filter plus an action
filter. There is no explicit deny, so no precedence rule. Its own README says
it is "not a general-purpose policy engine… use Cedar or OPA." It is a
constraint layer designed to run *after* somebody else's RBAC has already
decided who the subject is.

That is the decisive measurement: **the part of item 1 that is hard — subject,
scope, deny precedence — is exactly the part neither engine has.** GL has a
role table and no constraints; KVM Fleet has constraints and no subjects.
Neither has scope, and neither has a port scope (D-009).

Two defects were found by *executing* its evaluator, not just reading it:

- A midnight-crossing window (`22:00`→`06:00`) denies at **every** hour,
  because the comparison is `start <= current <= end`
  (`time_of_day.py:63`). It fails in the safe direction, silently, and makes
  the engine unusable for precisely the after-hours window a KVM needs.
- **Skip-on-missing-context fails OPEN**: `require_mfa` in `block` mode with
  the MFA field unset returns `allow`. For kazbek that default must be
  inverted — absent context is a denial, not a pass.

Enforcement is a pure library — the caller's problem. The sibling
`KVMFleet/agent` (Go, 3968 lines) is a verbatim reverse proxy for
kvmd/Janus/streamer; searching it for authorization finds only TLS-policy
comments and an IPMI *port* allowlist. So KVM Fleet also enforces at the API
and tunnels everything else undifferentiated. That is corroboration of the
thesis in §2, not a model to copy.

### The call: reinvent the engine, lift the vocabulary and the tests

Adopt neither engine. Lift, specifically:

- the `apply(rule, ctx) -> reason | nil` one-method constraint interface —
  the right shape, and it composes;
- the constraint **vocabulary**, including `max_sessions` and `source_cidr`,
  which `docs/modules/permissions.md` does not currently list and probably
  should;
- the `dry_run → warn → block` rollout ladder — a constraint you cannot
  deploy in observe-mode first will not get deployed;
- fail-closed-on-exception, and its four mutation tests for that behaviour;
- decision results carrying `policy_id` / `policy_name` / `reason`, which is
  what makes an audit trail answer "why";
- the test-corpus *shape*: timezone edges, naive-datetime-is-UTC, a property
  test over the whole day, and "warn does not short-circuit block".

Both defects above become test cases we must pass on day one.

**Caveat on this section:** the KVMFleet test suite was **not executed** — no
pytest in this container and `pip install` timed out against
`files.pythonhosted.org`. The 29-test count is a grep. The two defects above
were confirmed by direct `evaluate()` runs; everything else here is
read-from-source.

## 4b. Licence — this is not GPLv3

`LICENSE` in this tree is **Business Source License 1.1** (Licensor: GL.iNet;
Licensed Work: "GLKVM Cloud"), with an Additional Use Grant limited to
"non-production purposes, including development, testing, personal, or
academic use", and a Change Date of **2030-01-01**, on which it converts to
GPLv3 (`LICENSE:1`, `:12`, `:14`).

The kazbek README drafted for this project states "GPLv3, inherited from
`glkvm-cloud`". That is **incorrect** — GPLv3 is the *future* licence of the
upstream, from 2030. Until then the inherited code is BUSL-1.1 and
production use is not granted.

This is not an item-1 question but it is load-bearing for the whole project —
"self-hosted, you run it yourself" is a production-use claim — and it was
found while measuring item 1, so it is recorded here rather than dropped.
It needs an owner decision and a DECISIONS entry; this document does not make
one. (Confirmed independently against the tree's own `LICENSE`; the upstream
tag `v2.8.0` carries the same.)

## 4c. Corrections to the sub-agent research pass

Recorded because rule 1 applies to sub-agents too:

- The research pass reported **15** permission keys. The tree has **14**
  (`grep -c 'Key = \"' internal/domain/permission/model.go`). The count in
  §1 is the measured one.
- It reported the inherited engine as 102 total / 78 code lines. 102 total is
  confirmed; the 78 was not re-derived here and is not relied on.

## 4d. Test debt carried out of Phase 0

`internal/server/http.go:216` — the devid-mismatch check that did not block
(fixed in this branch, see the commit) ships **without** a regression test,
because `internal/server` has no harness able to stand up a device session and
a proxy conn. The item-1 test harness must carry a fails-on-removal case for
it: delete the `return`, and a test must go red.

---

## Appendix — environment, and what "green" means here (rule 2)

Rule 2 says a partial environment gives a false green, so this records exactly
what was stood up and what state it was in *before* any item-1 work.

**Getting to a full environment was not free.** `go build ./...` fails out of
the box:

```
ui/embed.go:5:12: pattern all:dist: no matching files found
```

`internal/server/api.go:46` imports `rttys/ui`, which `go:embed all:dist` — so
**no Go package in this repo builds until the frontend is built**. `ui/dist` is
gitignored (`ui/.gitignore:11-13`).

Building it hits two snags worth recording so they are not rediscovered:

1. `npm install` fails with `403 Forbidden` on
   `registry.npmmirror.com/...`. The configured registry is
   `https://registry.npmjs.org/` — npmmirror URLs come from **`ui/yarn.lock`**,
   which npm reads to seed resolutions when there is no `package-lock.json`.
   `--registry` does not override it; the lockfile does. Building from a copy of
   `ui/` with `yarn.lock` removed resolves against npmjs and succeeds
   (474 packages), then `npm run build` produces `dist/` in ~18s. The built
   `dist/` was copied back to `ui/dist`; nothing in the tracked tree changed.
2. The failure was initially invisible. `npm install ... | tail -5 && npm run
   build` reported `exit code 0` while the install had actually failed — `tail`
   supplied the exit status. This is the `&&`-chain hazard AGENTS.md already
   records, in a new costume: **a pipeline's exit status is the last command's.**
   The real error was only in `/root/.npm/_logs/*-debug-0.log`.

**Verified state of the tree at this point** (branch
`claude/glkvm-stock-debloat-migration-0pibl7`, `go1.24.7 linux/amd64`, `ui/dist`
present):

```
$ go build ./...   → exit 0
$ go vet ./...     → exit 0
$ go test ./...
ok    rttys/internal/pkg/useragent
ok    rttys/internal/qa
ok    rttys/internal/store/sqlite
FAIL  rttys/internal/server      0.014s
```

The one failure is **pre-existing and inherited**, not introduced here.
`TestRttysStress` (`internal/server/rttys_stress_test.go`) dies at
`FATA open : no such file or directory` — an empty path, i.e. it wants a config
file the test does not supply. Checked out `main` and ran the same package: it
fails identically. So the item-1 baseline is **3 packages green, 1 package red
before we start**, and any claim of "tests green" for this work must be stated
against that baseline, not against a clean sheet.

---

## 5. Design-step proposal (NOT built — this is what needs review)

Rule 10: this is a trust-boundary change in the core, so it stops here as a
proposal. Nothing below is implemented.

The problem to solve is the one measured in §2: `middleware.Require` cannot be
reused for the tunnel, because the tunnel routes are not `/api` routes, do not
resolve a principal, and — for `/web/:devid/:proto/:addr/*path` — do not
correspond to a single capability at all. Bolting gin middleware onto
`internal/server/api.go:214/240/263` would reproduce the exact failure the spec
warns about: **a check beside the path rather than on it.** A caller that
reaches `handleUserConnection` by any other route is unguarded again.

The shape that satisfies "physically cannot carry the stream":

```
// core interface — enforcement point, not a module
type Authorizer interface {
        // Resolve is called ONCE, at session establishment, before the
        // device is bound. It returns the capability set this session may
        // ever exercise. There is no re-check API by design: a session
        // cannot acquire a capability it was not created with.
        Resolve(ctx context.Context, subj Subject, target Target) (CapSet, error)
}
```

and the enforcement is **structural, not conditional**: `handleUserConnection`
(`internal/server/user.go:72`) takes the resolved `CapSet` and, when
`screen.control` is absent, binds a device connection whose HID and video
message types are *not wired up* — the demultiplexer for those frame types is
absent from the session, so there is nothing to bypass. Compare
`internal/server/device.go:667-721`, where message types are dispatched to
`user.WriteMsg` unconditionally today; the capability set decides which of those
arms exist for a session.

Two consequences the review should weigh:

- **`/web/:devid/:proto/:addr/*path` probably cannot be capability-mapped and
  should be gutted, not guarded** (D-008, "gut, not mask"). It is a generic
  proxy parameterised by protocol and address: the set of operations it can
  reach is not enumerable, so no 1:1 capability exists for it. Guarding it means
  guessing. This is a proposal to *remove a route the inherited product ships*,
  which is why it is a design step and not a fix.
- **`Subject` does not exist yet.** `httpAuth` (`internal/server/api.go:408`)
  returns a bool; it never resolves a user. Phase 1 needs the tunnel path to
  resolve a principal at all before it can authorize one — that is a
  prerequisite to Phase 2, not part of it, and it is currently unscoped in the
  plan.

Both of these change the size of Phase 2 materially, which is the second reason
this report stops here.
