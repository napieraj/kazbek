# Request to GL.iNet — production use for self-hosted derivatives

**Status:** draft, not sent. Goes **separately** from
`docs/gl-disclosure.md` and on its own track. Bundling a request with a
security report makes the report read as leverage however carefully it is
worded — and those findings should be fixed whatever the answer here is.

---

## The ask

`glkvm-cloud` is licensed under Business Source License 1.1, with an Additional
Use Grant covering "non-production purposes, including development, testing,
personal, or academic use", converting to GPLv3 on 2030-01-01.

**We would like to ask whether GL would extend that grant to cover production
use of self-hosted, non-commercial deployments of derivative works** — people
running a fork on their own hardware, for their own devices, without selling a
service on top.

## Why we think this is worth GL's while

The request is not really about us. We maintain a fork (`kazbek`) that replaces
the device-trust core with pinned mutual TLS, and we could sit on the
non-production grant indefinitely while the work matures. The people the
current terms actually bind are **the ones who would adopt it**: a homelab
operator or a small team who wants to run GLKVM hardware with a self-hosted
controller and no vendor cloud in the path.

For that audience the position today is awkward in a way we suspect is
unintended:

- They have **bought GL hardware**. The controller is what makes it useful
  without the vendor cloud.
- "Running my own KVM controller for my own devices" is production use by any
  ordinary reading, so the current grant does not cover the thing they want to
  do.
- The alternative is not that they buy a GL cloud subscription — it is that
  they use different hardware, or nothing.

A grant scoped to self-hosted, non-commercial use costs GL no revenue we can
identify: it does not permit reselling, hosting the software as a service, or
competing with GL's own offering. It makes GL hardware more attractive to the
segment most likely to buy several units and least likely to ever buy a cloud
subscription.

## What we would do with it

Nothing that competes with GL. The fork is a control plane for hardware people
already own, and it is aimed squarely at operators who were never going to use
the vendor cloud.

We are happy to accept a grant scoped however GL prefers — self-hosted only,
non-commercial only, a named-project grant rather than a general one, or a
revocable one. Any of those resolves the position for adopters.

## Two things we are not asking

- We are **not** asserting that the current terms permit what we want to do.
  They read as though they do not, which is why we are asking.
- We are **not** raising this as a condition of anything. The security findings
  in the separate report stand on their own and we will not link them.

## An observation, offered rather than claimed

While tracing provenance we noticed that nine Go files in `glkvm-cloud` carry a
verbatim MIT grant naming Jianhui Zhao — `rttys`, which `glkvm-cloud` derives
from — while the repository's `LICENSE` is BUSL-1.1; and that four further
files derived from `rttys`'s `main.go` appear to have had that attribution
removed.

We are not lawyers, we are not asserting a violation, and this is not part of
the request. We mention it only because it is far more easily resolved by GL
than by anyone downstream, and because a fork that wants to be scrupulous about
attribution would rather raise it than quietly work around it.
