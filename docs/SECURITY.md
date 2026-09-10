# Security policy

## Reporting
Email <security-contact>. Include affected version/commit, the finding, and
reproduction. Coordinated disclosure: we ask for a reasonable window to fix
before publication; we will credit you unless you prefer otherwise.

## Scope
kazbek (the management server) and its interaction with `glkvm-debloat` devices.
The device firmware has its own security process. Findings in the inherited
upstream (`glkvm-cloud`) that also affect upstream should be reported there too.

## Non-scope
- Physical attacks on a device an attacker holds (see the firmware threat model).
- A managed host's own OS compromise (console access to it is expected).
- Deployments that expose the management interface outside an isolated segment —
  network isolation is a documented, load-bearing control.

## Our commitments
- Signing keys are never required to live in the server (Signer backends).
- No auth path that locks the operator out during the outage a KVM exists for.
- Every finding is triaged by severity with the threat model as the frame.
