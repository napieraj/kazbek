# Module: <name>

**Mode:** local-only | cloud-managed | both
**Core dependency:** <which core interface it registers against>
**Status:** planned | design | building | done

## Purpose
One paragraph: what capability this adds and to whom.

## Interface
Which core interface it implements (`AuthProvider` / `Signer` / `TrustStore` /
capability enforcement point) and the contract.

## Design
The actual mechanism. For research-grade modules, this is the design doc that
must be reviewed before code.

## Threat model delta
What this module changes about the threat picture — what a compromise of it
yields, what it defends.

## Fallback / degradation
If cloud-managed or both: what happens when the server/dependency is
unreachable. (For auth modules this MUST include the local break-glass path.)

## Tests
The silent-failure modes and the test per each.
