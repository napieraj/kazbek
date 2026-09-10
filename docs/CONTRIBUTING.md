# Contributing

## Build & test
- Go server: `make build`, `make test`. The full test environment is required —
  a partial env gives false greens (learned the hard way on the firmware side).
- One commit per logical change. Descriptive messages that say *why*.

## Standing rules (see AGENTS.md for the full set)
- **Re-derive before trusting.** Line numbers, counts, and any doc's claims are
  stale until checked against the tree. Measure; don't assert.
- **Full environment only.** "Passes" against an incomplete env is a false green.
- **Mutation-check silent-if-missed checks.** A security check that no test
  fails-on-removal is not verified.
- **Gut, not mask.** Owned code: remove, don't disable. Presence is a security
  property.
- **Modules declare their mode** (local-only / cloud-managed / both) and their
  dependency on the core.
- **Document non-obvious constraints at the point someone would undo them.**

## Module contract
A module registers against a core interface (`AuthProvider`, `Signer`,
`TrustStore`, capability enforcement points), declares its mode, and ships its
own tests. It must not reach into the core beyond its interface, and must not be
loaded when disabled.

## Security-sensitive changes
Device-trust, signing, and the capability enforcement points are the sensitive
core. Changes there need: a threat-model note, tests per silent-failure mode,
and a reviewer. See DECISIONS.md before proposing a change to a settled call.
