// Package fixtures is test infrastructure for kazbek's capability model
// (roadmap item 1, docs/modules/permissions.md, D-009).
//
// It contains no production logic. It provides four things:
//
//  1. rm4pe.go   — a mock of the 4-port GLKVM RM4PE switch, modelled on the
//     real firmware (glkvm-debloat kvmd switch package) so that a port-scope
//     test asserts against something shaped like the hardware.
//  2. shapes.go / world.go — provisional grant/subject/scope/constraint types
//     and an ergonomic builder for them.
//  3. harness.go — a table-test harness for capability decisions, able to
//     express both the port-isolation tests and the stream-layer bypass test.
//  4. mutation.go — a mechanical mutation check (AGENTS.md rule 4): prove that
//     removing a security check turns at least one test red.
//
// # PROVISIONAL SHAPES — READ THIS FIRST
//
// The authorization core for item 1 does not exist yet. Every type in
// shapes.go and world.go is a PLACEHOLDER owned by the Phase 1 core author,
// who is free to replace, rename or re-home them. They exist only so this
// package compiles and so the harness has something to talk about. Each such
// file repeats this notice at its top. Nothing here encodes the inherited
// role -> flat-key model in internal/domain/permission — that engine is being
// replaced, and these fixtures deliberately do not bake in its shape.
//
// The one shape that is NOT provisional is the RM4PE mock: it is derived from
// the firmware and every modelled behaviour cites the file:line it came from.
// If the firmware and the mock disagree, the firmware is right (AGENTS.md
// rule 1 — re-derive before trusting).
//
// # How to use this package for a mutation check (AGENTS.md rule 4)
//
// A security check that no test fails-on-removal is not verified. The
// mechanical protocol here is:
//
//	sound := yourcore.NewEngine(world)        // the engine as shipped
//	cases := []fixtures.Case{ ... }           // the table that covers the check
//	fixtures.Run(t, sound, cases)             // all cases must pass
//	fixtures.AssertLoadBearing(t, sound, cases,
//	    fixtures.NewMutation("port-scope match", engineWithoutPortScopeCheck))
//
// AssertLoadBearing runs the same table against the mutated engine and FAILS
// if every case still passes — that is the signal that the check is dead
// weight or untested. If the core engine implements Mutable, DropCheck turns
// this into a one-liner and no hand-written mutant is needed.
//
// If a fixture cannot be driven mechanically (for example the mutation lives
// in wiring rather than in the engine), each fixture's doc comment states in
// prose exactly which check it is meant to hold down and what a test must do
// to prove it load-bearing.
package fixtures
