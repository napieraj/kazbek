package fixtures

// mutation.go — mechanical support for AGENTS.md rule 4.
//
//	"A security check that no test fails-on-removal is not verified — it might
//	 be dead. For each check that would fail silently if wrong, write a test and
//	 confirm it goes red when the check is removed."
//
// Doing that by hand means commenting out a line, running the tests, reading
// the output, and putting the line back — which is exactly the kind of step
// that gets skipped. AssertLoadBearing does it in the test run: it replays the
// table against an engine with the check removed and FAILS if everything still
// passes.
//
// Two ways to produce the mutant:
//
//  1. The engine implements Mutable and DropCheck builds it:
//
//     m, err := fixtures.DropCheck(engine, "port-scope")
//     if err != nil { t.Fatal(err) }
//     fixtures.AssertLoadBearing(t, engine, cases, m)
//
//  2. The test constructs it by hand — a second engine value, or a wrapper
//     that short-circuits one check:
//
//     fixtures.AssertLoadBearing(t, engine, cases,
//     fixtures.NewMutation("port-scope", engineWithPortScopeMatchingRemoved))
//
// Form 1 is preferred: it keeps the mutant next to the check instead of in a
// test file that will drift. Adopting Mutable in the Phase 1 core costs about
// ten lines and makes every check's coverage a one-liner.
//
// What a mutation is NOT: a change that makes the engine deny more. Removing a
// check must make the engine MORE permissive; the table then goes red on the
// rows that expected a deny. A mutant that denies everything will also turn
// rows red and prove nothing, so keep mutants to "this specific check is gone".

import (
	"fmt"
	"sort"
	"testing"
)

// Mutation is an engine with exactly one security check removed.
type Mutation struct {
	// Name is the check that was removed, as a human would say it:
	// "port-scope match", "deny-override", "constraint:requires_presence".
	Name string

	// Engine is the same engine minus that check.
	Engine Engine
}

// NewMutation pairs a name with a hand-built mutant engine.
func NewMutation(name string, mutant Engine) Mutation {
	return Mutation{Name: name, Engine: mutant}
}

// Mutable is the optional interface an engine implements to make its checks
// mechanically removable. WithoutCheck returns a copy of the engine with the
// named check disabled, and false if the name is unknown — an unknown name
// must NOT silently return the unmodified engine, or the mutation check would
// report "not load-bearing" for a check that simply was not removed.
type Mutable interface {
	Engine
	WithoutCheck(name string) (Engine, bool)
}

// Checked is the optional companion to Mutable: the list of check names the
// engine can drop. A test can range over it and assert that EVERY check is
// covered by some table — which is rule 4 applied exhaustively instead of to
// the checks someone remembered.
type Checked interface {
	Checks() []string
}

// DropCheck builds a Mutation from an engine that implements Mutable.
func DropCheck(e Engine, check string) (Mutation, error) {
	m, ok := e.(Mutable)
	if !ok {
		return Mutation{}, fmt.Errorf("fixtures: %T does not implement fixtures.Mutable; "+
			"either implement WithoutCheck(name) or build the mutant by hand with NewMutation", e)
	}
	mutant, ok := m.WithoutCheck(check)
	if !ok {
		return Mutation{}, fmt.Errorf("fixtures: %T has no check named %q", e, check)
	}
	if mutant == nil {
		return Mutation{}, fmt.Errorf("fixtures: %T returned a nil engine for check %q", e, check)
	}
	return Mutation{Name: check, Engine: mutant}, nil
}

// AssertLoadBearing proves each named check is actually held down by this
// table.
//
// It first requires the sound engine to pass every row — a table that is
// already red proves nothing about a mutant. Then, for each mutation, it
// replays the table and requires at least one row to fail. A mutation that
// changes no outcome is reported as a failure: either the check is dead code,
// or this table does not cover it, and both need a human.
func AssertLoadBearing(t *testing.T, sound Engine, cases []Case, mutations ...Mutation) {
	t.Helper()
	if len(cases) == 0 {
		t.Fatalf("fixtures: AssertLoadBearing called with an empty table")
	}
	if len(mutations) == 0 {
		t.Fatalf("fixtures: AssertLoadBearing called with no mutations")
	}

	if base := Failures(sound, cases); len(base) > 0 {
		for _, name := range sortedKeys(base) {
			t.Errorf("baseline row %q already fails against the unmutated engine: %v", name, base[name])
		}
		t.Fatalf("fixtures: the table must be green before a mutation can mean anything")
	}

	for _, m := range mutations {
		m := m
		t.Run("mutation/"+m.Name, func(t *testing.T) {
			if m.Engine == nil {
				t.Fatalf("mutation %q has a nil engine", m.Name)
			}
			red := Failures(m.Engine, cases)
			if len(red) == 0 {
				t.Errorf("removing the %q check turned NO row red: that check is not verified by this table.\n"+
					"Either the check is dead code (remove it — AGENTS.md rule 5, gut don't mask), "+
					"or add a row that only passes because the check is there.", m.Name)
				return
			}
			// Not a failure — reported so the run records which rows hold the
			// check down, which is the evidence rule 4 asks for.
			t.Logf("check %q is load-bearing: %d row(s) go red without it: %v",
				m.Name, len(red), sortedKeys(red))
		})
	}
}

// AssertEveryCheckCovered runs AssertLoadBearing over every check the engine
// declares, so a newly added check cannot land uncovered.
func AssertEveryCheckCovered(t *testing.T, sound Engine, cases []Case) {
	t.Helper()
	c, ok := sound.(Checked)
	if !ok {
		t.Fatalf("fixtures: %T does not implement fixtures.Checked; "+
			"list its checks or call AssertLoadBearing per check", sound)
	}
	names := c.Checks()
	if len(names) == 0 {
		t.Fatalf("fixtures: %T declares no checks", sound)
	}
	muts := make([]Mutation, 0, len(names))
	for _, name := range names {
		m, err := DropCheck(sound, name)
		if err != nil {
			t.Fatalf("fixtures: %v", err)
		}
		muts = append(muts, m)
	}
	AssertLoadBearing(t, sound, cases, muts...)
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
