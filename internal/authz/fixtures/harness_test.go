package fixtures

// Self-tests for the table harness, the scenario, and the mutation helper.
// They drive the test-only reference engine in refengine_test.go.
//
// The point of these is not to test the reference engine — it is disposable —
// but to prove the infrastructure does what its doc comments claim: that the
// harness catches a port leak, that a bypass row fails when the transport is
// unchecked, and that AssertLoadBearing actually finds red rows for every
// check the engine declares.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// coreCases is the capability-decision table for StandardScenario. Between
// them the rows cover every check the reference engine declares, which
// TestEveryCheckIsLoadBearing then proves mechanically.
func coreCases(sc *Scenario) []Case {
	return []Case{
		{
			Name:       "alice may view her own port",
			Req:        Ask(ScenarioAlice, CapView).OnPort(ScenarioDeviceA, 0).When(sc.Now).Build(),
			Want:       true,
			WantReason: "alice-view-p1",
			Why:        "alice holds a direct view grant scoped to exactly this port",
		},
		{
			Name:       "alice may not view a sibling port",
			Req:        Ask(ScenarioAlice, CapView).OnPort(ScenarioDeviceA, 2).When(sc.Now).Build(),
			Want:       false,
			WantReason: "no-grant",
			Why:        "a grant on port 1.1 must not reach port 1.3 (D-009)",
		},
		{
			Name:       "a port grant does not widen to the whole device",
			Req:        Ask(ScenarioAlice, CapView).OnDevice(ScenarioDeviceA).When(sc.Now).Build(),
			Want:       false,
			WantReason: "no-grant",
			Why:        "scope widening is one-way: device covers its ports, a port never covers its device",
		},
		{
			Name:       "an unrelated user inherits nothing",
			Req:        Ask(ScenarioMallory, CapView).OnPort(ScenarioDeviceA, 0).When(sc.Now).Build(),
			Want:       false,
			WantReason: "no-grant",
			Why:        "mallory holds no grant and belongs to no group; grants are not ambient",
		},
		{
			Name:       "group grant widens through the device group",
			Req:        Ask(ScenarioCarol, CapView).OnDevice(ScenarioDeviceB).When(sc.Now).Build(),
			Want:       true,
			WantReason: "ops-view-rack",
			Why:        "carol is in ops, ops holds view on rack-a, and kvm-2 is in rack-a",
		},
		{
			Name:       "explicit deny beats an inherited group allow",
			Req:        Ask(ScenarioDave, CapView).OnDevice(ScenarioDeviceB).When(sc.Now).Build(),
			Want:       false,
			WantReason: "explicit-deny",
			Why:        "effective capabilities are the union of grants MINUS explicit denies",
		},
		{
			Name: "atx.hard denied without the ceremony tap",
			Req: Ask(ScenarioCarol, CapATXHard).OnDevice(ScenarioDeviceA).When(sc.Now).
				ApprovedBy(ScenarioAlice, ScenarioBob).Build(),
			Want:       false,
			WantReason: string(ConstraintRequiresPresence),
			Why:        "the grant carries requires_presence and no tap was observed",
		},
		{
			Name: "atx.hard denied with only one approver",
			Req: Ask(ScenarioCarol, CapATXHard).OnDevice(ScenarioDeviceA).When(sc.Now).
				WithPresence().ApprovedBy(ScenarioAlice).Build(),
			Want:       false,
			WantReason: string(ConstraintFourEyes),
			Why:        "four-eyes needs two distinct approvers other than the requester",
		},
		{
			Name: "atx.hard allowed with presence and two approvers",
			Req: Ask(ScenarioCarol, CapATXHard).OnDevice(ScenarioDeviceA).When(sc.Now).
				WithPresence().ApprovedBy(ScenarioAlice, ScenarioBob).Build(),
			Want:       true,
			WantReason: "ops-atxhard-kvm1",
			Why:        "every constraint on the grant is satisfied",
		},
		{
			Name:       "msd.mount denied outside its window",
			Req:        Ask(ScenarioErin, CapMSDMount).OnDevice(ScenarioDeviceA).When(sc.Now).Build(),
			Want:       false,
			WantReason: string(ConstraintTimeWindow),
			Why:        "erin's grant is time-windowed and Now falls outside it",
		},
		{
			Name:       "msd.mount allowed inside its window",
			Req:        Ask(ScenarioErin, CapMSDMount).OnDevice(ScenarioDeviceA).When(sc.Now.Add(90 * time.Minute)).Build(),
			Want:       true,
			WantReason: "erin-msd-window",
			Why:        "the same grant inside its window allows; a constraint that always denies proves nothing",
		},
		{
			Name:       "bob has no screen.control at the stream endpoint",
			Req:        Ask(ScenarioBob, CapScreenControl).OnPort(ScenarioDeviceA, 2).At(PointStream).When(sc.Now).Build(),
			Want:       false,
			WantReason: "no-grant",
			Why:        "bob holds view only; the stream endpoint must decide for itself, not trust the API",
		},
	}
}

func TestStandardScenarioDecisions(t *testing.T) {
	sc := StandardScenario()
	Run(t, newRefEngine(sc.World), coreCases(sc))
}

// TestEveryCheckIsLoadBearing is AGENTS.md rule 4 applied mechanically and
// exhaustively: for every check the engine declares, removing it must turn at
// least one row of the table red.
func TestEveryCheckIsLoadBearing(t *testing.T) {
	sc := StandardScenario()
	AssertEveryCheckCovered(t, newRefEngine(sc.World), coreCases(sc))
}

func TestPortIsolationTable(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)

	// The gated operation for "view port N": select the channel, then pull a
	// frame. Both touch the mux, so the harness sees which channel was served.
	viewPort := func(d *RM4PE, p PortIndex) error {
		if err := d.SetActivePort(p); err != nil {
			return err
		}
		_, err := d.PullVideoFrame()
		return err
	}
	cases := PortIsolationCases(ScenarioAlice, CapView, sc.DeviceA, 0, sc.Now, viewPort)
	if len(cases) != PortCount {
		t.Fatalf("port isolation table has %d rows, want one per channel (%d)", len(cases), PortCount)
	}
	Run(t, eng, cases)

	m, err := DropCheck(eng, checkScope)
	if err != nil {
		t.Fatalf("DropCheck: %v", err)
	}
	AssertLoadBearing(t, eng, cases, m)
}

func TestStreamBypassTable(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)
	target := PortScope(ScenarioDeviceA, 2)

	// The core's stream wiring, modelled: the endpoint asks the SAME engine
	// the harness asked (handed in as e) before it serves a single frame. A
	// wiring that skipped this ask would serve video to bob and the rows would
	// report BYPASS.
	pull := func(d *RM4PE, e Engine) error {
		req := Request{
			Subject:    User(ScenarioBob),
			Capability: CapScreenControl,
			Scope:      target,
			Point:      PointStream,
			At:         sc.Now,
		}
		if dec := e.Decide(context.Background(), req); !dec.Allow {
			return fmt.Errorf("stream refused: %s", dec.Reason)
		}
		_, err := d.PullVideoFrame()
		return err
	}

	cases := StreamBypassCases(ScenarioBob, sc.DeviceA, target, sc.Now, pull)
	Run(t, eng, cases)

	m, err := DropCheck(eng, checkPoint)
	if err != nil {
		t.Fatalf("DropCheck: %v", err)
	}
	AssertLoadBearing(t, eng, cases, m)
}

// TestHarnessCatchesUnwiredStreamEndpoint is the meta-test for the BYPASS
// assertion: an endpoint that never asks the engine must make the row fail.
func TestHarnessCatchesUnwiredStreamEndpoint(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)
	target := PortScope(ScenarioDeviceA, 2)

	unwired := func(d *RM4PE, _ Engine) error {
		_, err := d.PullVideoFrame() // straight to the hardware: no check at all
		return err
	}
	cases := StreamBypassCases(ScenarioBob, sc.DeviceA, target, sc.Now, unwired)
	fails := Failures(eng, cases)
	if len(fails) == 0 {
		t.Fatalf("a stream endpoint that never asks the engine must fail every bypass row")
	}
	if !anyFailureContains(fails, "BYPASS") {
		t.Errorf("expected a BYPASS failure, got %v", fails)
	}
}

// TestHarnessCatchesPortLeak is the meta-test for the PORT LEAK assertion:
// a decision that allows "view port 1.1" while the mux is parked on 1.3 hands
// the session the wrong console, and the harness must say so even though the
// decision itself was an allow.
func TestHarnessCatchesPortLeak(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)
	sc.DeviceA.SeedActivePort(2) // the mux is on vault-host

	leaky := Case{
		Name: "view 1.1 while the mux is parked on 1.3",
		Req:  Ask(ScenarioAlice, CapView).OnPort(ScenarioDeviceA, 0).At(PointStream).When(sc.Now).Build(),
		Want: true,
		Why: "alice really does hold view on 1.1, so the decision allows; the harness must still " +
			"catch that the stream served a channel she has no grant on",
		Device: sc.DeviceA,
		Do: func(d *RM4PE, _ Engine) error {
			_, err := d.PullVideoFrame()
			return err
		},
	}
	fails := Failures(eng, []Case{leaky})
	if !anyFailureContains(fails, "PORT LEAK") {
		t.Errorf("expected a PORT LEAK failure, got %v", fails)
	}
}

// TestHarnessRejectsUndocumentedRow keeps Why mandatory.
func TestHarnessRejectsUndocumentedRow(t *testing.T) {
	sc := StandardScenario()
	fails := Failures(newRefEngine(sc.World), []Case{{
		Name: "no why",
		Req:  Ask(ScenarioAlice, CapView).OnPort(ScenarioDeviceA, 0).When(sc.Now).Build(),
		Want: true,
	}})
	if !anyFailureContains(fails, "empty Why") {
		t.Errorf("a row without a Why must fail, got %v", fails)
	}
}

// TestHarnessRejectsGroupTarget: a request names a concrete target; groups
// only widen grants.
func TestHarnessRejectsGroupTarget(t *testing.T) {
	sc := StandardScenario()
	fails := Failures(newRefEngine(sc.World), []Case{{
		Name: "group as a target",
		Req: Request{
			Subject: User(ScenarioCarol), Capability: CapView,
			Scope: DeviceGroupScope(ScenarioRack), Point: PointAPI, At: sc.Now,
		},
		Want: true,
		Why:  "this row is malformed on purpose",
	}})
	if !anyFailureContains(fails, "device-group") {
		t.Errorf("a group-targeted request must be rejected, got %v", fails)
	}
}

func TestDropCheckErrors(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)
	if _, err := DropCheck(eng, "no-such-check"); err == nil {
		t.Errorf("DropCheck must refuse an unknown check name rather than return the engine unchanged")
	}
	plain := EngineFunc(func(context.Context, Request) Decision { return Denied("stub") })
	if _, err := DropCheck(plain, checkScope); err == nil {
		t.Errorf("DropCheck must refuse an engine that does not implement Mutable")
	}
}

func TestTimeWindowBuilders(t *testing.T) {
	base := time.Date(2026, time.March, 17, 14, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{base, base.Add(30 * time.Minute), base.Add(-23 * time.Hour)} {
		if !WindowOpenAt(at).Contains(at) {
			t.Errorf("WindowOpenAt(%s) must contain its own instant", at.Format(time.RFC3339))
		}
		if WindowClosedAt(at).Contains(at) {
			t.Errorf("WindowClosedAt(%s) must not contain its own instant", at.Format(time.RFC3339))
		}
	}
	// A window that crosses midnight still works.
	night := TimeWindow{Start: TimeOfDay{Hour: 22}, End: TimeOfDay{Hour: 6}}
	if !night.Contains(base.Add(9 * time.Hour)) { // 23:00
		t.Errorf("overnight window must contain 23:00")
	}
	if night.Contains(base) { // 14:00
		t.Errorf("overnight window must not contain 14:00")
	}
	// Day filtering.
	tueOnly := TimeWindow{Start: TimeOfDay{Hour: 0}, End: TimeOfDay{Hour: 23, Minute: 59}, Days: []time.Weekday{time.Tuesday}}
	if !tueOnly.Contains(base) {
		t.Errorf("2026-03-17 is a Tuesday and must fall inside a Tuesday-only window")
	}
	if tueOnly.Contains(base.Add(24 * time.Hour)) {
		t.Errorf("Wednesday must fall outside a Tuesday-only window")
	}
}

func TestGrantBuilderRefusesScopelessGrant(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("a grant with no scope must panic at Build, not authorise everything")
		}
	}()
	_ = GrantFor(User(ScenarioAlice), CapView).Build()
}

func TestWorldWidening(t *testing.T) {
	sc := StandardScenario()
	chain := sc.ScopeChain(PortScope(ScenarioDeviceA, 0))
	want := []Scope{
		PortScope(ScenarioDeviceA, 0),
		DeviceScope(ScenarioDeviceA),
		DeviceGroupScope(ScenarioRack),
	}
	if len(chain) != len(want) {
		t.Fatalf("scope chain = %v, want %v", chain, want)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Errorf("scope chain[%d] = %v, want %v", i, chain[i], want[i])
		}
	}
	if got := sc.SubjectChain(ScenarioCarol); len(got) != 2 || got[0] != User(ScenarioCarol) || got[1] != UserGroup(ScenarioOpsGroup) {
		t.Errorf("subject chain for carol = %v, want [user:carol user-group:ops]", got)
	}
	if n := len(sc.GrantsFor(ScenarioAlice, CapView, PortScope(ScenarioDeviceA, 2))); n != 0 {
		t.Errorf("alice has %d candidate view grants on 1.3, want 0", n)
	}
}

func anyFailureContains(fails map[string][]string, needle string) bool {
	for _, msgs := range fails {
		for _, m := range msgs {
			if strings.Contains(m, needle) {
				return true
			}
		}
	}
	return false
}

func TestMagicChordTable(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)

	// The interlock the core must install in the HID path: before a chord is
	// allowed to move the mux, the session's hid.input on the DESTINATION port
	// is checked. Without this, alice types her way from 1.1 to 1.3.
	chord := func(d *RM4PE, e Engine, to PortIndex) error {
		req := Request{
			Subject:    User(ScenarioAlice),
			Capability: CapHIDInput,
			Scope:      PortScope(ScenarioDeviceA, to),
			Point:      PointHID,
			At:         sc.Now,
		}
		if dec := e.Decide(context.Background(), req); !dec.Allow {
			return fmt.Errorf("chord refused: %s", dec.Reason)
		}
		return d.MagicChordSwitch(to)
	}

	cases := MagicChordCases(ScenarioAlice, sc.DeviceA, ScenarioDeviceA, 0, sc.Now, chord)
	if len(cases) != PortCount-1 {
		t.Fatalf("chord table has %d rows, want %d", len(cases), PortCount-1)
	}
	Run(t, eng, cases)

	m, err := DropCheck(eng, checkScope)
	if err != nil {
		t.Fatalf("DropCheck: %v", err)
	}
	AssertLoadBearing(t, eng, cases, m)
}

// TestHarnessCatchesUninterlockedChord: a chord path that moves the mux
// without asking is the firmware's shipping behaviour, and must fail the table.
func TestHarnessCatchesUninterlockedChord(t *testing.T) {
	sc := StandardScenario()
	eng := newRefEngine(sc.World)
	raw := func(d *RM4PE, _ Engine, to PortIndex) error { return d.MagicChordSwitch(to) }
	fails := Failures(eng, MagicChordCases(ScenarioAlice, sc.DeviceA, ScenarioDeviceA, 0, sc.Now, raw))
	if !anyFailureContains(fails, "BYPASS") {
		t.Errorf("an uninterlocked magic chord must report BYPASS, got %v", fails)
	}
}
