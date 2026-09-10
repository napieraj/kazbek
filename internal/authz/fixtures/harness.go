package fixtures

// harness.go — the table-test harness for capability decisions.
//
// One Case is one authorization question plus the answer it must get and the
// reason that answer is right. The runner is deliberately picky:
//
//   - Why is mandatory. A table row nobody can explain is a row nobody will
//     notice going wrong.
//   - When a Case names a Device, the runner does not merely check the
//     decision: it invokes the gated operation and inspects the device call
//     log, so the assertion is "the hardware served only the granted channel",
//     not "a boolean came back true".
//   - Case evaluation is a pure function (evaluate) with no *testing.T, so the
//     mutation check in mutation.go can replay the same table against a mutated
//     engine and count which rows go red.
//
// The two tests docs/modules/permissions.md calls out are both expressible:
//
//	port isolation — Case{Req: Ask("alice", CapATX...).OnPort("kvm-1", 2), Want: false,
//	                      Device: dev, Do: func(d *RM4PE, _ Engine) error { return d.ATX(2, ATXPowerOffHard) }}
//	stream bypass  — Case{Req: Ask("bob", CapScreenControl).OnPort("kvm-1", 2).At(PointStream),
//	                      Want: false, AlsoDoOnDeny: true, Do: pullVideoThroughTheStreamWiring}

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Case is one row of a capability-decision table.
type Case struct {
	// Name identifies the row in test output. Required.
	Name string

	// Req is the authorization question.
	Req Request

	// Want is the expected outcome: true = allow.
	Want bool

	// Why states, in one line, why Want is the right answer. Required — the
	// runner fails a row with an empty Why. This is not ceremony: the reason
	// is what a future reader checks the row against when the engine changes.
	Why string

	// WantReason, when set, must appear in Decision.Reason. Use it so a deny
	// is asserted to be the RIGHT deny — "denied because no grant matched" and
	// "denied because presence was missing" are different bugs and a table
	// that cannot tell them apart will pass through both.
	WantReason string

	// Device, when set, is the device mock the gated operation runs against.
	// The runner snapshots and restores it around the case, so rows are
	// order-independent and the table can be replayed.
	Device *RM4PE

	// Do is the operation the decision gates: the thing the caller would
	// actually do to the hardware. The runner invokes it ONLY on an allow (or
	// on a deny too, if AlsoDoOnDeny is set) and requires it to succeed.
	//
	// It is handed the engine the runner just asked, so a Do that models the
	// core's stream/tunnel wiring consults the SAME engine — including a
	// mutated one during AssertLoadBearing. That is what lets a mutation
	// expose wiring that decides for itself instead of asking.
	Do func(d *RM4PE, e Engine) error

	// AlsoDoOnDeny makes the runner invoke Do even when the decision denies,
	// and require it to FAIL and to leave no successful device call behind.
	//
	// This is how the stream-layer rule is asserted rather than assumed. A Do
	// that calls the device mock directly will of course succeed — the mock has
	// no authorization — so a bypass Case must point Do at the core's stream
	// wiring. If Do reaches the device unimpeded on a deny, the row fails, and
	// that failure is the finding: the permission was hidden, not enforced.
	AlsoDoOnDeny bool
}

// Run executes a table against an engine, one subtest per row.
func Run(t *testing.T, e Engine, cases []Case) {
	t.Helper()
	for _, c := range cases {
		c := c
		name := c.Name
		if name == "" {
			name = c.Req.Subject.String() + "/" + string(c.Req.Capability)
		}
		t.Run(name, func(t *testing.T) {
			for _, f := range evaluate(context.Background(), e, c) {
				t.Error(f)
			}
		})
	}
}

// evaluate runs one case and returns its failures. Empty means the row passed.
// Pure by design: no *testing.T, so mutation.go can replay a table and count
// reds without faking the testing package.
func evaluate(ctx context.Context, e Engine, c Case) []string {
	var fails []string
	add := func(format string, args ...any) { fails = append(fails, fmt.Sprintf(format, args...)) }

	if strings.TrimSpace(c.Why) == "" {
		add("Case %q has an empty Why: state why this outcome is correct, or the row cannot be reviewed", c.Name)
	}
	if err := c.Req.Scope.Validate(); err != nil {
		add("Case %q has an invalid request scope: %v", c.Name, err)
		return fails
	}
	if c.Req.Scope.Kind == ScopeDeviceGroup {
		add("Case %q targets a device-group: a request must name a concrete target (device or port); groups only widen grants", c.Name)
		return fails
	}

	var snap Snapshot
	var before int
	if c.Device != nil {
		snap = c.Device.Snapshot()
		before = c.Device.CallCount()
		defer c.Device.Restore(snap)
	}

	got := e.Decide(ctx, c.Req)
	if got.Allow != c.Want {
		add("decision = %s, want allow=%v\n  request: %s %s on %s at %s\n  why: %s",
			got, c.Want, c.Req.Subject, c.Req.Capability, c.Req.Scope, c.Req.Point, c.Why)
	}
	if c.WantReason != "" && !strings.Contains(got.Reason, c.WantReason) {
		add("decision reason = %q, want it to contain %q (right answer for the wrong reason is not a pass)",
			got.Reason, c.WantReason)
	}

	if c.Device == nil || c.Do == nil {
		return fails
	}

	switch {
	case got.Allow:
		if err := c.Do(c.Device, e); err != nil {
			add("gated operation failed after an allow: %v", err)
		}
		for _, call := range c.Device.CallsSince(before) {
			if call.Err != nil || call.Port == PortNone {
				continue
			}
			if c.Req.Scope.Kind == ScopePort && call.Port != c.Req.Scope.Port {
				// The RM4PE mux serves the ACTIVE channel regardless of which
				// port the caller asked about, so this fires when a decision
				// scoped to one port let the caller reach another.
				add("PORT LEAK: request scoped to %s but the device served %s (op %s)\n  the grant covers one channel; the hardware served a different one",
					c.Req.Scope.Port, call.Port, call.Op)
			}
		}
	case c.AlsoDoOnDeny:
		err := c.Do(c.Device, e)
		if err == nil {
			add("BYPASS: the decision denied but the gated operation succeeded anyway — the check is not on the path the caller actually takes")
		}
		for _, call := range c.Device.CallsSince(before) {
			if call.Err == nil {
				add("BYPASS: the decision denied but the device still served %s on %s", call.Op, call.Port)
			}
		}
	}
	return fails
}

// Failures runs a table and returns, per row name, the failures it produced.
// Rows that passed are absent. Exposed because a test that wants to assert on
// its own table (a meta-test, or a mutation check written by hand) needs the
// same evaluation the runner uses, not a reimplementation of it.
func Failures(e Engine, cases []Case) map[string][]string {
	out := map[string][]string{}
	for _, c := range cases {
		if f := evaluate(context.Background(), e, c); len(f) > 0 {
			name := c.Name
			if name == "" {
				name = c.Req.Subject.String() + "/" + string(c.Req.Capability)
			}
			out[name] = f
		}
	}
	return out
}
