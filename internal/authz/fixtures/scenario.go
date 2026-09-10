package fixtures

// scenario.go — a canned world plus the two table generators the module spec
// asks for by name (docs/modules/permissions.md, "Tests").
//
// PROVISIONAL in the same sense as shapes.go: the grants are expressed in the
// placeholder types, so they move when those move. The SHAPE of the scenario —
// one four-port device, a single-port operator, a viewer without
// screen.control, a group-granted high-consequence capability behind presence
// and four-eyes, an explicit deny that must beat a group allow — is the part
// worth keeping whatever the types end up looking like.

import "time"

// Scenario identifiers. Named constants so a failure message and a test row
// cannot drift apart.
const (
	ScenarioDeviceA  = "kvm-1"   // rm4pe, 4 ports
	ScenarioDeviceB  = "kvm-2"   // rm4pe, 4 ports, same rack
	ScenarioRack     = "rack-a"  // device group holding both
	ScenarioOpsGroup = "ops"     // user group
	ScenarioAlice    = "alice"   // single-port operator on ScenarioDeviceA port 1.1
	ScenarioBob      = "bob"     // viewer on port 1.3, NO screen.control — the bypass subject
	ScenarioCarol    = "carol"   // ops member; atx.hard behind presence + four-eyes
	ScenarioDave     = "dave"    // ops member with an explicit deny on ScenarioDeviceB
	ScenarioErin     = "erin"    // msd.mount only inside a time window
	ScenarioMallory  = "mallory" // no grants at all
)

// Scenario is a ready-made world for capability tests.
type Scenario struct {
	*World

	// DeviceA and DeviceB are the two RM4PE mocks. DeviceA starts with channel
	// 1.1 active and every channel's links up — the worst case for isolation,
	// since nothing physical stops a wrongly-authorised session.
	DeviceA *RM4PE
	DeviceB *RM4PE

	// Now is the fixed decision time. Time-window grants are built relative to
	// it, so a test never depends on the wall clock.
	Now time.Time

	// OpenWindow contains Now; ClosedWindow does not.
	OpenWindow   TimeWindow
	ClosedWindow TimeWindow
}

// StandardScenario builds a fresh world. Call it per test: it hands out live
// device mocks, and sharing those between tests would make one test's device
// state another's false green.
//
// The grants, and the test each one exists for:
//
//	alice  view/screen.control/hid.input on port 1.1 of kvm-1
//	       -> port isolation: these must not reach 1.2, 1.3, 1.4, nor the device
//	bob    view on port 1.3 of kvm-1, and nothing else
//	       -> stream bypass: bob has no screen.control anywhere, so a stream or
//	          tunnel that carries video/HID for bob is a bypass
//	ops    view on device-group rack-a
//	       -> widening: carol (in ops) may view both devices
//	ops    atx.hard on device kvm-1, +requires_presence +four_eyes(2)
//	       -> constraints on a high-consequence capability
//	dave   DENY view on device kvm-2 (dave is in ops, so ops' allow covers it)
//	       -> deny-override: explicit deny beats an inherited group allow
//	erin   msd.mount on device kvm-1, +time_window(closed at Now)
//	       -> time_window outside hours denies
//	mallory (nothing)
//	       -> subject matching: an unrelated user must not inherit anyone's grant
func StandardScenario() *Scenario {
	now := time.Date(2026, time.March, 17, 14, 0, 0, 0, time.UTC) // a Tuesday
	w := NewWorld()

	devA := w.AddRM4PE(ScenarioDeviceA).SeedAllLinksUp().SeedActivePort(0)
	devB := w.AddRM4PE(ScenarioDeviceB).SeedAllLinksUp().SeedActivePort(0)
	devA.SeedPortName(0, "build-host").SeedPortName(2, "vault-host")

	w.AddDeviceToGroup(ScenarioDeviceA, ScenarioRack)
	w.AddDeviceToGroup(ScenarioDeviceB, ScenarioRack)
	w.AddUserToGroup(ScenarioCarol, ScenarioOpsGroup)
	w.AddUserToGroup(ScenarioDave, ScenarioOpsGroup)

	open := WindowOpenAt(now)
	closed := WindowClosedAt(now)

	w.Add(
		GrantFor(User(ScenarioAlice), CapView).OnPort(ScenarioDeviceA, 0).WithID("alice-view-p1").Build(),
		GrantFor(User(ScenarioAlice), CapScreenControl).OnPort(ScenarioDeviceA, 0).WithID("alice-control-p1").Build(),
		GrantFor(User(ScenarioAlice), CapHIDInput).OnPort(ScenarioDeviceA, 0).WithID("alice-hid-p1").Build(),

		GrantFor(User(ScenarioBob), CapView).OnPort(ScenarioDeviceA, 2).WithID("bob-view-p3").Build(),

		GrantFor(UserGroup(ScenarioOpsGroup), CapView).OnDeviceGroup(ScenarioRack).WithID("ops-view-rack").Build(),
		GrantFor(UserGroup(ScenarioOpsGroup), CapATXHard).OnDevice(ScenarioDeviceA).
			RequiringPresence().RequiringApprovals(2).WithID("ops-atxhard-kvm1").Build(),

		DenyFor(User(ScenarioDave), CapView).OnDevice(ScenarioDeviceB).WithID("dave-deny-view-kvm2").Build(),

		GrantFor(User(ScenarioErin), CapMSDMount).OnDevice(ScenarioDeviceA).
			WithinTimeWindow(closed).WithID("erin-msd-window").Build(),
	)

	return &Scenario{
		World:        w,
		DeviceA:      devA,
		DeviceB:      devB,
		Now:          now,
		OpenWindow:   open,
		ClosedWindow: closed,
	}
}

// ---------- table generators ----------

// PortIsolationCases builds the table docs/modules/permissions.md calls
// "port scope enforced on a Comet X (grant on port 1 does not reach port 3)".
//
// It emits one row per channel of the device: an allow for the granted port
// and a deny for every other, each carrying the gated operation so the runner
// checks the device call log rather than only the boolean.
//
// op receives the port the row is about; it should perform the real per-port
// device operation the capability gates (an ATX click, a set_port_params, a
// stream pull through the core's wiring).
//
// MUTATION CHECK: this table holds down the scope-matching check. Remove the
// engine's scope comparison — or make it match a port grant against any port
// of the same device — and the three deny rows go red. If they do not, the
// engine is not consulting scope at all and every port on the device is open
// to anyone with a grant on one of them.
func PortIsolationCases(userID string, cap Capability, dev *RM4PE, granted PortIndex, at time.Time, op func(d *RM4PE, p PortIndex) error) []Case {
	cases := make([]Case, 0, PortCount)
	for i := 0; i < PortCount; i++ {
		p := PortIndex(i)
		want := p == granted
		why := "the grant is scoped to " + granted.ID() + " and this row asks about " + p.ID() +
			": a port grant must not widen to a sibling channel (D-009)"
		if want {
			why = "the grant is scoped to exactly this port (" + granted.ID() + ")"
		}
		port := p
		cases = append(cases, Case{
			Name: string(cap) + " on " + p.ID(),
			Req: Request{
				Subject:    User(userID),
				Capability: cap,
				Scope:      PortScope(dev.ID(), port),
				Point:      PointAPI,
				At:         at,
			},
			Want:   want,
			Why:    why,
			Device: dev,
			Do: func(d *RM4PE, _ Engine) error {
				if op == nil {
					return nil
				}
				return op(d, port)
			},
		})
	}
	return cases
}

// StreamBypassCases builds the table docs/modules/permissions.md calls
// "stream-layer enforcement: a session without screen.control cannot pull
// video even by hitting the stream endpoint directly".
//
// Every row expects a deny and every row invokes the gated operation anyway
// (AlsoDoOnDeny), so a check that exists only in the REST handler shows up as
// a BYPASS failure rather than passing quietly.
//
// pull MUST go through the core's stream/tunnel wiring, not straight to the
// device mock: the mock has no authorization, so a pull aimed at it will
// always succeed and the row would fail for the wrong reason. Pointing pull at
// the wiring is what makes this a real test — it asserts the connection the
// session gets cannot carry video, which is the load-bearing rule. The runner
// hands pull the engine it just asked, so under a mutation the wiring consults
// the mutated engine too.
//
// MUTATION CHECK: this table holds down enforcement at the non-API points.
// Make the engine return allow for anything whose Point is not PointAPI (the
// "the transport is trusted" assumption the firmware /streamer finding
// disproved) and these rows go red.
func StreamBypassCases(userID string, dev *RM4PE, target Scope, at time.Time, pull func(d *RM4PE, e Engine) error) []Case {
	points := []EnforcementPoint{PointAPI, PointStream, PointTunnel, PointHID}
	caps := []Capability{CapScreenControl, CapHIDInput}
	cases := make([]Case, 0, len(points)*len(caps))
	for _, cap := range caps {
		for _, pt := range points {
			cases = append(cases, Case{
				Name: string(cap) + " at " + string(pt),
				Req: Request{
					Subject:    User(userID),
					Capability: cap,
					Scope:      target,
					Point:      pt,
					At:         at,
				},
				Want: false,
				Why: userID + " holds no " + string(cap) + " grant on " + target.String() +
					"; the refusal must come from the enforcement point itself, not from the UI hiding a button",
				Device:       dev,
				Do:           pull,
				AlsoDoOnDeny: true,
			})
		}
	}
	return cases
}
