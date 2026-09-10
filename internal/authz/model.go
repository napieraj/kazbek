package authz

// shapes.go
//

import (
	"context"
	"fmt"
	"time"
)

// ---------- subject ----------

// SubjectKind is user or user-group (docs/modules/permissions.md, "Model").
type SubjectKind string

const (
	SubjectUser      SubjectKind = "user"
	SubjectUserGroup SubjectKind = "user-group"
)

// Subject is who a grant is about.
type Subject struct {
	Kind SubjectKind
	ID   string
}

// User builds a user subject.
func User(id string) Subject { return Subject{Kind: SubjectUser, ID: id} }

// UserGroup builds a user-group subject.
func UserGroup(id string) Subject { return Subject{Kind: SubjectUserGroup, ID: id} }

func (s Subject) String() string { return string(s.Kind) + ":" + s.ID }

// ---------- capability ----------

// Capability maps 1:1 to an enforceable device operation
// (docs/modules/permissions.md). A capability is NOT a UI affordance: if
// nothing at the tunnel/stream layer can enforce it, it does not belong here.
type Capability string

const (
	CapView          Capability = "view"
	CapScreenshot    Capability = "screenshot"
	CapScreenControl Capability = "screen.control"
	CapHIDInput      Capability = "hid.input"
	CapATXSoft       Capability = "atx.soft"
	CapATXHard       Capability = "atx.hard"
	CapATXReset      Capability = "atx.reset"
	CapMSDMount      Capability = "msd.mount"
	CapSerial        Capability = "serial"

	// Management capabilities.
	CapPluginInstall Capability = "plugin.install"
	CapISOMount      Capability = "iso.mount"
	CapDeviceAdmin   Capability = "device.admin"
)

// AllCapabilities is the vocabulary from docs/modules/permissions.md. Useful
// for exhaustiveness tests ("every capability has an enforcement point").
var AllCapabilities = []Capability{
	CapView, CapScreenshot, CapScreenControl, CapHIDInput,
	CapATXSoft, CapATXHard, CapATXReset, CapMSDMount, CapSerial,
	CapPluginInstall, CapISOMount, CapDeviceAdmin,
}

// ---------- scope ----------

// ScopeKind is device, device-group, or port (D-009).
type ScopeKind string

const (
	ScopeDevice      ScopeKind = "device"
	ScopeDeviceGroup ScopeKind = "device-group"
	ScopePort        ScopeKind = "port"
)

// Scope is what a grant or a request applies to. It is deliberately a
// comparable value (no pointers, no slices) so it can be a map key and be
// compared with ==.
type Scope struct {
	Kind     ScopeKind
	DeviceID string    // device and port scopes
	GroupID  string    // device-group scope
	Port     PortIndex // port scope; PortNone otherwise
}

// DeviceScope scopes to a whole device.
func DeviceScope(deviceID string) Scope {
	return Scope{Kind: ScopeDevice, DeviceID: deviceID, Port: PortNone}
}

// DeviceGroupScope scopes to a device group.
func DeviceGroupScope(groupID string) Scope {
	return Scope{Kind: ScopeDeviceGroup, GroupID: groupID, Port: PortNone}
}

// PortScope scopes to one channel of one device (D-009 — the Comet X / RM4PE
// case that forced a port scope into the model).
func PortScope(deviceID string, port PortIndex) Scope {
	return Scope{Kind: ScopePort, DeviceID: deviceID, Port: port}
}

func (s Scope) String() string {
	switch s.Kind {
	case ScopeDevice:
		return "device:" + s.DeviceID
	case ScopeDeviceGroup:
		return "device-group:" + s.GroupID
	case ScopePort:
		return "port:" + s.DeviceID + "/" + s.Port.ID()
	default:
		return "scope:<invalid>"
	}
}

// Validate rejects malformed scopes. Fixtures call it so a typo in a test
// table fails loudly instead of silently denying.
func (s Scope) Validate() error {
	switch s.Kind {
	case ScopeDevice:
		if s.DeviceID == "" {
			return fmt.Errorf("fixtures: device scope needs a DeviceID")
		}
	case ScopeDeviceGroup:
		if s.GroupID == "" {
			return fmt.Errorf("fixtures: device-group scope needs a GroupID")
		}
	case ScopePort:
		if s.DeviceID == "" {
			return fmt.Errorf("fixtures: port scope needs a DeviceID")
		}
		if !s.Port.Valid() {
			return fmt.Errorf("fixtures: port scope needs a valid port, got %d", int(s.Port))
		}
	default:
		return fmt.Errorf("fixtures: unknown scope kind %q", s.Kind)
	}
	return nil
}

// ---------- constraints ----------

// ConstraintKind is one of the three constraints in
// docs/modules/permissions.md: requires_presence (ceremony tap), time_window,
// and approval (four-eyes).
type ConstraintKind string

const (
	ConstraintRequiresPresence ConstraintKind = "requires_presence"
	ConstraintTimeWindow       ConstraintKind = "time_window"
	ConstraintFourEyes         ConstraintKind = "four_eyes"
)

// Constraint is attached to a grant. Only the field belonging to Kind is
// meaningful; the others are zero.
type Constraint struct {
	Kind ConstraintKind

	// Window applies when Kind == ConstraintTimeWindow.
	Window TimeWindow

	// Approvals is the number of DISTINCT approvers required when
	// Kind == ConstraintFourEyes. "Four eyes" is two people, so the usual
	// value is 2 — and the approver must not be the requester, which is a
	// check worth mutation-testing on its own.
	Approvals int
}

// RequiresPresence builds the ceremony-tap constraint.
func RequiresPresence() Constraint { return Constraint{Kind: ConstraintRequiresPresence} }

// WithinWindow builds a time-window constraint.
func WithinWindow(w TimeWindow) Constraint {
	return Constraint{Kind: ConstraintTimeWindow, Window: w}
}

// FourEyes builds an approval constraint requiring n distinct approvers.
func FourEyes(n int) Constraint { return Constraint{Kind: ConstraintFourEyes, Approvals: n} }

// TimeOfDay is a wall-clock time, minute granularity.
type TimeOfDay struct {
	Hour   int
	Minute int
}

func (t TimeOfDay) minutes() int { return t.Hour*60 + t.Minute }

func (t TimeOfDay) String() string { return fmt.Sprintf("%02d:%02d", t.Hour, t.Minute) }

// TimeWindow is a recurring wall-clock window. Start > End means the window
// crosses midnight. Days empty means every day. Location nil means UTC.
type TimeWindow struct {
	Start    TimeOfDay
	End      TimeOfDay
	Days     []time.Weekday
	Location *time.Location
}

// Contains reports whether the instant falls inside the window.
//
func (w TimeWindow) Contains(t time.Time) bool {
	loc := w.Location
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	if len(w.Days) > 0 {
		ok := false
		for _, d := range w.Days {
			if d == lt.Weekday() {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	cur := lt.Hour()*60 + lt.Minute()
	start, end := w.Start.minutes(), w.End.minutes()
	if start <= end {
		return cur >= start && cur <= end
	}
	// Crosses midnight.
	return cur >= start || cur <= end
}

func (w TimeWindow) String() string {
	return fmt.Sprintf("%s-%s", w.Start, w.End)
}

// WindowOpenAt returns a window that contains t (t plus/minus an hour, every
// day). Use it for the "inside hours" leg of a time_window test without doing
// clock arithmetic in the test.
func WindowOpenAt(t time.Time) TimeWindow {
	return TimeWindow{
		Start:    todOf(t.Add(-time.Hour)),
		End:      todOf(t.Add(time.Hour)),
		Location: t.Location(),
	}
}

// WindowClosedAt returns a window that does NOT contain t (the hour starting an
// hour after t, every day). Use it for the "outside hours denies" leg.
func WindowClosedAt(t time.Time) TimeWindow {
	return TimeWindow{
		Start:    todOf(t.Add(time.Hour)),
		End:      todOf(t.Add(2 * time.Hour)),
		Location: t.Location(),
	}
}

func todOf(t time.Time) TimeOfDay { return TimeOfDay{Hour: t.Hour(), Minute: t.Minute()} }

// ---------- grant ----------

// Effect is allow or deny. Explicit denies exist because
// docs/modules/permissions.md defines effective capabilities as
// "union of group grants + direct grants, MINUS explicit denies" — so a deny
// must be representable, and deny-wins is a check worth mutation-testing.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Grant is the unit of authorization: (subject, capability, scope,
// constraints?), plus an effect.
type Grant struct {
	ID          string
	Subject     Subject
	Capability  Capability
	Scope       Scope
	Effect      Effect
	Constraints []Constraint
}

func (g Grant) String() string {
	s := fmt.Sprintf("%s %s %s on %s", g.Effect, g.Subject, g.Capability, g.Scope)
	for _, c := range g.Constraints {
		s += " +" + string(c.Kind)
	}
	return s
}

// ---------- request / decision ----------

// EnforcementPoint is WHERE the check is being made. It exists because
// docs/modules/permissions.md makes the load-bearing rule "enforce at the
// tunnel/stream layer, not the UI": a decision that is only ever asked for at
// PointAPI is exactly the bug the firmware /streamer finding warned about.
//
// A test that drives PointStream is asserting that a caller who skips the API
// and hits the stream endpoint directly still gets refused.
type EnforcementPoint string

const (
	PointAPI    EnforcementPoint = "api"    // the REST handler
	PointStream EnforcementPoint = "stream" // the video/streamer endpoint — the bypass surface
	PointTunnel EnforcementPoint = "tunnel" // the device tunnel setup
	PointHID    EnforcementPoint = "hid"    // the HID channel
)

// Request is a concrete authorization question. Scope here is always a
// CONCRETE target (a device or a port), never a group: groups widen a grant,
// they are not something a session acts on.
type Request struct {
	Subject    Subject
	Capability Capability
	Scope      Scope
	Point      EnforcementPoint
	At         time.Time

	// PresenceProven is set when the ceremony tap has been observed for this
	// session (requires_presence).
	PresenceProven bool

	// Approvals are the subject ids that have approved this action (four_eyes).
	Approvals []string
}

// Decision is the answer. Reason is a short machine-ish code — the harness can
// match on it so a test asserts not just "denied" but "denied for the right
// reason", which is what stops a check from passing by accident.
type Decision struct {
	Allow  bool
	Reason string
}

// Allowed builds an allow decision.
func Allowed(reason string) Decision { return Decision{Allow: true, Reason: reason} }

// Denied builds a deny decision.
func Denied(reason string) Decision { return Decision{Allow: false, Reason: reason} }

func (d Decision) String() string {
	if d.Allow {
		return "allow(" + d.Reason + ")"
	}
	return "deny(" + d.Reason + ")"
}

// Engine is what the harness drives. The Phase 1 core is expected to satisfy
// this, or to be wrapped in three lines by whoever writes its tests.
type Engine interface {
	Decide(ctx context.Context, req Request) Decision
}

// EngineFunc adapts a function to Engine.
type EngineFunc func(ctx context.Context, req Request) Decision

// Decide implements Engine.
func (f EngineFunc) Decide(ctx context.Context, req Request) Decision { return f(ctx, req) }
