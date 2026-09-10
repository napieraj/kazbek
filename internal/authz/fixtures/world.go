package fixtures

// world.go — the grant/subject fixture builder.
//
// PROVISIONAL — OWNED BY THE PHASE 1 AUTHORIZATION CORE (see shapes.go).
// World is a test-side stand-in for whatever store the core loads grants and
// memberships from. If the core grows a real store, keep World as the fixture
// that populates it and delete the accessors the core supersedes.

import (
	"fmt"
	"sort"
	"time"
)

// World holds the grants, the group memberships and the mock devices a test
// operates on. It is the argument you hand to a core engine constructor.
//
// Every mutator returns *World so a fixture reads as one statement.
type World struct {
	grants       []Grant
	userGroups   map[string][]string // user id -> user-group ids
	deviceGroups map[string][]string // device id -> device-group ids
	devices      map[string]*RM4PE
	nextID       int
}

// NewWorld returns an empty world.
func NewWorld() *World {
	return &World{
		userGroups:   map[string][]string{},
		deviceGroups: map[string][]string{},
		devices:      map[string]*RM4PE{},
	}
}

// AddUserToGroup records a user-group membership. Membership is what makes
// "effective capabilities = union of group grants + direct grants" testable
// (docs/modules/permissions.md).
func (w *World) AddUserToGroup(userID, groupID string) *World {
	if !contains(w.userGroups[userID], groupID) {
		w.userGroups[userID] = append(w.userGroups[userID], groupID)
	}
	return w
}

// AddDeviceToGroup records a device-group membership. This is the widening a
// device-group grant travels along.
func (w *World) AddDeviceToGroup(deviceID, groupID string) *World {
	if !contains(w.deviceGroups[deviceID], groupID) {
		w.deviceGroups[deviceID] = append(w.deviceGroups[deviceID], groupID)
	}
	return w
}

// AddRM4PE registers a 4-port device mock under the given kazbek device id and
// returns it for seeding. Panics on a duplicate id — a silently shared device
// between two fixtures produces a false green.
func (w *World) AddRM4PE(deviceID string) *RM4PE {
	if _, dup := w.devices[deviceID]; dup {
		panic(fmt.Sprintf("fixtures: device %q already registered", deviceID))
	}
	d := NewRM4PE(deviceID)
	w.devices[deviceID] = d
	return d
}

// Device returns a registered device mock, or nil.
func (w *World) Device(deviceID string) *RM4PE { return w.devices[deviceID] }

// Add appends grants, assigning an id to any grant that lacks one so that a
// failure message can name the grant that produced it.
func (w *World) Add(grants ...Grant) *World {
	for _, g := range grants {
		if err := g.Scope.Validate(); err != nil {
			panic(fmt.Sprintf("fixtures: invalid grant %s: %v", g, err))
		}
		if g.ID == "" {
			w.nextID++
			g.ID = fmt.Sprintf("g%d", w.nextID)
		}
		w.grants = append(w.grants, g)
	}
	return w
}

// Grants returns a copy of every grant in the world.
func (w *World) Grants() []Grant {
	out := make([]Grant, len(w.grants))
	copy(out, w.grants)
	return out
}

// GroupsOfUser returns the user-group ids a user belongs to, sorted.
func (w *World) GroupsOfUser(userID string) []string { return sortedCopy(w.userGroups[userID]) }

// GroupsOfDevice returns the device-group ids a device belongs to, sorted.
func (w *World) GroupsOfDevice(deviceID string) []string {
	return sortedCopy(w.deviceGroups[deviceID])
}

// SubjectChain returns every subject a request from this user is evaluated
// against: the user itself, then each of its groups. An engine that forgets
// the group leg denies too much; one that forgets the user leg denies too much
// too — both are visible as failures in a table that covers each.
func (w *World) SubjectChain(userID string) []Subject {
	out := []Subject{User(userID)}
	for _, g := range w.GroupsOfUser(userID) {
		out = append(out, UserGroup(g))
	}
	return out
}

// ScopeChain returns the scopes a grant may sit on and still cover the given
// concrete target, from most specific to least: the port itself, then its
// device, then that device's groups.
//
// This is the ONE-WAY widening that makes port isolation work. A grant on the
// device reaches its ports; a grant on port 1 reaches NOTHING but port 1 — not
// port 3, and not the device as a whole. If an engine's scope matching is
// symmetric, this chain will not catch it but the port-isolation table will:
// see PortIsolationCases.
func (w *World) ScopeChain(target Scope) []Scope {
	switch target.Kind {
	case ScopePort:
		out := []Scope{target, DeviceScope(target.DeviceID)}
		for _, g := range w.GroupsOfDevice(target.DeviceID) {
			out = append(out, DeviceGroupScope(g))
		}
		return out
	case ScopeDevice:
		out := []Scope{target}
		for _, g := range w.GroupsOfDevice(target.DeviceID) {
			out = append(out, DeviceGroupScope(g))
		}
		return out
	case ScopeDeviceGroup:
		return []Scope{target}
	default:
		return nil
	}
}

// GrantsFor returns every grant whose subject is in the request's subject
// chain and whose scope is in the target's scope chain — i.e. the candidate
// set an engine must consider. It applies NO constraint evaluation and NO
// deny-override: those are the engine's job, and a fixture that did them would
// be marking its own homework.
func (w *World) GrantsFor(userID string, cap Capability, target Scope) []Grant {
	subjects := map[Subject]bool{}
	for _, s := range w.SubjectChain(userID) {
		subjects[s] = true
	}
	scopes := map[Scope]bool{}
	for _, s := range w.ScopeChain(target) {
		scopes[s] = true
	}
	var out []Grant
	for _, g := range w.grants {
		if g.Capability == cap && subjects[g.Subject] && scopes[g.Scope] {
			out = append(out, g)
		}
	}
	return out
}

// ---------- grant builder ----------

// GrantBuilder constructs a Grant readably. Use GrantFor to start one.
//
//	fixtures.GrantFor(fixtures.User("alice"), fixtures.CapATXHard).
//	    OnPort("kvm-1", 3).
//	    RequiringPresence().
//	    RequiringApprovals(2).
//	    Build()
type GrantBuilder struct {
	g       Grant
	scopeOK bool
}

// GrantFor starts an allow grant for a subject and capability.
func GrantFor(subject Subject, cap Capability) *GrantBuilder {
	return &GrantBuilder{g: Grant{Subject: subject, Capability: cap, Effect: EffectAllow}}
}

// DenyFor starts an explicit deny. Explicit denies subtract from the union
// (docs/modules/permissions.md); an engine that ORs everything together will
// pass every allow test and fail only here.
func DenyFor(subject Subject, cap Capability) *GrantBuilder {
	return &GrantBuilder{g: Grant{Subject: subject, Capability: cap, Effect: EffectDeny}}
}

// WithID names the grant so failures can point at it.
func (b *GrantBuilder) WithID(id string) *GrantBuilder { b.g.ID = id; return b }

// OnDevice scopes the grant to a whole device.
func (b *GrantBuilder) OnDevice(deviceID string) *GrantBuilder {
	b.g.Scope = DeviceScope(deviceID)
	b.scopeOK = true
	return b
}

// OnDeviceGroup scopes the grant to a device group.
func (b *GrantBuilder) OnDeviceGroup(groupID string) *GrantBuilder {
	b.g.Scope = DeviceGroupScope(groupID)
	b.scopeOK = true
	return b
}

// OnPort scopes the grant to one channel of one device (D-009).
func (b *GrantBuilder) OnPort(deviceID string, port PortIndex) *GrantBuilder {
	b.g.Scope = PortScope(deviceID, port)
	b.scopeOK = true
	return b
}

// RequiringPresence attaches the ceremony-tap constraint.
func (b *GrantBuilder) RequiringPresence() *GrantBuilder {
	b.g.Constraints = append(b.g.Constraints, RequiresPresence())
	return b
}

// WithinTimeWindow attaches a time-window constraint.
func (b *GrantBuilder) WithinTimeWindow(w TimeWindow) *GrantBuilder {
	b.g.Constraints = append(b.g.Constraints, WithinWindow(w))
	return b
}

// RequiringApprovals attaches a four-eyes constraint requiring n distinct
// approvers.
func (b *GrantBuilder) RequiringApprovals(n int) *GrantBuilder {
	b.g.Constraints = append(b.g.Constraints, FourEyes(n))
	return b
}

// Build returns the grant. It panics if no scope was set or the scope is
// malformed: a fixture with a silently empty scope would make every test using
// it pass for the wrong reason.
func (b *GrantBuilder) Build() Grant {
	if !b.scopeOK {
		panic(fmt.Sprintf("fixtures: grant %s %s has no scope; call OnDevice/OnDeviceGroup/OnPort",
			b.g.Subject, b.g.Capability))
	}
	if err := b.g.Scope.Validate(); err != nil {
		panic("fixtures: " + err.Error())
	}
	return b.g
}

// ---------- request builder ----------

// Ask builds a Request for a user at an enforcement point. Chain the With*
// methods to add presence, approvals or a timestamp.
type RequestBuilder struct{ r Request }

// Ask starts a request from a user (not a group — sessions belong to users).
func Ask(userID string, cap Capability) *RequestBuilder {
	return &RequestBuilder{r: Request{
		Subject:    User(userID),
		Capability: cap,
		Point:      PointAPI,
		Scope:      Scope{Port: PortNone},
	}}
}

// OnDevice targets a whole device.
func (b *RequestBuilder) OnDevice(deviceID string) *RequestBuilder {
	b.r.Scope = DeviceScope(deviceID)
	return b
}

// OnPort targets one channel.
func (b *RequestBuilder) OnPort(deviceID string, port PortIndex) *RequestBuilder {
	b.r.Scope = PortScope(deviceID, port)
	return b
}

// At sets the enforcement point. The default is PointAPI; a bypass test MUST
// set PointStream, because asking at the API is exactly the check an attacker
// skips.
func (b *RequestBuilder) At(p EnforcementPoint) *RequestBuilder { b.r.Point = p; return b }

// When sets the decision timestamp (time_window).
func (b *RequestBuilder) When(ts time.Time) *RequestBuilder { b.r.At = ts; return b }

// WithPresence marks the ceremony tap as observed.
func (b *RequestBuilder) WithPresence() *RequestBuilder { b.r.PresenceProven = true; return b }

// ApprovedBy records approvers for a four-eyes constraint.
func (b *RequestBuilder) ApprovedBy(userIDs ...string) *RequestBuilder {
	b.r.Approvals = append(b.r.Approvals, userIDs...)
	return b
}

// Build returns the request.
func (b *RequestBuilder) Build() Request { return b.r }

// ---------- helpers ----------

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedCopy(xs []string) []string {
	out := make([]string, len(xs))
	copy(out, xs)
	sort.Strings(out)
	return out
}
