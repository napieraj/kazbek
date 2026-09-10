package authz

import (
	"context"
	"sort"
	"time"
)

// Resolution: effective capabilities = union of group grants + direct grants,
// MINUS explicit denies (docs/modules/permissions.md, "Model").
//
// Two properties are load-bearing and are tested as such.
//
// DENY PRECEDENCE. A deny that matches beats every allow that matches, at any
// scope, unconditionally. It is deliberately NOT "most specific wins": that
// rule requires ranking scopes against each other, and every ranking has an
// ordering where a broad deny loses to a narrow allow. Neither surveyed engine
// (GL's role table, KVM Fleet's constraint layer) had explicit deny at all, so
// there is no prior art to inherit here and the simple rule is the defensible
// one. If you find yourself wanting "this deny should lose to that allow", the
// answer is to not write the deny, not to rank them.
//
// ORDER INDEPENDENCE. The decision must not depend on the order grants arrive
// in. This is a property of the implementation, not just the specification:
// the resolver makes two full passes over the grant set (deny, then allow) and
// never short-circuits on the first match, so shuffling the input cannot
// change the output. TestResolveIsOrderIndependent shuffles and asserts.

// Memberships answers which user-groups a subject belongs to, and which
// device-groups a device belongs to. It is an interface so the core depends on
// no store (D-014); the caller adapts whatever it has.
type Memberships interface {
	// UserGroupsOf returns the group ids a user subject belongs to. For a
	// user-group subject it should return nothing — groups do not nest here.
	UserGroupsOf(ctx context.Context, s Subject) ([]string, error)

	// DeviceGroupsOf returns the device-group ids a device belongs to.
	DeviceGroupsOf(ctx context.Context, deviceID string) ([]string, error)
}

// NoMemberships is the empty implementation: no user is in any group and no
// device is in any group. Direct grants still resolve.
type NoMemberships struct{}

func (NoMemberships) UserGroupsOf(context.Context, Subject) ([]string, error)  { return nil, nil }
func (NoMemberships) DeviceGroupsOf(context.Context, string) ([]string, error) { return nil, nil }

// Resolver decides requests against a grant set.
type Resolver struct {
	grants []Grant
	member Memberships
}

// NewResolver copies the grant slice so a caller mutating theirs afterwards
// cannot change decisions underneath a live session.
func NewResolver(grants []Grant, m Memberships) *Resolver {
	if m == nil {
		m = NoMemberships{}
	}
	cp := make([]Grant, len(grants))
	copy(cp, grants)
	return &Resolver{grants: cp, member: m}
}

// Reasons a decision carries. Tests match on these so a denial has to be the
// RIGHT denial — a check passing for an accidental reason is the failure mode
// AGENTS.md rule 4 exists for.
const (
	ReasonExplicitDeny  = "explicit-deny"
	ReasonGranted       = "granted"
	ReasonNoGrant       = "no-grant"
	ReasonScopeMismatch = "scope-mismatch"
	ReasonBadRequest    = "bad-request"
)

// Decide answers one authorization question.
//
// It returns only allow/deny. Constraints attached to the conferring grant are
// NOT evaluated here — that is Phase 3 — but a constrained grant still confers
// the capability, so callers in the interim must not treat a constrained allow
// as unconditional. ConferringGrants exposes them for that purpose.
func (r *Resolver) Decide(ctx context.Context, req Request) Decision {
	if req.Capability == "" || req.Subject.ID == "" {
		return Denied(ReasonBadRequest)
	}
	if err := req.Scope.Validate(); err != nil {
		return Denied(ReasonBadRequest)
	}
	// A request must name a concrete target. A group is how a grant widens,
	// never something a session acts on.
	if req.Scope.Kind == ScopeDeviceGroup {
		return Denied(ReasonBadRequest)
	}

	subjects, err := r.subjectsFor(ctx, req.Subject)
	if err != nil {
		return Denied(ReasonNoGrant)
	}
	deviceGroups, err := r.member.DeviceGroupsOf(ctx, req.Scope.DeviceID)
	if err != nil {
		return Denied(ReasonNoGrant)
	}

	// PASS 1 — denies. Full pass, no short-circuit on allows.
	for _, g := range r.grants {
		if g.Effect == EffectDeny && r.matches(g, req, subjects, deviceGroups) {
			return Denied(ReasonExplicitDeny)
		}
	}
	// PASS 2 — allows. Only reached when no deny matched.
	for _, g := range r.grants {
		if g.Effect == EffectAllow && r.matches(g, req, subjects, deviceGroups) {
			return Allowed(ReasonGranted)
		}
	}
	return Denied(ReasonNoGrant)
}

// ConferringGrants returns every allow grant that would confer req's
// capability, ignoring denies. Phase 3 uses it to find the constraints in
// play; it is also what makes "granted, but constrained" inspectable.
//
// The result is sorted by grant ID so it too is order-independent.
func (r *Resolver) ConferringGrants(ctx context.Context, req Request) []Grant {
	subjects, err := r.subjectsFor(ctx, req.Subject)
	if err != nil {
		return nil
	}
	deviceGroups, _ := r.member.DeviceGroupsOf(ctx, req.Scope.DeviceID)

	var out []Grant
	for _, g := range r.grants {
		if g.Effect == EffectAllow && r.matches(g, req, subjects, deviceGroups) {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Capabilities resolves the full capability set for a subject against one
// concrete target. This is what D-011's session construction calls ONCE, at
// establishment: the session is then wired with exactly these and there is no
// re-check API.
func (r *Resolver) Capabilities(ctx context.Context, s Subject, target Scope, point EnforcementPoint, at time.Time) []Capability {
	var out []Capability
	for _, c := range AllCapabilities {
		req := Request{Subject: s, Capability: c, Scope: target, Point: point, At: at}
		if r.Decide(ctx, req).Allow {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// subjectsFor expands a user subject into itself plus its user-groups, so a
// grant made to a group matches a request made by a member. Order-independent
// by construction: the result is only ever membership-tested.
func (r *Resolver) subjectsFor(ctx context.Context, s Subject) (map[Subject]bool, error) {
	set := map[Subject]bool{s: true}
	if s.Kind != SubjectUser {
		return set, nil
	}
	groups, err := r.member.UserGroupsOf(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		set[UserGroup(g)] = true
	}
	return set, nil
}

// matches reports whether a grant bears on this request. Capability, subject
// and scope must all match; effect is the caller's business.
func (r *Resolver) matches(g Grant, req Request, subjects map[Subject]bool, deviceGroups []string) bool {
	if g.Capability != req.Capability {
		return false
	}
	if !subjects[g.Subject] {
		return false
	}
	return scopeCovers(g.Scope, req.Scope, deviceGroups)
}

// scopeCovers reports whether a grant's scope covers a concrete target.
//
// The port case is the one with teeth (D-009/D-010): a device-scoped grant
// covers every port on that device, but a PORT-scoped grant covers ONLY its
// own port. Widening a port grant to its siblings is the exact failure the
// port-isolation tests exist to catch — do not "helpfully" relax it.
func scopeCovers(grant, target Scope, targetDeviceGroups []string) bool {
	switch grant.Kind {
	case ScopeDeviceGroup:
		for _, dg := range targetDeviceGroups {
			if dg == grant.GroupID {
				return true
			}
		}
		return false

	case ScopeDevice:
		// Covers the whole device, ports included.
		return grant.DeviceID == target.DeviceID

	case ScopePort:
		if grant.DeviceID != target.DeviceID {
			return false
		}
		// A port grant does NOT confer whole-device access: a request that
		// names no port is asking for more than the grant gives.
		if target.Kind != ScopePort {
			return false
		}
		return grant.Port == target.Port

	default:
		return false
	}
}
