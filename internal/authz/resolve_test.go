package authz

import (
	"context"
	"math/rand"
	"testing"
	"time"
)

type fakeMembers struct {
	userGroups   map[string][]string
	deviceGroups map[string][]string
}

func (f fakeMembers) UserGroupsOf(_ context.Context, s Subject) ([]string, error) {
	return f.userGroups[s.ID], nil
}
func (f fakeMembers) DeviceGroupsOf(_ context.Context, d string) ([]string, error) {
	return f.deviceGroups[d], nil
}

func req(u string, c Capability, sc Scope) Request {
	return Request{Subject: User(u), Capability: c, Scope: sc, Point: PointTunnel, At: time.Now()}
}

// ---------------------------------------------------------------------------
// DENY PRECEDENCE — the hardest-checked property.
//
// Neither surveyed engine had explicit deny, so there is no prior art to lean
// on and the bug here would be SILENT: a deny that fails to override a union
// of allows produces an allow, which no ordinary test notices because allows
// are the expected outcome everywhere else.
//
// MUTATION CHECK (AGENTS.md rule 4): in Resolve's Decide, delete the deny pass
// (PASS 1) or move it after the allow pass, and every subtest below whose name
// starts "deny" goes red. If any survives, the deny path is not held down.
// ---------------------------------------------------------------------------

func TestDenyOverridesEveryAllow(t *testing.T) {
	ctx := context.Background()
	dev := DeviceScope("dev1")

	cases := []struct {
		name   string
		grants []Grant
		target Scope // the concrete thing being asked about
		want   bool
		reason string
	}{
		{
			name: "deny beats a direct allow on the same scope",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapATXHard, Scope: dev, Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapATXHard, Scope: dev, Effect: EffectDeny},
			},
			want: false, reason: ReasonExplicitDeny,
		},
		{
			name: "deny beats an allow inherited from a user-group",
			grants: []Grant{
				{ID: "a", Subject: UserGroup("ops"), Capability: CapATXHard, Scope: dev, Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapATXHard, Scope: dev, Effect: EffectDeny},
			},
			want: false, reason: ReasonExplicitDeny,
		},
		{
			name: "deny beats an allow inherited from a device-group",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapATXHard, Scope: DeviceGroupScope("rack1"), Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapATXHard, Scope: dev, Effect: EffectDeny},
			},
			want: false, reason: ReasonExplicitDeny,
		},
		{
			// The target is the PORT, so the narrow allow genuinely matches
			// and genuinely competes. Targeting the device instead would make
			// this vacuous — the port allow would not match at all and the
			// case would pass without exercising precedence. (Found by the
			// mutation check: it was the one deny case that survived moving
			// the deny pass after the allow pass.)
			name: "a BROAD deny beats a NARROW allow — precedence is not specificity",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapView, Scope: PortScope("dev1", 1), Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapView, Scope: dev, Effect: EffectDeny},
			},
			target: PortScope("dev1", 1),
			want:   false, reason: ReasonExplicitDeny,
		},
		{
			name: "deny at the group level beats a direct allow",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapMSDMount, Scope: dev, Effect: EffectAllow},
				{ID: "d", Subject: UserGroup("ops"), Capability: CapMSDMount, Scope: dev, Effect: EffectDeny},
			},
			want: false, reason: ReasonExplicitDeny,
		},
		{
			name: "deny is capability-scoped: it must NOT deny a different capability",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapView, Scope: dev, Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapATXHard, Scope: dev, Effect: EffectDeny},
			},
			want: true, reason: ReasonGranted,
		},
		{
			name: "deny is device-scoped: it must NOT reach a different device",
			grants: []Grant{
				{ID: "a", Subject: User("u"), Capability: CapView, Scope: dev, Effect: EffectAllow},
				{ID: "d", Subject: User("u"), Capability: CapView, Scope: DeviceScope("dev2"), Effect: EffectDeny},
			},
			want: true, reason: ReasonGranted,
		},
	}

	m := fakeMembers{
		userGroups:   map[string][]string{"u": {"ops"}},
		deviceGroups: map[string][]string{"dev1": {"rack1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			if target.Kind == "" {
				target = dev
			}
			got := NewResolver(tc.grants, m).Decide(ctx, req("u", tc.grants[0].Capability, target))
			if got.Allow != tc.want {
				t.Fatalf("allow=%v want %v (reason %q)", got.Allow, tc.want, got.Reason)
			}
			if got.Reason != tc.reason {
				t.Errorf("reason=%q want %q — right answer for the wrong reason is not a pass",
					got.Reason, tc.reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ORDER INDEPENDENCE — a property of the implementation, not the spec.
// Shuffling the grant set must not change any decision.
// ---------------------------------------------------------------------------

func TestResolveIsOrderIndependent(t *testing.T) {
	ctx := context.Background()
	m := fakeMembers{
		userGroups:   map[string][]string{"u": {"ops", "oncall"}},
		deviceGroups: map[string][]string{"dev1": {"rack1"}},
	}
	grants := []Grant{
		{ID: "g1", Subject: User("u"), Capability: CapView, Scope: DeviceScope("dev1"), Effect: EffectAllow},
		{ID: "g2", Subject: UserGroup("ops"), Capability: CapView, Scope: DeviceGroupScope("rack1"), Effect: EffectAllow},
		{ID: "g3", Subject: User("u"), Capability: CapATXHard, Scope: DeviceScope("dev1"), Effect: EffectAllow},
		{ID: "g4", Subject: UserGroup("oncall"), Capability: CapATXHard, Scope: DeviceScope("dev1"), Effect: EffectDeny},
		{ID: "g5", Subject: User("u"), Capability: CapHIDInput, Scope: PortScope("dev1", 1), Effect: EffectAllow},
		{ID: "g6", Subject: User("u"), Capability: CapMSDMount, Scope: DeviceGroupScope("rack1"), Effect: EffectAllow},
		{ID: "g7", Subject: UserGroup("ops"), Capability: CapMSDMount, Scope: DeviceScope("dev1"), Effect: EffectDeny},
	}

	probes := []Request{
		req("u", CapView, DeviceScope("dev1")),
		req("u", CapATXHard, DeviceScope("dev1")),
		req("u", CapMSDMount, DeviceScope("dev1")),
		req("u", CapHIDInput, PortScope("dev1", 1)),
		req("u", CapHIDInput, PortScope("dev1", 3)),
		req("u", CapSerial, DeviceScope("dev1")),
	}

	want := make([]Decision, len(probes))
	for i, p := range probes {
		want[i] = NewResolver(grants, m).Decide(ctx, p)
	}

	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		shuffled := make([]Grant, len(grants))
		copy(shuffled, grants)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		r := NewResolver(shuffled, m)
		for i, p := range probes {
			got := r.Decide(ctx, p)
			if got != want[i] {
				t.Fatalf("iter %d: order changed the decision for %s on %s: got %v want %v\norder: %v",
					iter, p.Capability, p.Scope, got, want[i], ids(shuffled))
			}
		}
	}
}

func ids(gs []Grant) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.ID
	}
	return out
}

// ---------------------------------------------------------------------------
// PORT ISOLATION (D-009/D-010).
// ---------------------------------------------------------------------------

func TestPortGrantDoesNotWiden(t *testing.T) {
	ctx := context.Background()
	r := NewResolver([]Grant{
		{ID: "p1", Subject: User("u"), Capability: CapView, Scope: PortScope("dev1", 1), Effect: EffectAllow},
	}, nil)

	if d := r.Decide(ctx, req("u", CapView, PortScope("dev1", 1))); !d.Allow {
		t.Errorf("grant on port 1 should reach port 1: %v", d)
	}
	for _, p := range []PortIndex{0, 2, 3} {
		if d := r.Decide(ctx, req("u", CapView, PortScope("dev1", p))); d.Allow {
			t.Errorf("grant on port 1 REACHED port %d — port scope is not isolating", p)
		}
	}
	// A port grant must not confer whole-device access.
	if d := r.Decide(ctx, req("u", CapView, DeviceScope("dev1"))); d.Allow {
		t.Errorf("port grant widened to the whole device: %v", d)
	}
	// A device grant does cover every port.
	rd := NewResolver([]Grant{
		{ID: "d1", Subject: User("u"), Capability: CapView, Scope: DeviceScope("dev1"), Effect: EffectAllow},
	}, nil)
	for _, p := range []PortIndex{0, 1, 2, 3} {
		if d := rd.Decide(ctx, req("u", CapView, PortScope("dev1", p))); !d.Allow {
			t.Errorf("device grant did not cover port %d: %v", p, d)
		}
	}
}

// A request may not name a group: groups widen grants, they are not targets.
func TestGroupIsNotARequestTarget(t *testing.T) {
	r := NewResolver([]Grant{
		{ID: "g", Subject: User("u"), Capability: CapView, Scope: DeviceGroupScope("rack1"), Effect: EffectAllow},
	}, nil)
	d := r.Decide(context.Background(), req("u", CapView, DeviceGroupScope("rack1")))
	if d.Allow || d.Reason != ReasonBadRequest {
		t.Errorf("a group-scoped request should be a bad request, got %v", d)
	}
}

// The empty grant set denies everything, and says why.
func TestNoGrantsDeniesWithReason(t *testing.T) {
	r := NewResolver(nil, nil)
	for _, c := range AllCapabilities {
		d := r.Decide(context.Background(), req("u", c, DeviceScope("dev1")))
		if d.Allow {
			t.Errorf("empty grant set allowed %s", c)
		}
		if d.Reason != ReasonNoGrant {
			t.Errorf("%s denied for %q, want %q", c, d.Reason, ReasonNoGrant)
		}
	}
}
