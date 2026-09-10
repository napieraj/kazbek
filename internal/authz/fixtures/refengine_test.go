package fixtures

// refengine_test.go — a reference capability engine, TEST-ONLY.
//
// This is NOT the Phase 1 core and must not become it. It exists so this
// package's own tests can prove the harness and the mutation helper work: a
// harness that has never been pointed at an engine is not test infrastructure,
// it is a hope. It implements Mutable and Checked so the mechanical mutation
// path is exercised end to end.
//
// It deliberately implements the model from docs/modules/permissions.md and
// nothing else: union of group + direct grants, minus explicit denies, widened
// along the scope chain, with the three constraints, enforced at every point
// and not only at the API.

import "context"

const (
	checkSubject  = "subject-match"
	checkScope    = "scope-match"
	checkDeny     = "deny-override"
	checkPoint    = "enforce-at-transport"
	checkPresence = "constraint:requires_presence"
	checkWindow   = "constraint:time_window"
	checkFourEyes = "constraint:four_eyes"
)

type refEngine struct {
	w   *World
	off map[string]bool
}

func newRefEngine(w *World) *refEngine { return &refEngine{w: w, off: map[string]bool{}} }

func (e *refEngine) Checks() []string {
	return []string{checkSubject, checkScope, checkDeny, checkPoint, checkPresence, checkWindow, checkFourEyes}
}

func (e *refEngine) WithoutCheck(name string) (Engine, bool) {
	known := false
	for _, c := range e.Checks() {
		if c == name {
			known = true
			break
		}
	}
	if !known {
		return nil, false
	}
	off := make(map[string]bool, len(e.off)+1)
	for k, v := range e.off {
		off[k] = v
	}
	off[name] = true
	return &refEngine{w: e.w, off: off}, true
}

func (e *refEngine) on(name string) bool { return !e.off[name] }

func (e *refEngine) Decide(_ context.Context, req Request) Decision {
	// The load-bearing rule: the decision is the same wherever it is asked.
	// Dropping this check models "we only check in the REST handler" — the
	// /streamer bypass class.
	if !e.on(checkPoint) && req.Point != PointAPI {
		return Allowed("transport-unchecked")
	}

	subjects := map[Subject]bool{}
	for _, s := range e.w.SubjectChain(req.Subject.ID) {
		subjects[s] = true
	}
	scopes := map[Scope]bool{}
	for _, s := range e.w.ScopeChain(req.Scope) {
		scopes[s] = true
	}

	var allows []Grant
	for _, g := range e.w.Grants() {
		if g.Capability != req.Capability {
			continue
		}
		if e.on(checkSubject) && !subjects[g.Subject] {
			continue
		}
		if e.on(checkScope) && !scopes[g.Scope] {
			continue
		}
		if g.Effect == EffectDeny {
			if e.on(checkDeny) {
				return Denied("explicit-deny:" + g.ID)
			}
			continue
		}
		allows = append(allows, g)
	}
	if len(allows) == 0 {
		return Denied("no-grant")
	}
	blocked := "no-grant"
	for _, g := range allows {
		reason, ok := e.constraintsOK(g, req)
		if ok {
			return Allowed("grant:" + g.ID)
		}
		blocked = reason
	}
	return Denied(blocked)
}

func (e *refEngine) constraintsOK(g Grant, req Request) (string, bool) {
	for _, c := range g.Constraints {
		switch c.Kind {
		case ConstraintRequiresPresence:
			if e.on(checkPresence) && !req.PresenceProven {
				return string(ConstraintRequiresPresence), false
			}
		case ConstraintTimeWindow:
			if e.on(checkWindow) && !c.Window.Contains(req.At) {
				return string(ConstraintTimeWindow), false
			}
		case ConstraintFourEyes:
			if e.on(checkFourEyes) {
				distinct := map[string]bool{}
				for _, a := range req.Approvals {
					if a != req.Subject.ID { // an approval from the requester is not four eyes
						distinct[a] = true
					}
				}
				if len(distinct) < c.Approvals {
					return string(ConstraintFourEyes), false
				}
			}
		}
	}
	return "", true
}
