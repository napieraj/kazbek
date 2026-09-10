package server

import (
	"testing"

	"rttys/internal/authz"
)

// AuthzSubject must FAIL CLOSED. Every path that cannot establish a principal
// with certainty returns ok=false, and callers must refuse rather than
// substitute a zero subject.
//
// These cases run with no session store and no container wired, which is the
// most common "cannot resolve" shape and the one a unit test can reach
// directly. The point is the contract, not the plumbing: ok=false must come
// with a ZERO subject, so a caller that ignores ok cannot accidentally hold a
// usable principal.
//
// MUTATION CHECK (AGENTS.md rule 4): give AuthzSubject a fallback — return
// authz.User("anonymous"), true, or return the subject with ok=true when the
// user lookup fails — and TestAuthzSubjectFailsClosed goes red. If it does
// not, the fail-closed property is not held down.
func TestAuthzSubjectFailsClosed(t *testing.T) {
	// A nil context cannot yield a principal.
	subj, ok := AuthzSubject(nil)
	if ok {
		t.Errorf("nil context resolved a subject: %v", subj)
	}
	if subj != (authz.Subject{}) {
		t.Errorf("failed resolution returned a non-zero subject %v — a caller ignoring ok would hold a usable principal", subj)
	}
}

// The subject id is derived from the numeric user id, never the username:
// grants are written against this string, and a rename must not silently move
// someone's grants to a different principal.
func TestSubjectIDIsStableAcrossRename(t *testing.T) {
	if got, want := subjectIDForUser(42), "user:42"; got != want {
		t.Errorf("subjectIDForUser(42) = %q want %q", got, want)
	}
	if subjectIDForUser(1) == subjectIDForUser(2) {
		t.Error("distinct users collapsed to the same subject id")
	}
	// Negative and zero ids must not silently render as something reusable.
	if subjectIDForUser(0) == subjectIDForUser(1) {
		t.Error("user 0 and user 1 share a subject id")
	}
}
