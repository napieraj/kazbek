package plugins

import (
	"crypto/sha256"
	"encoding/hex"
)

// Runtime tiers. This is the blast-radius split: a device plugin's worst case
// is one console, a management plugin's worst case is the fleet, and the two
// must never be reachable through the same load path (invariant 6).
const (
	RuntimeDevice     = "device"
	RuntimeManagement = "management"
)

// Verifier is the swap seam.
//
// Signing is deferred, but the place signing will go is not. Everything
// downstream of this interface — transport, placement, rollback, readback — is
// identical whichever crypto eventually lands, so the crypto is a hook, and
// the hook is specified now and filled later. Nothing downstream knows or
// cares which implementation is behind it.
type Verifier interface {
	Name() string
	// Verify returns nil to accept, or a *RefusalError to refuse.
	Verify(m *Manifest, payload []byte) error
}

// VerifierNoop accepts any payload.
//
// It does NOT skip the gate's structural checks — that distinction is the
// whole reason noop is tolerable in a tree at all. It disables authenticity
// checking, not path safety.
//
// Dev only. Never a default in any real config; Resolve fails closed rather
// than falling back to this.
type VerifierNoop struct{}

func (VerifierNoop) Name() string { return "noop" }

func (VerifierNoop) Verify(_ *Manifest, _ []byte) error { return nil }

// VerifierHashOnly is the buildable-now floor: integrity without authenticity.
// It refuses unless the payload hashes to what the manifest claims, and it
// ignores the signature block entirely.
type VerifierHashOnly struct{}

func (VerifierHashOnly) Name() string { return "hash-only" }

func (VerifierHashOnly) Verify(m *Manifest, payload []byte) error {
	sum := sha256.Sum256(payload)
	got := hex.EncodeToString(sum[:])
	if got != m.Payload.SHA256 {
		return refuse(CodePayloadHashMismatch, "payload sha256 %s, manifest %s", got, m.Payload.SHA256)
	}
	return nil
}

// Resolve maps a configured verifier name to an implementation.
//
// It fails closed. An absent name, an unrecognised name, and "signed" (which
// is deliberately not a v1 tier) all refuse rather than silently downgrading
// to noop — a config typo must not become an open door.
func Resolve(name string) (Verifier, error) {
	switch name {
	case "noop":
		return VerifierNoop{}, nil
	case "hash-only":
		return VerifierHashOnly{}, nil
	default:
		return nil, refuse(CodeVerifyUnconfigured, "verifier %q is not a v1 tier", name)
	}
}
