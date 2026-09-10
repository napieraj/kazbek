package plugins

// Gate is the single choke point where an install can be refused.
//
// Both halves call Gate and never a Verifier directly. That is what makes
// invariant 3 a single testable claim rather than a property scattered across
// two codebases and two languages.
//
// The contract on every caller:
//
//	If Gate refuses, the caller MUST NOT unpack, place, or load.
//	Nothing may touch the disk.
//
// That contract is why install_result distinguishes "refused" from "failed":
// refused means the plugin never reached the disk, and collapsing the two
// would make invariant 3 untestable from the server's side.
//
// Step order is contract, not implementation detail — the vectors assert which
// code comes back when a manifest is invalid *and* the payload is corrupt, so
// the Go and Python implementations cannot diverge on precedence:
//
//  1. validate the manifest
//  2. check the payload length against manifest.payload.size
//  3. call the verifier
//
// Steps 1 and 2 run before the verifier and run for every verifier, noop
// included. Step 2 is not redundant with hash-only: it bounds the work done
// before hashing, and it still holds when the configured verifier does not
// hash at all.
func Gate(v Verifier, m *Manifest, payload []byte) error {
	if v == nil {
		return refuse(CodeVerifyUnconfigured, "no verifier configured")
	}
	if m == nil {
		return refuse(CodeMalformed, "no manifest")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if int64(len(payload)) != m.Payload.Size {
		return refuse(CodePayloadSizeMismatch, "payload %d bytes, manifest %d", len(payload), m.Payload.Size)
	}
	if err := v.Verify(m, payload); err != nil {
		return err
	}
	return nil
}

// GateNamed resolves a configured verifier name and runs the gate. Resolution
// failure is itself a refusal, so a missing or misspelled config cannot be
// mistaken for an accept.
func GateNamed(name string, m *Manifest, payload []byte) error {
	v, err := Resolve(name)
	if err != nil {
		return err
	}
	return Gate(v, m, payload)
}

// AdmitOffer decides whether a plugin.offer is worth transferring, before a
// plugin.fetch is sent and before any payload chunk moves.
//
// It is a distinct check from Gate step 2, not a duplicate of it. Gate step 2
// compares the *assembled* length against the declared size and can only run
// once the bytes have arrived; admission compares the *declared* size against
// the protocol ceiling and runs before any do. Without admission an oversized
// bundle is transferred in full and only then refused — and because a dropped
// transfer restarts from chunk 0, size and link reliability multiply, so a
// bundle too large to transfer must be refused while it is still a claim.
//
// Admission neither sees nor needs the payload. That is what distinguishes it
// from the verify gate, and it is why it can run on the offer alone.
// installedRevision is the revision currently installed for this manifest's
// name, or 0 when nothing is.
func AdmitOffer(m *Manifest, installedRevision int64) error {
	if m == nil {
		return refuse(CodeMalformed, "no manifest")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	return CheckRevision(m, installedRevision)
}

// CheckRevision closes the downgrade and freeze attack class: re-serving a
// genuinely-authored older plugin with a known flaw, or re-serving the current
// one forever to prevent an upgrade.
//
// It is an integer comparison and nothing more, which is exactly why it lands
// now rather than with signing — it needs no trust model to work, and even
// mature implementations get it subtly wrong when it is buried inside one.
//
// Equal is refused, not just lower: an identical revision is the freeze half of
// the class. Idempotent re-push is handled by the payload-hash noop path, which
// compares what is actually installed, not by accepting a stale revision.
func CheckRevision(m *Manifest, installedRevision int64) error {
	if m.Revision <= installedRevision {
		return refuse(CodePolicyRollbackRefused,
			"revision %d is not newer than the installed %d", m.Revision, installedRevision)
	}
	return nil
}
