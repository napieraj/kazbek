package plugins

import "fmt"

// Refusal reason codes. These strings cross the wire in install_result.reason
// and are asserted by the shared conformance vectors, so they are contract,
// not implementation detail. See contract/plugins/errors.md.
const (
	CodeMalformed              = "manifest.malformed"
	CodeUnsupportedVersion     = "manifest.unsupported_version"
	CodeBadName                = "manifest.bad_name"
	CodeBadType                = "manifest.bad_type"
	CodeBadRuntime             = "manifest.bad_runtime"
	CodeBadEntry               = "manifest.bad_entry"
	CodeEntryTypeMismatch      = "manifest.entry_type_mismatch"
	CodeEntryNameMismatch      = "manifest.entry_name_mismatch"
	CodeBadCompat              = "manifest.bad_compat"
	CodeBadPayloadHash         = "manifest.bad_payload_hash"
	CodeBadPayloadSize         = "manifest.bad_payload_size"
	CodePayloadTooLarge        = "manifest.payload_too_large"
	CodeCapabilitiesNotAllowed = "manifest.capabilities_not_allowed"
	CodeBadCapability          = "manifest.bad_capability"

	CodePayloadSizeMismatch = "payload.size_mismatch"
	CodePayloadHashMismatch = "payload.hash_mismatch"

	CodeVerifyRefused      = "verify.refused"
	CodeVerifyUnconfigured = "verify.unconfigured"

	CodeBundleMalformed    = "bundle.malformed"
	CodeBundleUnsafePath   = "bundle.unsafe_path"
	CodeBundleUnsafeEntry  = "bundle.unsafe_entry"
	CodeBundleEntryMissing = "bundle.entry_missing"

	CodeWireBadFrame      = "wire.bad_frame"
	CodeWireBadSequence   = "wire.bad_sequence"
	CodeWireBadFlags      = "wire.bad_flags"
	CodeWireUnsolicited   = "wire.unsolicited"
	CodeWireChunkTooLarge = "wire.chunk_too_large"

	CodePolicyWrongRuntime         = "policy.wrong_runtime"
	CodePolicyIncompatibleModel    = "policy.incompatible_model"
	CodePolicyIncompatibleFirmware = "policy.incompatible_firmware"

	CodeInstallLoadFailed       = "install.load_failed"
	CodeInstallPlaceFailed      = "install.place_failed"
	CodeInstallReadbackMismatch = "install.readback_mismatch"
)

// RefusalError carries a contract code plus human detail. The code is what the
// server acts on and what the vectors assert; the detail is for operators and
// is deliberately never parsed.
type RefusalError struct {
	Code   string
	Detail string
}

func (e *RefusalError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func refuse(code string, format string, args ...any) *RefusalError {
	return &RefusalError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the contract code carried by err, or "" if err is nil or is
// not a refusal. Callers report the code; they never string-match Error().
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	if re, ok := err.(*RefusalError); ok {
		return re.Code
	}
	return ""
}
