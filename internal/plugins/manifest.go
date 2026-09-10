package plugins

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// PayloadMaxSize caps a bundle at 8 MiB. The receiver is an embedded device
// that must buffer and hash the whole bundle before it may touch the disk, so
// an unbounded payload is a memory-exhaustion path reached *before* the verify
// gate can protect against it. See contract/plugins/manifest.md.
const PayloadMaxSize int64 = 8 << 20

// PluginTypes are the plugin sub-directories that exist under kvmd/plugins/.
// A type outside this set has no loader and cannot be placed anywhere
// meaningful, so it is refused rather than carried.
var PluginTypes = []string{"atx", "msd", "hid", "ugpio", "auth"}

var (
	// Constrained to what a Python module name may be, because this becomes
	// kvmd.plugins.<type>.<name> at the device loader. Leading underscores are
	// excluded because kvmd's existing get_plugin_class already treats them as
	// unknown.
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	entryRe  = regexp.MustCompile(`^plugins/(atx|msd|hid|ugpio|auth)/([a-z][a-z0-9_]{0,31})\.py$`)
	hexRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	capRe    = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	compatRe = regexp.MustCompile(`^(>=|<=|==)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Payload is the bundle's identity: its hash and its exact length.
type Payload struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Signature is the stubbed trust block. It is defined now and populated never
// — its presence in the schema is exactly what lets the signing module land as
// an implementation change behind the Verifier seam rather than as a schema
// migration across a fleet of already-deployed devices.
type Signature struct {
	Alg   string `json:"alg,omitempty"`
	KeyID string `json:"key_id,omitempty"`
	Value string `json:"value,omitempty"`
}

// Manifest describes a plugin. Field order is bytewise-sorted by JSON tag so
// that encoding/json emits canonical JSON directly: Go marshals struct fields
// in declaration order, and canonical form requires sorted keys.
//
// Capabilities and Signature are pointers so that "absent" and "present but
// empty" stay distinguishable — canonical encoding omits an absent field
// entirely but must still emit an explicitly empty capabilities list.
type Manifest struct {
	Capabilities   *[]string  `json:"capabilities,omitempty"`
	Entry          string     `json:"entry"`
	FirmwareCompat string     `json:"firmware_compat"`
	ModelCompat    string     `json:"model_compat"`
	Name           string     `json:"name"`
	Payload        Payload    `json:"payload"`
	Runtime        string     `json:"runtime"`
	Signature      *Signature `json:"signature,omitempty"`
	Type           string     `json:"type"`
}

var (
	manifestRequired = []string{"entry", "firmware_compat", "model_compat", "name", "payload", "runtime", "type"}
	manifestOptional = []string{"capabilities", "signature"}
	payloadRequired  = []string{"sha256", "size"}
)

// ParseManifest decodes canonical JSON into a Manifest without validating it.
// Unknown top-level fields are refused rather than ignored: that costs forward
// compatibility and buys the thing worth more, which is that a device and a
// server can never disagree about what a manifest said.
func ParseManifest(data []byte) (*Manifest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, refuse(CodeMalformed, "not a JSON object: %v", err)
	}
	if err := checkKeys(raw, manifestRequired, manifestOptional); err != nil {
		return nil, err
	}

	var payloadRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw["payload"], &payloadRaw); err != nil {
		return nil, refuse(CodeMalformed, "payload is not an object: %v", err)
	}
	if err := checkKeys(payloadRaw, payloadRequired, nil); err != nil {
		return nil, err
	}

	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, refuse(CodeMalformed, "decode: %v", err)
	}
	return &m, nil
}

func checkKeys(raw map[string]json.RawMessage, required, optional []string) error {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, k := range required {
		if _, ok := raw[k]; !ok {
			return refuse(CodeMalformed, "missing required field %q", k)
		}
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range raw {
		if !allowed[k] {
			return refuse(CodeMalformed, "unknown field %q", k)
		}
	}
	return nil
}

// Validate applies every structural rule in contract/plugins/manifest.md.
//
// Field order here is contract, not taste: the vectors pin which code comes
// back when more than one rule is broken. Type is checked before Entry because
// an unknown type would otherwise surface as a bad_entry (the entry pattern
// enumerates the known types), and Name before Entry so a bad module name is
// reported as such rather than as a mismatch against the entry it also breaks.
func (m *Manifest) Validate() error {
	if !nameRe.MatchString(m.Name) {
		return refuse(CodeBadName, "name %q", m.Name)
	}
	if !isPluginType(m.Type) {
		return refuse(CodeBadType, "type %q", m.Type)
	}
	if m.Runtime != RuntimeDevice && m.Runtime != RuntimeManagement {
		// Never defaulted: defaulting a security tier is how tiers stop
		// meaning anything.
		return refuse(CodeBadRuntime, "runtime %q", m.Runtime)
	}

	groups := entryRe.FindStringSubmatch(m.Entry)
	if groups == nil {
		return refuse(CodeBadEntry, "entry %q", m.Entry)
	}
	// Invariant 1: entry describes the bundle's shape, it does not instruct
	// where to write. A disagreement with the loader's own derivation from
	// type+name is a refusal, never a redirection.
	if groups[1] != m.Type {
		return refuse(CodeEntryTypeMismatch, "entry type %q, manifest type %q", groups[1], m.Type)
	}
	if groups[2] != m.Name {
		return refuse(CodeEntryNameMismatch, "entry stem %q, manifest name %q", groups[2], m.Name)
	}

	for field, c := range map[string]string{"model_compat": m.ModelCompat, "firmware_compat": m.FirmwareCompat} {
		if !validCompat(c) {
			return refuse(CodeBadCompat, "%s %q", field, c)
		}
	}

	if !hexRe.MatchString(m.Payload.SHA256) {
		// Canonical means one spelling: uppercase hex is a violation, not
		// something to normalise.
		return refuse(CodeBadPayloadHash, "payload.sha256 %q", m.Payload.SHA256)
	}
	if m.Payload.Size < 1 {
		return refuse(CodeBadPayloadSize, "payload.size %d", m.Payload.Size)
	}
	if m.Payload.Size > PayloadMaxSize {
		return refuse(CodePayloadTooLarge, "payload.size %d exceeds %d", m.Payload.Size, PayloadMaxSize)
	}

	if m.Capabilities != nil && len(*m.Capabilities) > 0 {
		// Device plugins draw their blast radius from the console they run on,
		// not from a capability grant; allowing the field there would create a
		// second, weaker authorisation story.
		if m.Runtime != RuntimeManagement {
			return refuse(CodeCapabilitiesNotAllowed, "runtime %q", m.Runtime)
		}
		for _, c := range *m.Capabilities {
			if !capRe.MatchString(c) {
				return refuse(CodeBadCapability, "capability %q", c)
			}
		}
	}
	return nil
}

func isPluginType(t string) bool {
	for _, known := range PluginTypes {
		if known == t {
			return true
		}
	}
	return false
}

// validCompat parses the minimal constraint grammar from manifest.md. It is
// deliberately small: compatibility gating is a device-side policy decision,
// and the contract's only job is to make the expression parse identically on
// both sides.
func validCompat(c string) bool {
	if c == "*" {
		return true
	}
	return compatRe.MatchString(c)
}

// CanonicalJSON encodes the manifest in canonical form: keys sorted bytewise,
// no insignificant whitespace, no HTML escaping (Go escapes <, > and & by
// default, which Python's json does not — the two must agree byte for byte).
func (m *Manifest) CanonicalJSON() ([]byte, error) {
	return canonicalJSON(m)
}

// CompareVersions orders two compat tokens by splitting on '.' and '-' and
// comparing segments numerically when both are all-digits, bytewise otherwise.
func CompareVersions(a, b string) int {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	}
	as, bs := split(a), split(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		if xErr == nil && yErr == nil {
			if xn != yn {
				return sign(xn - yn)
			}
			continue
		}
		if x != y {
			return strings.Compare(x, y)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
