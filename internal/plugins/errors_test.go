package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// knownCodes is every refusal code this package can produce. It is written out
// rather than reflected because the point of the test below is to catch a code
// that exists in the document and nowhere in the implementation, which a
// reflection over the implementation could never notice.
var knownCodes = []string{
	CodeMalformed, CodeUnsupportedVersion, CodeBadName, CodeBadType, CodeBadRuntime,
	CodeBadEntry, CodeEntryTypeMismatch, CodeEntryNameMismatch, CodeBadCompat,
	CodeBadPayloadHash, CodeBadPayloadSize, CodePayloadTooLarge,
	CodeCapabilitiesNotAllowed, CodeBadCapability,
	CodePayloadSizeMismatch, CodePayloadHashMismatch,
	CodeVerifyRefused, CodeVerifyUnconfigured,
	CodeBundleMalformed, CodeBundleUnsafePath, CodeBundleUnsafeEntry, CodeBundleEntryMissing,
	CodeWireBadFrame, CodeWireBadSequence, CodeWireBadFlags, CodeWireUnsolicited, CodeWireChunkTooLarge,
	CodePolicyWrongRuntime, CodePolicyIncompatibleModel, CodePolicyIncompatibleFirmware,
	CodeInstallLoadFailed, CodeInstallPlaceFailed, CodeInstallReadbackMismatch,
}

var docCodeRe = regexp.MustCompile("(?m)^\\| `([a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*)` \\|")

// TestErrorCodesMatchContractDoc keeps the refusal vocabulary honest.
//
// A code that exists in one place and not the other means the two halves would
// disagree about why an install failed. It also keeps the codes for behaviour
// that lands in a later cycle — placement, loading, runtime-tier policy —
// defined because the contract defines them, not because something happens to
// reference them yet.
func TestErrorCodesMatchContractDoc(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(contractDir, "errors.md"))
	if err != nil {
		t.Fatalf("read errors.md: %v", err)
	}
	matches := docCodeRe.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal("no codes parsed out of errors.md — the table format changed")
	}

	inDoc := map[string]bool{}
	for _, m := range matches {
		inDoc[m[1]] = true
	}
	inCode := map[string]bool{}
	for _, c := range knownCodes {
		inCode[c] = true
	}

	if missing := diffKeys(inCode, inDoc); len(missing) > 0 {
		t.Errorf("codes in errors.go but not errors.md: %v", missing)
	}
	if missing := diffKeys(inDoc, inCode); len(missing) > 0 {
		t.Errorf("codes in errors.md but not errors.go: %v", missing)
	}
}

func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryVectorCodeIsKnown catches a vector asserting a code this
// implementation cannot produce, which would otherwise pass vacuously in one
// language and fail in the other.
func TestEveryVectorCodeIsKnown(t *testing.T) {
	known := map[string]bool{}
	for _, c := range knownCodes {
		known[c] = true
	}
	for _, name := range []string{"manifest.json", "verify.json", "frames.json", "bundles.json"} {
		var doc struct {
			Cases []struct {
				ID   string `json:"id"`
				Code string `json:"code"`
			} `json:"cases"`
		}
		data, err := os.ReadFile(vectorPath(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, c := range doc.Cases {
			if c.Code != "" && !known[c.Code] {
				t.Errorf("%s:%s asserts unknown code %q", name, c.ID, c.Code)
			}
		}
	}
}

func TestRefusalErrorCarriesItsCode(t *testing.T) {
	err := refuse(CodeBadName, "detail here")
	if CodeOf(err) != CodeBadName {
		t.Errorf("CodeOf = %q, want %q", CodeOf(err), CodeBadName)
	}
	if err.Error() != CodeBadName+": detail here" {
		t.Errorf("Error() = %q", err.Error())
	}
}

// TestCodeOfIgnoresNonRefusals: callers report the code and never string-match
// the message, so a non-refusal must not be mistaken for one.
func TestCodeOfIgnoresNonRefusals(t *testing.T) {
	if got := CodeOf(os.ErrNotExist); got != "" {
		t.Errorf("CodeOf(non-refusal) = %q, want empty", got)
	}
	if got := CodeOf(nil); got != "" {
		t.Errorf("CodeOf(nil) = %q, want empty", got)
	}
}

// TestPluginTypesMatchLoaderTree pins the plugin types to the directories that
// actually exist under kvmd/plugins on the device; a type with no loader
// cannot be placed anywhere meaningful.
func TestPluginTypesMatchLoaderTree(t *testing.T) {
	want := []string{"atx", "msd", "hid", "ugpio", "auth"}
	if !reflect.DeepEqual(PluginTypes, want) {
		t.Errorf("PluginTypes = %v, want %v", PluginTypes, want)
	}
}
