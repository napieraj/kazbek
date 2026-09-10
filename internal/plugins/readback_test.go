package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ===== offer admission =====

type admissionVectors struct {
	Cases []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Manifest    json.RawMessage `json:"manifest"`
		Installed   int64           `json:"installed_revision"`
		Expect      string          `json:"expect"`
		Code        string          `json:"code"`
	} `json:"cases"`
}

// Admission runs on the offer alone, before a fetch is sent and before any
// chunk moves. It neither sees nor needs the payload — which is exactly what
// distinguishes it from the verify gate.
func TestAdmitOfferVectors(t *testing.T) {
	var v admissionVectors
	loadVectors(t, "admission.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no admission vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			m, err := ParseManifest(c.Manifest)
			if err == nil {
				err = AdmitOffer(m, c.Installed)
			}
			if c.Expect == "admit" {
				if err != nil {
					t.Fatalf("expected admit, refused with %q (%v)\n%s", CodeOf(err), err, c.Description)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected refusal %q, got admit\n%s", c.Code, c.Description)
			}
			if got := CodeOf(err); got != c.Code {
				t.Fatalf("refusal code %q, want %q (%v)\n%s", got, c.Code, err, c.Description)
			}
		})
	}
}

// TestAdmissionPrecedesTransfer states the ordering claim directly: an
// oversized declaration is refused without the payload existing at all. Gate
// step 2 could not make this call, because it has nothing to measure until the
// bytes have already crossed the wire.
func TestAdmissionPrecedesTransfer(t *testing.T) {
	m, err := ParseManifest([]byte(`{"entry":"plugins/ugpio/big.py","firmware_compat":"*",` +
		`"model_compat":"*","name":"big","payload":{"sha256":"` + zeros64 + `","size":8388609},` +
		`"revision":1,"runtime":"device","signature":{"entries":[],"model":"hash-only"},` +
		`"type":"ugpio"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := CodeOf(AdmitOffer(m, 0)); got != CodePayloadTooLarge {
		t.Fatalf("admission code %q, want %q", got, CodePayloadTooLarge)
	}
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

// ===== readback re-reads the disk =====

func placeTree(t *testing.T, files []TreeFile) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, f.Data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func TestReadbackReportsThePlacedTree(t *testing.T) {
	files, err := ReadBundle(loadBlob(t, "reference-bundle.tar"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	root := placeTree(t, files)

	rb, err := ReadbackFor(zeros64, root)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if rb.V != ProtocolVersion || rb.SHA256 != zeros64 {
		t.Errorf("readback header wrong: %+v", rb)
	}
	if rb.TreeSHA256 != TreeHash(files) {
		t.Errorf("tree hash %s, want %s", rb.TreeSHA256, TreeHash(files))
	}
	if len(rb.Entries) != len(files) {
		t.Errorf("%d entries, want %d", len(rb.Entries), len(files))
	}
}

// TestReadbackDetectsOnDiskDrift is the test the disk re-read exists for.
//
// The bundle is untouched and would hash correctly; only the placed file
// changed. A readback that hashed the received bundle would pass this and
// report a healthy install over a corrupted disk — which is why it must not.
func TestReadbackDetectsOnDiskDrift(t *testing.T) {
	files, err := ReadBundle(loadBlob(t, "reference-bundle.tar"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	root := placeTree(t, files)

	clean, err := ReadbackFor(zeros64, root)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}

	// Corrupt one placed file. The bundle in memory is deliberately untouched.
	victim := filepath.Join(root, filepath.FromSlash(files[0].Path))
	if err := os.WriteFile(victim, append(files[0].Data, []byte("# tampered\n")...), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	drifted, err := ReadbackFor(zeros64, root)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if drifted.TreeSHA256 == clean.TreeSHA256 {
		t.Fatal("readback did not notice an on-disk change — it is hashing the " +
			"received bundle rather than re-reading the placed files")
	}
	if drifted.TreeSHA256 == TreeHash(files) {
		t.Fatal("readback matches the bundle's hash despite the disk differing")
	}
}

// A truncated file is the partial-write case readback is meant to catch.
func TestReadbackDetectsTruncation(t *testing.T) {
	files, err := ReadBundle(loadBlob(t, "reference-bundle.tar"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	root := placeTree(t, files)
	victim := filepath.Join(root, filepath.FromSlash(files[0].Path))
	if err := os.WriteFile(victim, files[0].Data[:len(files[0].Data)/2], 0o644); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	rb, err := ReadbackFor(zeros64, root)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if rb.TreeSHA256 == TreeHash(files) {
		t.Fatal("readback did not notice a truncated placed file")
	}
}

// A file that never landed is the failed-rename case.
func TestReadbackDetectsMissingFile(t *testing.T) {
	files, err := ReadBundle(loadBlob(t, "reference-bundle.tar"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	root := placeTree(t, files)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(files[0].Path))); err != nil {
		t.Fatalf("remove: %v", err)
	}
	rb, err := ReadbackFor(zeros64, root)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if rb.TreeSHA256 == TreeHash(files) {
		t.Fatal("readback did not notice a missing placed file")
	}
	if len(rb.Entries) != len(files)-1 {
		t.Errorf("%d entries, want %d", len(rb.Entries), len(files)-1)
	}
}
