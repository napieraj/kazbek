package plugins

import (
	"archive/tar"
	"bytes"
	"testing"
)

// tarOf builds a minimal uncompressed ustar carrying one regular file per path.
func tarOf(t *testing.T, paths ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range paths {
		data := []byte("x")
		if err := tw.WriteHeader(&tar.Header{
			Name:     p,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}); err != nil {
			t.Fatalf("write header %q: %v", p, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write body %q: %v", p, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestAdmissionAcceptsOrdinaryEntries guards against over-refusal: none of
// these shadows the declared source.
func TestAdmissionAcceptsOrdinaryEntries(t *testing.T) {
	files, err := ReadBundle(tarOf(t,
		"plugins/ugpio/acme_relay.py",
		"plugins/ugpio/table.json",
		"plugins/ugpio/notes.txt",
		"plugins/ugpio/lib.python.helper.py",
	))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if len(files) != 4 {
		t.Fatalf("got %d files, want 4", len(files))
	}
}

// TestAdmissionRefusesEntriesImportableAheadOfSource pins invariant 4 in the
// silent direction. Readback cannot catch any of these: the shadowing file is
// in the bundle the server holds, so both sides compute the same tree hash and
// agree. Admission is the only place the refusal can happen.
func TestAdmissionRefusesEntriesImportableAheadOfSource(t *testing.T) {
	for _, path := range []string{
		"plugins/ugpio/__pycache__/acme_relay.cpython-311.pyc",
		"plugins/ugpio/__pycache__/anything.txt",
		"plugins/ugpio/acme_relay.pyc",
		"plugins/ugpio/acme_relay.pyo",
		"plugins/ugpio/acme_relay.so",
		"plugins/ugpio/acme_relay.abi3.so",
		"plugins/ugpio/acme_relay.cpython-311-x86_64-linux-gnu.so",
		"plugins/ugpio/acme_relay.pyd",
		"plugins/ugpio/ACME_RELAY.SO",
	} {
		t.Run(path, func(t *testing.T) {
			_, err := ReadBundle(tarOf(t, "plugins/ugpio/acme_relay.py", path))
			if err == nil {
				t.Fatalf("accepted %q, want refusal %s", path, CodeBundleUnsafeEntry)
			}
			if got := CodeOf(err); got != CodeBundleUnsafeEntry {
				t.Fatalf("refusal code %q, want %q (%v)", got, CodeBundleUnsafeEntry, err)
			}
		})
	}
}
