package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The conformance vectors are the shared test contract. Both repos vendor the
// identical contract/plugins tree and run their own suite against it, so a
// divergence between the Go and Python implementations is caught by each
// repo's own tests rather than at integration time.

const contractDir = "../../contract/plugins"

func vectorPath(elem ...string) string {
	return filepath.Join(append([]string{contractDir, "vectors"}, elem...)...)
}

func loadVectors(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(vectorPath(name))
	if err != nil {
		t.Fatalf("read vectors %s: %v", name, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("parse vectors %s: %v", name, err)
	}
}

func loadBlob(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(vectorPath("blobs", name))
	if err != nil {
		t.Fatalf("read blob %s: %v", name, err)
	}
	return data
}

// ===== contract sync =====

// TestContractSHA256 fails when this repo's vendored contract has been edited
// without regenerating the hash — which is how a one-sided contract change is
// caught by the repo that made it, instead of by the other repo months later.
func TestContractSHA256(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(contractDir, "CONTRACT-SHA256"))
	if err != nil {
		t.Fatalf("read CONTRACT-SHA256: %v", err)
	}
	var files []TreeFile
	root := filepath.Clean(contractDir)
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() == "CONTRACT-SHA256" {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, TreeFile{Path: filepath.ToSlash(rel), Data: body})
		return nil
	})
	if err != nil {
		t.Fatalf("walk contract: %v", err)
	}
	// Deliberately the same algorithm as the readback tree hash: one hashing
	// algorithm in this contract, not two.
	if got := TreeHash(files); got != trimNewline(string(want)) {
		t.Fatalf("contract tree hash %s, CONTRACT-SHA256 says %s\n"+
			"the vendored contract was edited without regenerating the hash", got, trimNewline(string(want)))
	}
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// ===== manifest =====

type manifestVectors struct {
	Cases []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Manifest    json.RawMessage `json:"manifest"`
		Raw         *string         `json:"raw"`
		Canonical   string          `json:"canonical"`
		Valid       bool            `json:"valid"`
		Code        string          `json:"code"`
	} `json:"cases"`
}

func TestManifestVectors(t *testing.T) {
	var v manifestVectors
	loadVectors(t, "manifest.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no manifest vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			input := []byte(c.Canonical)
			if c.Raw != nil {
				input = []byte(*c.Raw)
			}

			m, err := ParseManifest(input)
			if err == nil {
				err = m.Validate()
			}

			if c.Valid {
				if err != nil {
					t.Fatalf("expected valid, refused with %q (%v)\n%s", CodeOf(err), err, c.Description)
				}
				// Canonical encoding must round-trip byte-stably, or the two
				// languages cannot hash the same manifest to the same value —
				// which the signing module will depend on.
				got, err := m.CanonicalJSON()
				if err != nil {
					t.Fatalf("canonical encode: %v", err)
				}
				if string(got) != c.Canonical {
					t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, c.Canonical)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected refusal %q, got accept\n%s", c.Code, c.Description)
			}
			if got := CodeOf(err); got != c.Code {
				t.Fatalf("refusal code %q, want %q (%v)\n%s", got, c.Code, err, c.Description)
			}
		})
	}
}

// ===== verify gate =====

type verifyVectors struct {
	Cases []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Verifier    string          `json:"verifier"`
		Manifest    json.RawMessage `json:"manifest"`
		PayloadBlob string          `json:"payload_blob"`
		Expect      string          `json:"expect"`
		Code        string          `json:"code"`
	} `json:"cases"`
}

// verifierAlwaysFail refuses everything. It is test-only on purpose: it lives
// in a _test.go file so it can never be reached from production code, and
// Resolve does not know its name.
type verifierAlwaysFail struct{}

func (verifierAlwaysFail) Name() string { return "always-fail" }

func (verifierAlwaysFail) Verify(_ *Manifest, _ []byte) error {
	return refuse(CodeVerifyRefused, "always-fail verifier")
}

func TestVerifyGateVectors(t *testing.T) {
	var v verifyVectors
	loadVectors(t, "verify.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no verify vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			m, err := ParseManifest(c.Manifest)
			if err != nil {
				t.Fatalf("vector manifest did not parse: %v", err)
			}
			payload := loadBlob(t, c.PayloadBlob)

			// "always-fail" is never resolvable by name; every other name goes
			// through Resolve so that fail-closed behaviour is exercised too.
			if c.Verifier == "always-fail" {
				err = Gate(verifierAlwaysFail{}, m, payload)
			} else {
				err = GateNamed(c.Verifier, m, payload)
			}

			if c.Expect == "accept" {
				if err != nil {
					t.Fatalf("expected accept, refused with %q (%v)\n%s", CodeOf(err), err, c.Description)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected refusal %q, got accept\n%s", c.Code, c.Description)
			}
			if got := CodeOf(err); got != c.Code {
				t.Fatalf("refusal code %q, want %q (%v)\n%s", got, c.Code, err, c.Description)
			}
		})
	}
}

// ===== tree hash =====

type treehashVectors struct {
	Cases []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Files       []struct {
			Path       string `json:"path"`
			ContentB64 string `json:"content_b64"`
		} `json:"files"`
		TreeSHA256 string `json:"tree_sha256"`
	} `json:"cases"`
}

func TestTreeHashVectors(t *testing.T) {
	var v treehashVectors
	loadVectors(t, "treehash.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no treehash vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			files := make([]TreeFile, 0, len(c.Files))
			for _, f := range c.Files {
				files = append(files, TreeFile{Path: f.Path, Data: decodeB64(t, f.ContentB64)})
			}
			if got := TreeHash(files); got != c.TreeSHA256 {
				t.Fatalf("tree hash %s, want %s\n%s", got, c.TreeSHA256, c.Description)
			}
		})
	}
}

// ===== bundles =====

type bundleVectors struct {
	Cases []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Blob        string `json:"blob"`
		Code        string `json:"code"`
		Files       []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		TreeSHA256 string `json:"tree_sha256"`
	} `json:"cases"`
}

func TestBundleVectors(t *testing.T) {
	var v bundleVectors
	loadVectors(t, "bundles.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no bundle vectors loaded")
	}

	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			files, err := ReadBundle(loadBlob(t, c.Blob))

			if c.Code != "" {
				if err == nil {
					t.Fatalf("expected refusal %q, unpacked %d files\n%s", c.Code, len(files), c.Description)
				}
				if got := CodeOf(err); got != c.Code {
					t.Fatalf("refusal code %q, want %q (%v)\n%s", got, c.Code, err, c.Description)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected unpack, refused with %q (%v)\n%s", CodeOf(err), err, c.Description)
			}
			if len(files) != len(c.Files) {
				t.Fatalf("unpacked %d files, want %d", len(files), len(c.Files))
			}
			sortTreeFiles(files)
			for i, want := range c.Files {
				if files[i].Path != want.Path {
					t.Fatalf("file %d path %q, want %q", i, files[i].Path, want.Path)
				}
				sum := sha256.Sum256(files[i].Data)
				if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
					t.Fatalf("file %q sha256 %s, want %s", want.Path, got, want.SHA256)
				}
			}
			if got := TreeHash(files); got != c.TreeSHA256 {
				t.Fatalf("tree hash %s, want %s", got, c.TreeSHA256)
			}
		})
	}
}
