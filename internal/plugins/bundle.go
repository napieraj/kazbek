package plugins

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

// A v1 bundle is an uncompressed POSIX ustar archive of regular files only.
// Both sides already have a tar reader in their standard library, so the
// bundle costs no dependency on the device.
//
// The checks below are not defence in depth over the verify gate — they are
// the reason a noop verifier is survivable at all. Path safety is structural
// and is enforced regardless of which Verifier is configured.

// BundleMaxEntries bounds a bundle's file count, so a well-formed archive
// cannot become a resource-exhaustion path after the size check has passed.
const BundleMaxEntries = 256

// ReadBundle validates and unpacks a bundle into its files. It refuses before
// returning anything, so a caller can never act on a partially-validated tree.
func ReadBundle(data []byte) ([]TreeFile, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var files []TreeFile
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, refuse(CodeBundleMalformed, "read: %v", err)
		}
		if len(files) >= BundleMaxEntries {
			return nil, refuse(CodeBundleMalformed, "more than %d entries", BundleMaxEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			// Symlinks can redirect a later write outside the root, and
			// directory entries would smuggle in modes; v1 carries neither.
			return nil, refuse(CodeBundleUnsafeEntry, "entry %q is not a regular file", hdr.Name)
		}
		if err := checkBundlePath(hdr.Name); err != nil {
			return nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, refuse(CodeBundleMalformed, "read %q: %v", hdr.Name, err)
		}
		files = append(files, TreeFile{Path: hdr.Name, Data: body})
	}
	if len(files) == 0 {
		return nil, refuse(CodeBundleMalformed, "no entries")
	}
	return files, nil
}

// checkBundlePath enforces invariant 1 at the archive level: no entry may name
// a location outside the loader-owned root.
func checkBundlePath(name string) error {
	switch {
	case name == "":
		return refuse(CodeBundleUnsafePath, "empty path")
	case strings.HasPrefix(name, "/"):
		return refuse(CodeBundleUnsafePath, "absolute path %q", name)
	case strings.Contains(name, `\`):
		// Refused rather than normalised: a separator that means one thing on
		// the server and another on the device is exactly the ambiguity that
		// path checks are supposed to remove.
		return refuse(CodeBundleUnsafePath, "backslash in %q", name)
	case strings.HasSuffix(name, "/"):
		return refuse(CodeBundleUnsafeEntry, "directory entry %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return refuse(CodeBundleUnsafePath, "unsafe segment in %q", name)
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return refuse(CodeBundleUnsafePath, "non-printable-ASCII in %q", name)
		}
	}
	return nil
}

// RequireEntry checks that the bundle actually contains the module the
// manifest names. A manifest that describes a plugin the bundle does not carry
// is a refusal, not something to discover at import time.
func RequireEntry(files []TreeFile, m *Manifest) error {
	for _, f := range files {
		if f.Path == m.Entry {
			return nil
		}
	}
	return refuse(CodeBundleEntryMissing, "bundle has no %q", m.Entry)
}

// ReadbackFor builds the readback body for a placed tree.
func ReadbackFor(manifestSHA string, files []TreeFile) *ReadbackBody {
	rb := &ReadbackBody{
		Entries:    []ReadbackEntry{},
		SHA256:     manifestSHA,
		TreeSHA256: TreeHash(files),
		V:          ProtocolVersion,
	}
	if len(files) > ReadbackMaxEntries {
		// Detail is capped; the tree hash still tells the server drift happened.
		return rb
	}
	sorted := make([]TreeFile, len(files))
	copy(sorted, files)
	sortTreeFiles(sorted)
	for _, f := range sorted {
		sum := sha256.Sum256(f.Data)
		rb.Entries = append(rb.Entries, ReadbackEntry{Path: f.Path, SHA256: hex.EncodeToString(sum[:])})
	}
	return rb
}
