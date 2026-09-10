package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// TreeFile is one regular file in a placed plugin tree.
type TreeFile struct {
	Path string // POSIX-relative to the plugin root, no leading "./"
	Data []byte
}

// TreeHash is the canonical tree hash used by readback and by contract-sync
// checking.
//
// Both sides must compute this identically or every readback comparison is
// meaningless, which is why vectors/treehash.json exists.
//
//	for each regular file:
//	    sha256_hex(content) + "  " + path + "\n"     (two spaces, as sha256sum)
//	concatenated in bytewise path order, then sha256_hex of the whole.
//
// Directories, symlinks, modes and timestamps are not hashed and are not
// permitted in a v1 bundle, so there is nothing left to disagree about.
func TreeHash(files []TreeFile) string {
	sorted := make([]TreeFile, len(files))
	copy(sorted, files)
	sortTreeFiles(sorted)

	h := sha256.New()
	for _, f := range sorted {
		sum := sha256.Sum256(f.Data)
		h.Write([]byte(hex.EncodeToString(sum[:]) + "  " + f.Path + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sortTreeFiles orders by path bytewise ascending. Go's string comparison is
// already bytewise, which is what the contract requires — not a locale order.
func sortTreeFiles(files []TreeFile) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
}
