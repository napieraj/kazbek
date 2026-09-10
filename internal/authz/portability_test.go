// Package authz's portability guard.
//
// D-014: internal/authz/ must not depend on GL-original code beyond a defined
// interface. That is not tidiness — docs/LICENSING.md measures the inherited
// management plane as GL-original and BUSL-encumbered, while the transport
// kazbek actually swaps is MIT. An authorization spine with no dependency on
// GL-original code survives every licence outcome (a grant, waiting for the
// 2030 Change Date, or reopening D-001), which is what keeps the licence off
// this work's critical path.
//
// The condition was already expressible as a command —
// `go list -deps ./internal/authz/...` returning exactly one rttys/ package —
// so it is run rather than recorded. It holds today and will fail the first
// time someone reaches into the inherited domain for a convenient type, which
// is exactly when it is worth knowing.
package authz

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthzHasNoGLOriginalDependencies walks every Go file under internal/authz
// and asserts each import is either stdlib or another internal/authz package.
//
// MUTATION CHECK (AGENTS.md rule 4): add `import _ "rttys/internal/domain/permission"`
// to any file in this tree and this test goes red naming that import. If it
// does not, the guard is dead.
func TestAuthzHasNoGLOriginalDependencies(t *testing.T) {
	const selfPrefix = "rttys/internal/authz"

	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}

	var checked int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)

			// Another internal/authz package: fine, that is the seam's inside.
			if p == selfPrefix || strings.HasPrefix(p, selfPrefix+"/") {
				continue
			}
			// Stdlib: the first path segment of a stdlib import never contains
			// a dot, whereas module paths ("rttys/...", "github.com/...") do
			// at the first segment or are the module name itself.
			first, _, _ := strings.Cut(p, "/")
			if !strings.Contains(first, ".") && first != "rttys" {
				continue
			}
			t.Errorf(
				"%s imports %q — internal/authz must depend on nothing outside itself but stdlib (D-014). "+
					"If this type is genuinely needed, define it in this package and have the caller adapt, "+
					"or pass it across the seam as an interface.",
				rel, p,
			)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("no Go files inspected — the guard is not actually looking at anything")
	}
	t.Logf("D-014 portability: %d files inspected, no external dependencies", checked)
}
