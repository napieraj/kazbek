package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

// TestHookIsInertWithNoPath pins the guard that stops the logger killing the
// process on its first line.
//
// logFileHook is attached whenever stdout is not a terminal -- true under
// `go test`, under systemd, in a container with redirected output, and behind
// any supervisor. Without a path configured it used to open "", fail, and call
// log.Fatal() from inside the logger, which is os.Exit(1). The whole
// rttys/internal/server package died at 0.010s before any test ran.
//
// Run() cannot be allowed to terminate the process, so this test asserts it
// returns; if the guard is removed the fatal path is taken and the test binary
// exits, which the runner reports as a failure rather than a pass.
func TestHookIsInertWithNoPath(t *testing.T) {
	h := &logFileHook{}
	if h.path != "" {
		t.Fatalf("fresh hook has path %q, want empty", h.path)
	}
	h.Run(nil, zerolog.InfoLevel, "a line emitted before SetPath")
	if h.err != nil {
		t.Fatalf("hook latched an error with no path configured: %v", h.err)
	}
}

// TestHookWritesWhenPathIsSet is the other half: a guard that made the hook
// inert unconditionally would satisfy the test above.
func TestHookWritesWhenPathIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kazbek.log")
	h := &logFileHook{path: path}
	h.Run(nil, zerolog.InfoLevel, "written")
	if h.err != nil {
		t.Fatalf("hook errored with a writable path: %v", h.err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("log file is empty")
	}
}

// TestHookLatchesAndDoesNotTerminate covers an unopenable path: the failure
// must be recorded and swallowed, never fatal.
func TestHookLatchesAndDoesNotTerminate(t *testing.T) {
	h := &logFileHook{path: filepath.Join(t.TempDir(), "no-such-dir", "kazbek.log")}
	h.Run(nil, zerolog.InfoLevel, "unwritable")
	if h.err == nil {
		t.Fatal("hook did not record the open failure")
	}
	h.Run(nil, zerolog.InfoLevel, "second line must not retry")
}
