//go:build darwin

package procpath_test

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/internal/procpath"
)

func TestLookupSelf(t *testing.T) {
	pid := os.Getpid()
	node, ok := procpath.Lookup(pid)
	if !ok {
		t.Fatal("expected lookup to succeed for self")
	}
	if node.PID != pid {
		t.Fatalf("pid = %d, want %d", node.PID, pid)
	}
	if node.Path == "" {
		t.Fatal("expected non-empty path")
	}
	if node.PPID != os.Getppid() {
		t.Fatalf("ppid = %d, want %d", node.PPID, os.Getppid())
	}
}
