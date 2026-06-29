//go:build darwin

package bookmark_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/bookmark"
)

func TestResolveSecurityScopedBookmarkRoundTrip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("bookmark round-trip requires non-root user context")
	}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "scoped.txt")
	if err := os.WriteFile(filePath, []byte("sandbox"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := bookmark.SecurityScopedBookmarkForPath(filePath, true)
	if err != nil {
		t.Fatalf("SecurityScopedBookmarkForPath: %v", err)
	}

	resource, err := bookmark.ResolveSecurityScopedBookmark(data, "")
	if err != nil {
		t.Fatalf("ResolveSecurityScopedBookmark: %v", err)
	}
	defer resource.Stop()

	if resource.Path() == "" {
		t.Fatal("ScopedResource.Path() is empty")
	}
}

func TestBeginSecurityScopedAccessNilURL(t *testing.T) {
	_, err := bookmark.BeginSecurityScopedAccess(nil)
	if err == nil {
		t.Fatal("BeginSecurityScopedAccess(nil) error = nil, want error")
	}
}
