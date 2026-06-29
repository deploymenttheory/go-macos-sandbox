//go:build darwin

package entitlements_test

import (
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
)

func TestNewEntitlementConstants(t *testing.T) {
	cases := map[string]string{
		entitlements.PrivilegedFileOperations: "com.apple.developer.security.privileged-file-operations",
		entitlements.BookmarksAppScope:        "com.apple.security.files.bookmarks.app-scope",
		entitlements.BookmarksDocumentScope:   "com.apple.security.files.bookmarks.document-scope",
		entitlements.FilesAll:                 "com.apple.security.files.all",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("entitlement constant = %q, want %q", got, want)
		}
	}
}
