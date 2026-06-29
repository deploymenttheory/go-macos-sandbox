//go:build darwin

package searchpath_test

import (
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/searchpath"
)

func TestSearchPathDocumentDirectory(t *testing.T) {
	path, err := searchpath.DocumentDirectory(false)
	if err != nil {
		t.Fatalf("DocumentDirectory(): %v", err)
	}
	if path == "" {
		t.Fatal("DocumentDirectory() returned empty path")
	}
	t.Logf("DocumentDirectory = %s", path)
}
