//go:build darwin

package container_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/container"
)

func TestContainerRootsIncludesSystemRoot(t *testing.T) {
	roots := container.ContainerRoots()
	if len(roots) == 0 {
		t.Fatal("ContainerRoots() returned no roots")
	}
	if roots[0] != "/Library/Containers" {
		t.Fatalf("first root = %q, want /Library/Containers", roots[0])
	}
}

func TestParseContainerMissingPlist(t *testing.T) {
	dir := t.TempDir()
	if _, ok := container.ParseContainer(dir); ok {
		t.Fatal("ParseContainer() = ok, want false for missing Container.plist")
	}
}

func TestContainerDataPath(t *testing.T) {
	path := container.ContainerDataPath("/Users/test", "com.example.app")
	want := filepath.Join("/Users/test", "Library", "Containers", "com.example.app", "Data")
	if path != want {
		t.Fatalf("ContainerDataPath() = %q, want %q", path, want)
	}
}

func TestParseContainerFromLiveSystem(t *testing.T) {
	for _, root := range container.ContainerRoots() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, ok := container.ParseContainer(filepath.Join(root, entry.Name()))
			if !ok {
				continue
			}
			if info.Label == "" {
				t.Fatalf("parsed container missing label at %s", info.Path)
			}
			return
		}
	}
	t.Log("no parseable sandbox containers found")
}
