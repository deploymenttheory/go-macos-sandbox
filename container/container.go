//go:build darwin

package container

import (
	"os"
	"path/filepath"
	"strings"

	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/plistutil"
)

const containerPlistName = "Container.plist"

var systemContainerRoot = "/Library/Containers"

// ContainerInfo describes a macOS App Sandbox container directory.
type ContainerInfo struct {
	Label      string
	User       string
	Enabled    bool
	BuildID    string
	BundlePath string
	Path       string
}

// ContainerRoots returns sandbox container root directories for all local users.
func ContainerRoots() []string {
	roots := []string{systemContainerRoot}

	entries, err := os.ReadDir("/Users")
	if err != nil {
		return roots
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		roots = append(roots, filepath.Join("/Users", entry.Name(), "Library", "Containers"))
	}
	return roots
}

// ParseContainer reads Container.plist under containerPath.
func ParseContainer(containerPath string) (ContainerInfo, bool) {
	plistPath := filepath.Join(containerPath, containerPlistName)
	tree, err := plistutil.ReadPlistFile(plistPath)
	if err != nil {
		return ContainerInfo{}, false
	}

	info, ok := tree["SandboxProfileDataValidationInfo"].(map[string]any)
	if !ok {
		return ContainerInfo{}, false
	}
	params, ok := info["SandboxProfileDataValidationParametersKey"].(map[string]any)
	if !ok {
		return ContainerInfo{}, false
	}

	enabled := false
	if ents, ok := info["SandboxProfileDataValidationEntitlementsKey"].(map[string]any); ok {
		enabled = plistutil.PlistBool(ents[entitlements.AppSandbox])
	}

	return ContainerInfo{
		Label:      plistutil.PlistString(params["application_container_id"]),
		User:       plistutil.PlistString(params["_USER"]),
		Enabled:    enabled,
		BuildID:    plistutil.PlistString(params["sandbox_build_id"]),
		BundlePath: plistutil.PlistString(params["application_bundle"]),
		Path:       containerPath,
	}, true
}

// AppGroupContainerPath returns the shared container path for an application group identifier.
func AppGroupContainerPath(groupIdentifier string) (string, error) {
	url := foundation.DefaultManager().ContainerURLForSecurityApplicationGroupIdentifier(groupIdentifier)
	return containerURLPath(url)
}

// UbiquityContainerPath returns the iCloud ubiquity container path for containerIdentifier.
func UbiquityContainerPath(containerIdentifier string) (string, error) {
	url := foundation.DefaultManager().URLForUbiquityContainerIdentifier(containerIdentifier)
	return containerURLPath(url)
}

// ContainerDataPath returns the Data subdirectory inside a container for bundleID and homeDir.
func ContainerDataPath(homeDir, bundleID string) string {
	return filepath.Join(homeDir, "Library", "Containers", bundleID, "Data")
}

func containerURLPath(url *foundation.URL) (string, error) {
	if url == nil {
		return "", ErrContainerNotFound
	}
	path := url.Path()
	if path == "" {
		return "", ErrContainerNotFound
	}
	return path, nil
}
