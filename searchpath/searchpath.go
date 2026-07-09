//go:build darwin

package searchpath

import (
	"errors"

	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
)

// errContainerNotFound is returned when a sandbox container URL cannot be resolved.
var errContainerNotFound = errors.New("sandbox container not found")

// SearchPathURL returns a standard directory URL for a sandboxed app container.
func SearchPathURL(directory foundation.SearchPathDirectory, domain foundation.SearchPathDomainMask, shouldCreate bool) (string, error) {
	path, err := foundation.DefaultManager().URLForDirectoryInDomainAppropriateForURLCreate(
		directory,
		domain,
		"",
		shouldCreate,
	)
	if err != nil {
		return "", err
	}
	return containerURLPath(path)
}

// DocumentDirectory returns the user Documents directory inside the app container when sandboxed.
func DocumentDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.DocumentDirectory, foundation.UserDomainMask, shouldCreate)
}

// ApplicationSupportDirectory returns Application Support inside the app container when sandboxed.
func ApplicationSupportDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.ApplicationSupportDirectory, foundation.UserDomainMask, shouldCreate)
}

// CachesDirectory returns Caches inside the app container when sandboxed.
func CachesDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.CachesDirectory, foundation.UserDomainMask, shouldCreate)
}

// DownloadsDirectory returns Downloads inside the app container when sandboxed.
func DownloadsDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.DownloadsDirectory, foundation.UserDomainMask, shouldCreate)
}

// DesktopDirectory returns Desktop inside the app container when sandboxed.
func DesktopDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.DesktopDirectory, foundation.UserDomainMask, shouldCreate)
}

// LibraryDirectory returns the user Library directory inside the app container when sandboxed.
func LibraryDirectory(shouldCreate bool) (string, error) {
	return SearchPathURL(foundation.LibraryDirectory, foundation.UserDomainMask, shouldCreate)
}

// containerURLPath validates the filesystem path resolved from a container
// directory URL (the bindings return file URLs as plain paths).
func containerURLPath(path string) (string, error) {
	if path == "" {
		return "", errContainerNotFound
	}
	return path, nil
}
