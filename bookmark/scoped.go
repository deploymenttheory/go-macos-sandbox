//go:build darwin

package bookmark

import (
	"fmt"

	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
)

// ScopedResource grants temporary access to a security-scoped URL in a sandboxed app.
type ScopedResource struct {
	url    *foundation.URL
	active bool
}

// BeginSecurityScopedAccess starts access for a security-scoped URL.
//
// The URL must come from ResolveSecurityScopedBookmark, an Open/Save panel result,
// or another API that produces a security-scoped bookmark URL. Plain paths passed
// through FileURLWithPath are not security-scoped and StartAccessingSecurityScopedResource
// returns false for them inside a sandboxed app.
func BeginSecurityScopedAccess(url *foundation.URL) (*ScopedResource, error) {
	return beginSecurityScopedAccess(url)
}

func beginSecurityScopedAccess(url *foundation.URL) (*ScopedResource, error) {
	if url == nil {
		return nil, fmt.Errorf("URL is nil")
	}
	if !url.StartAccessingSecurityScopedResource() {
		return nil, ErrNotSecurityScoped
	}
	return &ScopedResource{url: url, active: true}, nil
}

// ResolveSecurityScopedBookmark resolves bookmark data and begins security-scoped access.
func ResolveSecurityScopedBookmark(bookmarkData []byte, relativeTo string) (*ScopedResource, error) {
	if len(bookmarkData) == 0 {
		return nil, fmt.Errorf("bookmark data is empty")
	}
	url, _, err := foundation.URLByResolvingBookmarkDataOptionsRelativeToURLBookmarkDataIsStale(
		bookmarkData,
		foundation.URLBookmarkResolutionWithSecurityScope,
		relativeTo,
	)
	if err != nil {
		return nil, err
	}
	return beginSecurityScopedAccess(url)
}

// SecurityScopedBookmarkForPath creates security-scoped bookmark data for path.
func SecurityScopedBookmarkForPath(path string, readOnly bool) ([]byte, error) {
	url := foundation.NewURLFileURLWithPath(path)
	if url == nil {
		return nil, fmt.Errorf("invalid path %q", path)
	}

	options := foundation.URLBookmarkCreationWithSecurityScope
	if readOnly {
		options |= foundation.URLBookmarkCreationSecurityScopeAllowOnlyReadAccess
	}

	data, err := url.BookmarkDataWithOptionsIncludingResourceValuesForKeysRelativeToURL(options, nil, "")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("bookmark data is empty")
	}
	return data, nil
}

// Path returns the filesystem path for the scoped URL.
func (resource *ScopedResource) Path() string {
	if resource == nil || resource.url == nil {
		return ""
	}
	return resource.url.Path()
}

// Stop revokes security-scoped access. Safe to call more than once.
func (resource *ScopedResource) Stop() {
	if resource == nil || !resource.active || resource.url == nil {
		return
	}
	resource.url.StopAccessingSecurityScopedResource()
	resource.active = false
}
