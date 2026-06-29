//go:build darwin

package process

import (
	"errors"
	"os"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/cfconv"
)

// IsSandboxedSelf reports whether the current process runs under the App Sandbox,
// determined from its code-signing entitlements via the csops(2) syscall.
//
// Unlike IsSandboxed it does NOT use the Objective-C runtime (no SecTask, no
// main-thread dispatch). That makes it safe to call from code paths that
// themselves dispatch to the main thread — the SDK auto-dispatches @MainActor
// calls via dispatch_sync to the main queue, which would deadlock if the main
// thread is not draining it. A missing entitlement returns (false, nil).
func IsSandboxedSelf() (bool, error) {
	return CurrentEntitlementBoolSelf(entitlements.AppSandbox)
}

// CurrentEntitlementBoolSelf reports whether the current process holds a Boolean
// entitlement, read via csops(2) (no Objective-C runtime). A missing entitlement
// returns (false, nil).
func CurrentEntitlementBoolSelf(key string) (bool, error) {
	ents, err := processEntitlements(os.Getpid())
	if err != nil {
		if errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return false, nil
		}
		return false, err
	}
	enabled, _ := cfconv.BoolFromAny(ents[key])
	return enabled, nil
}
