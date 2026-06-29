//go:build darwin

package codesign

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	purego "github.com/deploymenttheory/go-bindings-macosplatform/bindings/runtime/purego"
	corefoundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/corefoundation"
	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
	security "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/security"
	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/obj"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/cfconv"
)

const (
	secCSSigningInformation     security.SecCSFlags = 2
	secCSRequirementInformation security.SecCSFlags = 4
)

// Verification summarizes App Sandbox state read from a signed binary.
type Verification struct {
	Sandboxed    bool
	Entitlements map[string]any
}

// EntitlementsFromPath reads the embedded entitlements dictionary from a signed binary.
func EntitlementsFromPath(path string) (map[string]any, error) {
	verification, err := VerifyAtPath(path)
	if err != nil {
		return nil, err
	}
	if len(verification.Entitlements) == 0 {
		return nil, entitlements.ErrEntitlementNotFound
	}
	return verification.Entitlements, nil
}

// VerifyAtPath reads signing entitlements and derives sandbox status from path.
func VerifyAtPath(path string) (Verification, error) {
	ents, err := entitlementsFromPath(path)
	if err != nil {
		if errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return Verification{Entitlements: map[string]any{}}, nil
		}
		return Verification{}, err
	}
	return Verification{
		Sandboxed:    plistBool(ents[entitlements.AppSandbox]),
		Entitlements: ents,
	}, nil
}

// EntitlementValueAtPath returns one embedded entitlement value from path.
func EntitlementValueAtPath(path, key string) (any, error) {
	ents, err := entitlementsFromPath(path)
	if err != nil {
		return nil, err
	}
	value, ok := ents[key]
	if !ok {
		return nil, entitlements.ErrEntitlementNotFound
	}
	return value, nil
}

// HasEntitlementAtPath reports whether path's code signature includes a Boolean entitlement.
// A missing entitlement returns (false, nil).
func HasEntitlementAtPath(path, key string) (bool, error) {
	value, err := EntitlementValueAtPath(path, key)
	if err != nil {
		if errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return false, nil
		}
		return false, err
	}
	enabled, ok := cfconv.BoolFromAny(value)
	if !ok {
		return false, fmt.Errorf("entitlement %q is not boolean", key)
	}
	return enabled, nil
}

// IsSandboxedAtPath reports whether path's code signature includes App Sandbox.
// A missing entitlement returns (false, nil).
func IsSandboxedAtPath(path string) (bool, error) {
	return HasEntitlementAtPath(path, entitlements.AppSandbox)
}

// SigningIdentifierAtPath returns the code signing identifier for path.
func SigningIdentifierAtPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if _, err := os.Stat(path); err != nil {
		return "", err
	}

	url := foundation.FileURLWithPath(path)
	if url == nil {
		return "", fmt.Errorf("invalid path %q", path)
	}

	var staticCode purego.ID
	if err := security.SecStaticCodeCreateWithPath(url, security.KSecCSDefaultFlags, unsafe.Pointer(&staticCode)); err != nil {
		return "", err
	}
	if staticCode == 0 {
		return "", fmt.Errorf("SecStaticCodeCreateWithPath returned nil")
	}
	code := obj.Wrap(staticCode)
	defer corefoundation.CFRelease(code)

	info, err := security.SecCodeCopySigningInformation(code, secCSSigningInformation|secCSRequirementInformation)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", fmt.Errorf("no signing information for %q", path)
	}
	defer corefoundation.CFRelease(info)

	infoDict, ok := obj.As(info, "NSDictionary", foundation.DictionaryFromID)
	if !ok {
		return "", fmt.Errorf("signing information is not a dictionary")
	}

	identifier := infoDict.ObjectForKey(security.KSecCodeInfoIdentifier())
	if identifier == nil {
		return "", entitlements.ErrEntitlementNotFound
	}
	text := cfconv.ObjectToString(identifier)
	if text == "" {
		return "", fmt.Errorf("signing identifier is empty")
	}
	return text, nil
}

func entitlementsFromPath(path string) (map[string]any, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	url := foundation.FileURLWithPath(path)
	if url == nil {
		return nil, fmt.Errorf("invalid path %q", path)
	}

	var staticCode purego.ID
	if err := security.SecStaticCodeCreateWithPath(url, security.KSecCSDefaultFlags, unsafe.Pointer(&staticCode)); err != nil {
		return nil, err
	}
	if staticCode == 0 {
		return nil, fmt.Errorf("SecStaticCodeCreateWithPath returned nil")
	}
	code := obj.Wrap(staticCode)
	defer corefoundation.CFRelease(code)

	info, err := security.SecCodeCopySigningInformation(code, secCSSigningInformation|secCSRequirementInformation)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("no signing information for %q", path)
	}
	defer corefoundation.CFRelease(info)

	infoDict, ok := obj.As(info, "NSDictionary", foundation.DictionaryFromID)
	if !ok {
		return nil, fmt.Errorf("signing information is not a dictionary")
	}

	ents := infoDict.ObjectForKey(security.KSecCodeInfoEntitlementsDict())
	if ents == nil {
		return nil, entitlements.ErrEntitlementNotFound
	}

	raw := cfconv.ObjectToAny(ents)
	dict, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("entitlements is not a dictionary")
	}
	return dict, nil
}

func plistBool(value any) bool {
	enabled, ok := cfconv.BoolFromAny(value)
	if !ok {
		return false
	}
	return enabled
}
