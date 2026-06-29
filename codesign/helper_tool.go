//go:build darwin

package codesign

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/cfconv"
)

// RequiredHelperToolEntitlements are the only entitlements Apple recommends for
// embedded sandbox helper tools.
var RequiredHelperToolEntitlements = []string{
	entitlements.AppSandbox,
	entitlements.Inherit,
}

// IncompatibleWithInheritEntitlements lists entitlements that must not appear on
// helper tools signed with com.apple.security.inherit.
var IncompatibleWithInheritEntitlements = []string{
	entitlements.GetTaskAllow,
}

// HelperToolVerification reports whether an embedded helper tool meets Apple's
// sandbox inheritance signing requirements.
type HelperToolVerification struct {
	Path                string
	SigningIdentifier   string
	Sandboxed           bool
	InheritsSandbox     bool
	Entitlements        map[string]any
	ExtraEntitlements   []string
	IncompatiblePresent []string
	Issues              []string
}

// Valid reports whether the helper tool satisfies Apple's minimum requirements.
func (verification HelperToolVerification) Valid() bool {
	return len(verification.Issues) == 0
}

// EmbeddedHelperToolPath returns the recommended helper tool location inside
// an app bundle: Contents/MacOS/<toolName>.
func EmbeddedHelperToolPath(appBundlePath, toolName string) string {
	return filepath.Join(appBundlePath, "Contents", "MacOS", toolName)
}

// ExpectedHelperToolIdentifier returns the conventional code-signing identifier
// for a helper tool embedded in appBundleIdentifier.
func ExpectedHelperToolIdentifier(appBundleIdentifier, toolName string) string {
	return appBundleIdentifier + "." + toolName
}

// VerifyEmbeddedHelperTool validates a helper tool embedded in appBundlePath.
func VerifyEmbeddedHelperTool(appBundlePath, toolName string) (HelperToolVerification, error) {
	return VerifyHelperToolAtPath(EmbeddedHelperToolPath(appBundlePath, toolName))
}

// VerifyHelperToolAtPath validates helper tool entitlements at path.
func VerifyHelperToolAtPath(path string) (HelperToolVerification, error) {
	if path == "" {
		return HelperToolVerification{}, fmt.Errorf("path is required")
	}
	if _, err := os.Stat(path); err != nil {
		return HelperToolVerification{Path: path}, err
	}

	verification, err := VerifyAtPath(path)
	if err != nil {
		return HelperToolVerification{Path: path}, err
	}

	identifier, err := SigningIdentifierAtPath(path)
	if err != nil {
		return HelperToolVerification{Path: path}, err
	}

	result := ValidateHelperToolEntitlements(verification.Entitlements)
	result.Path = path
	result.SigningIdentifier = identifier
	result.Sandboxed = verification.Sandboxed
	result.InheritsSandbox = plistBool(verification.Entitlements[entitlements.Inherit])
	return result, nil
}

// IsHelperToolAtPath reports whether path is signed as a sandbox-inheriting helper.
func IsHelperToolAtPath(path string) (bool, error) {
	verification, err := VerifyHelperToolAtPath(path)
	if err != nil {
		return false, err
	}
	return verification.Valid(), nil
}

// ValidateHelperToolEntitlements evaluates entitlements against Apple's embedded
// helper tool guidance without reading code signatures from disk.
func ValidateHelperToolEntitlements(ents map[string]any) HelperToolVerification {
	result := HelperToolVerification{
		Entitlements: ents,
	}
	if ents == nil {
		ents = map[string]any{}
	}

	if !plistBool(ents[entitlements.AppSandbox]) {
		result.Issues = append(result.Issues, "missing com.apple.security.app-sandbox entitlement")
	}
	if !plistBool(ents[entitlements.Inherit]) {
		result.Issues = append(result.Issues, "missing com.apple.security.inherit entitlement")
	}

	for _, key := range IncompatibleWithInheritEntitlements {
		if plistBool(ents[key]) {
			result.IncompatiblePresent = append(result.IncompatiblePresent, key)
			result.Issues = append(result.Issues, fmt.Sprintf("entitlement %q is incompatible with sandbox inheritance", key))
		}
	}

	required := map[string]struct{}{
		entitlements.AppSandbox: {},
		entitlements.Inherit:    {},
	}
	for key, value := range ents {
		if _, ok := required[key]; ok {
			continue
		}
		if !entitlementIsActive(value) {
			continue
		}
		result.ExtraEntitlements = append(result.ExtraEntitlements, key)
	}
	sort.Strings(result.ExtraEntitlements)
	sort.Strings(result.IncompatiblePresent)

	if len(result.ExtraEntitlements) > 0 {
		result.Issues = append(result.Issues,
			fmt.Sprintf("helper tool should only include %q and %q; found extra entitlements: %v",
				entitlements.AppSandbox, entitlements.Inherit, result.ExtraEntitlements))
	}

	result.Sandboxed = plistBool(ents[entitlements.AppSandbox])
	result.InheritsSandbox = plistBool(ents[entitlements.Inherit])
	return result
}

// VerifySandboxedAppWithHelper validates a sandboxed app bundle and one embedded helper.
func VerifySandboxedAppWithHelper(appBundlePath, toolName string) (app Verification, helper HelperToolVerification, err error) {
	app, err = VerifyAtPath(appBundlePath)
	if err != nil {
		return Verification{}, HelperToolVerification{}, err
	}
	if !app.Sandboxed {
		return app, HelperToolVerification{}, fmt.Errorf("app is not sandboxed")
	}

	helper, err = VerifyEmbeddedHelperTool(appBundlePath, toolName)
	if err != nil {
		return app, helper, err
	}
	if !helper.Valid() {
		return app, helper, fmt.Errorf("embedded helper tool is invalid")
	}
	return app, helper, nil
}

func entitlementIsActive(value any) bool {
	if value == nil {
		return false
	}
	if enabled, ok := cfconv.BoolFromAny(value); ok {
		return enabled
	}
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case string:
		return typed != ""
	default:
		return true
	}
}
