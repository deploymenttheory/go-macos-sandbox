//go:build darwin

package process

import (
	"errors"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-macos-sandbox/codesign"
	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/cfconv"
	"github.com/deploymenttheory/go-macos-sandbox/internal/procpath"
)

// IsProcessSandboxed reports whether pid runs with App Sandbox enabled.
// A missing entitlement returns (false, nil).
func IsProcessSandboxed(pid int) (bool, error) {
	return ProcessEntitlementBool(pid, entitlements.AppSandbox)
}

// ProcessEntitlementBool reports whether pid holds a Boolean entitlement.
// A missing entitlement returns (false, nil).
func ProcessEntitlementBool(pid int, key string) (bool, error) {
	value, err := ProcessEntitlement(pid, key)
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

// ProcessEntitlement returns one runtime entitlement value for pid.
func ProcessEntitlement(pid int, key string) (any, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	if pid == os.Getpid() {
		return CurrentTaskEntitlement(key)
	}

	ents, err := processEntitlements(pid)
	if err == nil {
		value, ok := ents[key]
		if !ok {
			return nil, entitlements.ErrEntitlementNotFound
		}
		return value, nil
	}
	if !errors.Is(err, entitlements.ErrEntitlementNotFound) {
		return nil, err
	}
	return entitlementFromExecutable(pid, key)
}

// ProcessEntitlements returns runtime entitlement values for pid and keys.
// Missing keys are omitted from the result map.
func ProcessEntitlements(pid int, keys []string) (map[string]any, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	if pid == os.Getpid() {
		return CurrentTaskEntitlements(keys)
	}

	ents, err := processEntitlements(pid)
	if err != nil {
		if !errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return nil, err
		}
		ents = map[string]any{}
	}

	path, pathErr := procpath.Path(pid)
	if pathErr != nil && len(ents) == 0 {
		return nil, pathErr
	}
	if pathErr == nil {
		signed, err := codesign.EntitlementsFromPath(path)
		if err != nil && !errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return nil, err
		}
		for key, value := range signed {
			if _, exists := ents[key]; !exists {
				ents[key] = value
			}
		}
	}

	result := make(map[string]any, len(keys))
	for _, key := range keys {
		value, ok := ents[key]
		if !ok {
			continue
		}
		result[key] = value
	}
	return result, nil
}

// ProcessEntitlementString coerces a string entitlement for pid when present.
func ProcessEntitlementString(pid int, key string) (string, error) {
	value, err := ProcessEntitlement(pid, key)
	if err != nil {
		return "", err
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("entitlement %q is not a string", key)
	}
	return text, nil
}

// ProcessApplicationGroups returns application group identifiers granted to pid.
func ProcessApplicationGroups(pid int) ([]string, error) {
	value, err := ProcessEntitlement(pid, entitlements.ApplicationGroups)
	if err != nil {
		if errors.Is(err, entitlements.ErrEntitlementNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return stringSliceFromAny(value)
}

func entitlementFromExecutable(pid int, key string) (any, error) {
	path, err := procpath.Path(pid)
	if err != nil {
		return nil, err
	}
	return codesign.EntitlementValueAtPath(path, key)
}

func stringSliceFromAny(value any) ([]string, error) {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("item %d is not a string", index)
			}
			out = append(out, text)
		}
		return out, nil
	case []string:
		return typed, nil
	default:
		return nil, fmt.Errorf("value is not a string array")
	}
}
