//go:build darwin

package process

import (
	"errors"
	"fmt"

	purego "github.com/deploymenttheory/go-bindings-macosplatform/bindings/runtime/purego"
	corefoundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/corefoundation"
	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
	security "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/security"
	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/obj"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/internal/cfconv"
)

// IsSandboxed reports whether the current process has App Sandbox enabled.
func IsSandboxed() (bool, error) {
	return HasCurrentTaskEntitlement(entitlements.AppSandbox)
}

// HasCurrentTaskEntitlement reports whether the current process holds a Boolean entitlement.
// A missing entitlement returns (false, nil).
func HasCurrentTaskEntitlement(key string) (bool, error) {
	value, err := CurrentTaskEntitlement(key)
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

// CurrentTaskEntitlement returns the entitlement value for the current process.
func CurrentTaskEntitlement(key string) (any, error) {
	return taskEntitlementValue(nil, key)
}

// CurrentTaskEntitlements returns entitlement values for the given keys on the current process.
// Missing keys are omitted from the result map.
func CurrentTaskEntitlements(keys []string) (map[string]any, error) {
	task := security.SecTaskCreateFromSelf(nil)
	if task == nil {
		return nil, fmt.Errorf("SecTaskCreateFromSelf returned nil")
	}
	defer corefoundation.CFRelease(task)

	keyObjects := make([]*foundation.String, len(keys))
	for index, key := range keys {
		keyObjects[index] = foundation.NewStringWithUTF8String(key)
	}
	arrayID := purego.SliceToNSArray(keyObjects, func(keyObject *foundation.String) purego.ID {
		return obj.ID(keyObject)
	})
	array := obj.Wrap(arrayID)
	if array == nil {
		return nil, fmt.Errorf("failed to build entitlement key array")
	}

	values, err := security.SecTaskCopyValuesForEntitlements(task, array)
	if err != nil {
		return nil, err
	}
	if values == nil {
		return map[string]any{}, nil
	}
	defer corefoundation.CFRelease(values)

	dict, ok := obj.As(values, "NSDictionary", foundation.DictionaryFromID)
	if !ok {
		return nil, fmt.Errorf("entitlement values is not a dictionary")
	}

	result := make(map[string]any, len(keys))
	for _, key := range keys {
		keyObject := foundation.NewStringWithUTF8String(key)
		raw := dict.ObjectForKey(keyObject)
		if raw == nil {
			continue
		}
		converted, err := cfconv.ObjectValue(raw)
		if err != nil {
			return nil, fmt.Errorf("entitlement %q: %w", key, err)
		}
		result[key] = converted
	}
	return result, nil
}

func taskEntitlementValue(task obj.Object, key string) (any, error) {
	if task == nil {
		task = security.SecTaskCreateFromSelf(nil)
		if task == nil {
			return nil, fmt.Errorf("SecTaskCreateFromSelf returned nil")
		}
		defer corefoundation.CFRelease(task)
	}

	value, err := security.SecTaskCopyValueForEntitlement(task, foundation.NewStringWithUTF8String(key))
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, entitlements.ErrEntitlementNotFound
	}
	defer corefoundation.CFRelease(value)
	return cfconv.ObjectValue(value)
}
