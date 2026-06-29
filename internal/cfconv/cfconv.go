//go:build darwin

package cfconv

import (
	"encoding/json"
	"fmt"

	corefoundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/corefoundation"
	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/obj"
	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/rt"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
)

const cfStringEncodingUTF8 = 0x08000100

// ObjectToAny converts a CoreFoundation property-list object to a Go value.
func ObjectToAny(value obj.Object) any {
	converted, _ := ObjectValue(value)
	return converted
}

// ObjectValue converts a CoreFoundation property-list object to a Go value,
// returning an error when conversion fails.
func ObjectValue(value obj.Object) (any, error) {
	if value == nil {
		return nil, entitlements.ErrEntitlementNotFound
	}
	// NSJSONSerialization rejects a scalar top-level value (a bare boolean, number,
	// or string is not valid JSON) and throws an ObjC exception that crashes the
	// process. Entitlement values are frequently scalars — most notably the
	// com.apple.security.app-sandbox boolean read by IsSandboxed. Wrap the value in
	// an array so the top level is always JSON-legal, then unwrap the single element.
	wrapper := foundation.NewMutableArrayWithCapacity(1)
	wrapper.AddObject(value)

	data, err := foundation.DataWithJSONObjectOptionsError(wrapper, 0)
	if err != nil {
		return nil, fmt.Errorf("serialize entitlement value: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("%w: empty JSON for entitlement value", entitlements.ErrMalformedEntitlements)
	}
	var result []any
	if err := json.Unmarshal(rt.NSDataToBytes(obj.ID(data)), &result); err != nil {
		return nil, fmt.Errorf("decode entitlement value: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf(
			"%w: empty JSON array for entitlement value",
			entitlements.ErrMalformedEntitlements,
		)
	}
	return result[0], nil
}

// ObjectToBool coerces a CoreFoundation entitlement value to bool.
func ObjectToBool(value obj.Object) (bool, bool) {
	if value == nil {
		return false, false
	}
	if corefoundation.CFGetTypeID(value) == corefoundation.CFBooleanGetTypeID() {
		return corefoundation.CFBooleanGetValue(value) != 0, true
	}
	if number, ok := obj.As(value, "NSNumber", foundation.NumberFromID); ok {
		return number.BoolValue(), true
	}
	if str, ok := obj.As(value, "NSString", foundation.StringFromID); ok {
		return str.BoolValue(), true
	}
	return false, false
}

// ObjectToString coerces a CoreFoundation string object to string.
func ObjectToString(value obj.Object) string {
	if value == nil {
		return ""
	}
	if s := corefoundation.CFStringGetCStringPtr(value, cfStringEncodingUTF8); s != "" {
		return s
	}
	if str, ok := obj.As(value, "NSString", foundation.StringFromID); ok {
		return str.SubstringFromIndex(0)
	}
	return ""
}

// BoolFromAny coerces a decoded property-list value to bool.
func BoolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}
