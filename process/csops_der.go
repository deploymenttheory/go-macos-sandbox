//go:build darwin

package process

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
)

// parseDEREntitlements decodes Apple's DER-encoded entitlements blob (the payload
// returned by csops CS_OPS_DER_ENTITLEMENTS_BLOB) into a Go dictionary.
//
// The encoding, defined by Apple's CoreEntitlements, maps property-list values
// onto ASN.1 as follows:
//
//	dictionary -> SET OF entitlement     (entitlement = SEQUENCE { key, value })
//	array      -> SEQUENCE OF value
//	boolean    -> BOOLEAN
//	integer    -> INTEGER
//	string     -> UTF8String
//
// The top level is a SEQUENCE { version INTEGER, root SET }; we also accept a bare
// dictionary for resilience against format variations.
func parseDEREntitlements(data []byte) (map[string]any, error) {
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode DER entitlements: %w", err)
	}
	if root.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("%w: unexpected class %d", entitlements.ErrMalformedEntitlements, root.Class)
	}

	switch root.Tag {
	case asn1.TagSet:
		return derDictionary(root)
	case asn1.TagSequence:
		children, err := derChildren(root.Bytes)
		if err != nil {
			return nil, err
		}
		// Versioned form: SEQUENCE { INTEGER version, SET root }.
		if len(children) == 2 && children[0].Tag == asn1.TagInteger {
			return derDictionary(children[1])
		}
		// Otherwise treat the sequence's children as entitlement entries directly.
		return derEntriesToMap(children)
	default:
		return nil, fmt.Errorf(
			"%w: unexpected top-level tag %d",
			entitlements.ErrMalformedEntitlements,
			root.Tag,
		)
	}
}

// derDictionary interprets a SET (or SEQUENCE) of entitlement entries as a map.
func derDictionary(value asn1.RawValue) (map[string]any, error) {
	children, err := derChildren(value.Bytes)
	if err != nil {
		return nil, err
	}
	return derEntriesToMap(children)
}

func derEntriesToMap(entries []asn1.RawValue) (map[string]any, error) {
	out := make(map[string]any, len(entries))
	for _, entry := range entries {
		if entry.Tag != asn1.TagSequence {
			return nil, fmt.Errorf(
				"%w: entry is not a SEQUENCE (tag %d)",
				entitlements.ErrMalformedEntitlements,
				entry.Tag,
			)
		}
		fields, err := derChildren(entry.Bytes)
		if err != nil {
			return nil, err
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf(
				"%w: entry has %d fields, want key and value",
				entitlements.ErrMalformedEntitlements, len(fields),
			)
		}
		key, err := derString(fields[0])
		if err != nil {
			return nil, err
		}
		value, err := derValue(fields[1])
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

// derValue converts one DER entitlement value to a Go value, recursing into
// arrays (SEQUENCE) and nested dictionaries (SET).
func derValue(value asn1.RawValue) (any, error) {
	if value.Class != asn1.ClassUniversal {
		return value.FullBytes, nil
	}
	switch value.Tag {
	case asn1.TagBoolean:
		if len(value.Bytes) != 1 {
			return nil, fmt.Errorf(
				"%w: BOOLEAN of length %d",
				entitlements.ErrMalformedEntitlements,
				len(value.Bytes),
			)
		}
		return value.Bytes[0] != 0, nil
	case asn1.TagInteger:
		// asn1 recognizes big integers only through a **big.Int target.
		var number *big.Int
		if _, err := asn1.Unmarshal(value.FullBytes, &number); err != nil {
			return nil, fmt.Errorf("malformed INTEGER: %w", err)
		}
		if number.IsInt64() {
			return number.Int64(), nil
		}
		return number, nil
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		return string(value.Bytes), nil
	case asn1.TagSequence:
		children, err := derChildren(value.Bytes)
		if err != nil {
			return nil, err
		}
		array := make([]any, 0, len(children))
		for _, child := range children {
			element, err := derValue(child)
			if err != nil {
				return nil, err
			}
			array = append(array, element)
		}
		return array, nil
	case asn1.TagSet:
		return derDictionary(value)
	default:
		return value.FullBytes, nil
	}
}

func derString(value asn1.RawValue) (string, error) {
	switch value.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		return string(value.Bytes), nil
	default:
		return "", fmt.Errorf(
			"%w: key is not a string (tag %d)",
			entitlements.ErrMalformedEntitlements,
			value.Tag,
		)
	}
}

// derChildren splits the contents of a constructed DER value into its elements.
func derChildren(content []byte) ([]asn1.RawValue, error) {
	var children []asn1.RawValue
	for len(content) > 0 {
		var child asn1.RawValue
		rest, err := asn1.Unmarshal(content, &child)
		if err != nil {
			return nil, fmt.Errorf("split DER value: %w", err)
		}
		children = append(children, child)
		content = rest
	}
	return children, nil
}
