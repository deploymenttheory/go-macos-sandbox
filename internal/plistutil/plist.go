//go:build darwin

// Package plistutil provides minimal plist decoding and value coercion helpers.
package plistutil

import (
	"errors"
	"os"

	howettplist "howett.net/plist"
)

// ReadPlistFile decodes a plist file into a string-keyed map.
func ReadPlistFile(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var root any
	if err := howettplist.NewDecoder(f).Decode(&root); err != nil {
		return nil, err
	}
	dict, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("plist root is not a dictionary")
	}
	return dict, nil
}

// PlistString coerces a plist value to string.
func PlistString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PlistBool coerces a plist value to bool.
func PlistBool(v any) bool {
	switch typed := v.(type) {
	case bool:
		return typed
	case int64:
		return typed != 0
	case uint64:
		return typed != 0
	case float64:
		return typed != 0
	default:
		return false
	}
}
