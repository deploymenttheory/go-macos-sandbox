//go:build darwin

package entitlements

import "errors"

var (
	// ErrEntitlementNotFound is returned when an entitlement key is absent.
	ErrEntitlementNotFound = errors.New("entitlement not found")

	// ErrMalformedEntitlements is returned when an entitlements blob cannot be parsed.
	ErrMalformedEntitlements = errors.New("malformed entitlements")
)
