//go:build darwin

// Package codesign inspects the code signature and embedded entitlements of
// on-disk Mach-O binaries and app bundles via the Security framework's
// SecStaticCode APIs, including verification of embedded sandboxed helper tools.
package codesign
