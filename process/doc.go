//go:build darwin

// Package process inspects App Sandbox status and code-signing entitlements for
// the current process and for arbitrary PIDs.
//
// It offers two complementary paths: a csops(2) syscall path (no Objective-C
// runtime, safe to call from any goroutine) used by the *Self helpers, and the
// Security framework's SecTask APIs for richer queries. Process lookups fall
// back to reading the executable's static signature (see package codesign).
package process
