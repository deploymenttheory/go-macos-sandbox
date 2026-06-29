//go:build darwin

// Package container discovers macOS App Sandbox container directories (system
// and per-user) and parses their Container.plist metadata, plus app-group and
// iCloud ubiquity container paths.
package container
