//go:build darwin

// Package searchpath resolves standard container directories (Documents,
// Application Support, Caches, Downloads, ...) inside the App Sandbox, wrapping
// FileManager.URLForDirectory(inDomain:appropriateFor:create:).
package searchpath
