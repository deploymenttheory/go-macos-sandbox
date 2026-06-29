//go:build darwin

// Package bookmark creates and resolves macOS security-scoped bookmarks, which
// let a sandboxed app persist and regain access to user-selected files and
// folders across launches. BeginSecurityScopedAccess accepts only
// security-scoped URLs (from bookmarks or Open/Save panels), not plain file URLs.
package bookmark
