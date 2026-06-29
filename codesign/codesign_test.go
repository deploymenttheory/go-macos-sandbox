//go:build darwin

package codesign_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/codesign"
	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
)

func TestIsSandboxedAtPathMissingEntitlement(t *testing.T) {
	sandboxed, err := codesign.IsSandboxedAtPath("/bin/ls")
	if err != nil {
		t.Fatalf("IsSandboxedAtPath(/bin/ls) error: %v", err)
	}
	if sandboxed {
		t.Fatal("IsSandboxedAtPath(/bin/ls) = true, want false")
	}
}

func TestVerifyAtPathSystemBinary(t *testing.T) {
	verification, err := codesign.VerifyAtPath("/bin/ls")
	if err != nil {
		t.Fatalf("VerifyAtPath(/bin/ls): %v", err)
	}
	if verification.Sandboxed {
		t.Fatal("VerifyAtPath(/bin/ls).Sandboxed = true, want false")
	}
}

func TestEntitlementsFromPathSystemBinary(t *testing.T) {
	ents, err := codesign.EntitlementsFromPath("/bin/ls")
	if !errors.Is(err, entitlements.ErrEntitlementNotFound) {
		if err != nil {
			t.Fatalf("EntitlementsFromPath(/bin/ls): %v", err)
		}
		t.Logf("entitlements keys: %d", len(ents))
		return
	}
	t.Log("no embedded entitlements in /bin/ls")
}

func TestIsSandboxedAtPathKnownApp(t *testing.T) {
	candidates := []string{
		"/System/Applications/App Store.app",
		"/Applications/Safari.app",
		"/Applications/Xcode.app",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		sandboxed, err := codesign.IsSandboxedAtPath(candidate)
		if err != nil {
			t.Fatalf("IsSandboxedAtPath(%q): %v", candidate, err)
		}
		t.Logf("%s sandboxed=%v", candidate, sandboxed)
		return
	}
	t.Log("no candidate app bundle found for IsSandboxedAtPath test")
}

func TestEmbeddedHelperToolPath(t *testing.T) {
	path := codesign.EmbeddedHelperToolPath("/Applications/Foo.app", "ToolX")
	want := filepath.Join("/Applications/Foo.app", "Contents", "MacOS", "ToolX")
	if path != want {
		t.Fatalf("EmbeddedHelperToolPath() = %q, want %q", path, want)
	}
}

func TestExpectedHelperToolIdentifier(t *testing.T) {
	got := codesign.ExpectedHelperToolIdentifier("com.example.AppWithTool", "ToolX")
	want := "com.example.AppWithTool.ToolX"
	if got != want {
		t.Fatalf("ExpectedHelperToolIdentifier() = %q, want %q", got, want)
	}
}

func TestValidateHelperToolEntitlementsValid(t *testing.T) {
	verification := codesign.ValidateHelperToolEntitlements(map[string]any{
		entitlements.AppSandbox: true,
		entitlements.Inherit:    true,
	})
	if !verification.Valid() {
		t.Fatalf("ValidateHelperToolEntitlements() issues=%v", verification.Issues)
	}
}

func TestValidateHelperToolEntitlementsRejectsGetTaskAllow(t *testing.T) {
	verification := codesign.ValidateHelperToolEntitlements(map[string]any{
		entitlements.AppSandbox:   true,
		entitlements.Inherit:      true,
		entitlements.GetTaskAllow: true,
	})
	if verification.Valid() {
		t.Fatal("ValidateHelperToolEntitlements() = valid, want invalid")
	}
}

func TestValidateHelperToolEntitlementsRejectsExtraEntitlement(t *testing.T) {
	verification := codesign.ValidateHelperToolEntitlements(map[string]any{
		entitlements.AppSandbox:    true,
		entitlements.Inherit:       true,
		entitlements.NetworkClient: true,
	})
	if verification.Valid() {
		t.Fatal("ValidateHelperToolEntitlements() = valid, want invalid")
	}
	if len(verification.ExtraEntitlements) == 0 {
		t.Fatal("ExtraEntitlements is empty, want network.client")
	}
}

func TestVerifyHelperToolAtPathSystemBinary(t *testing.T) {
	verification, err := codesign.VerifyHelperToolAtPath("/bin/ls")
	if err != nil {
		t.Fatalf("VerifyHelperToolAtPath(/bin/ls): %v", err)
	}
	if verification.Valid() {
		t.Fatalf("VerifyHelperToolAtPath(/bin/ls) = valid, want invalid: %v", verification.Issues)
	}
}
