//go:build darwin

package process_test

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/deploymenttheory/go-macos-sandbox/entitlements"
	"github.com/deploymenttheory/go-macos-sandbox/process"
)

func TestIsSandboxedCurrentProcess(t *testing.T) {
	sandboxed, err := process.IsSandboxed()
	if err != nil {
		t.Fatalf("IsSandboxed() error: %v", err)
	}
	t.Logf("current process sandboxed=%v", sandboxed)
}

func TestIsProcessSandboxedSelf(t *testing.T) {
	pid := os.Getpid()
	sandboxed, err := process.IsProcessSandboxed(pid)
	if err != nil {
		t.Fatalf("IsProcessSandboxed(%d): %v", pid, err)
	}
	current, err := process.IsSandboxed()
	if err != nil {
		t.Fatalf("IsSandboxed(): %v", err)
	}
	if sandboxed != current {
		t.Fatalf("IsProcessSandboxed(%d)=%v, IsSandboxed()=%v", pid, sandboxed, current)
	}
}

func TestIsProcessSandboxedInvalidPID(t *testing.T) {
	_, err := process.IsProcessSandboxed(0)
	if err == nil {
		t.Fatal("IsProcessSandboxed(0) error = nil, want error")
	}
}

func TestCurrentTaskEntitlementReturnsGoValue(t *testing.T) {
	value, err := process.CurrentTaskEntitlement(entitlements.AppSandbox)
	if errors.Is(err, entitlements.ErrEntitlementNotFound) {
		if value != nil {
			t.Fatalf("CurrentTaskEntitlement() value = %v, want nil", value)
		}
		return
	}
	if err != nil {
		t.Fatalf("CurrentTaskEntitlement(): %v", err)
	}
	if _, ok := value.(bool); !ok {
		t.Fatalf("CurrentTaskEntitlement() type = %T, want bool", value)
	}
}

func TestProcessEntitlementMatchesSelf(t *testing.T) {
	pid := os.Getpid()
	value, err := process.ProcessEntitlement(pid, entitlements.AppSandbox)
	if errors.Is(err, entitlements.ErrEntitlementNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("ProcessEntitlement(): %v", err)
	}
	current, err := process.CurrentTaskEntitlement(entitlements.AppSandbox)
	if err != nil {
		t.Fatalf("CurrentTaskEntitlement(): %v", err)
	}
	if value != current {
		t.Fatalf("ProcessEntitlement()=%v, CurrentTaskEntitlement()=%v", value, current)
	}
}

func TestProcessEntitlementShell(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sh: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	sandboxed, err := process.IsProcessSandboxed(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("IsProcessSandboxed(%d): %v", cmd.Process.Pid, err)
	}
	if sandboxed {
		t.Fatalf("IsProcessSandboxed(/bin/sh) = true, want false")
	}
}
