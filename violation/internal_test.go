//go:build darwin

package violation

import "testing"

func TestParseViolationOperation(t *testing.T) {
	message := "Sandbox: SampleApp(12447) deny(1) network-outbound /private/var/run/mDNSResponder"
	operation, path := parseViolationOperation(message)
	if operation != "network-outbound" {
		t.Fatalf("operation = %q, want network-outbound", operation)
	}
	if path != "/private/var/run/mDNSResponder" {
		t.Fatalf("path = %q", path)
	}

	process, pid := parseViolationProcess(message)
	if process != "SampleApp" || pid != 12447 {
		t.Fatalf("process=%q pid=%d, want SampleApp/12447", process, pid)
	}
}

func TestParseViolationOperationNoMatch(t *testing.T) {
	operation, path := parseViolationOperation("nothing to see here")
	if operation != "" || path != "" {
		t.Fatalf("operation=%q path=%q, want empty", operation, path)
	}
}
