//go:build darwin

package violation_test

import (
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-sandbox/violation"
)

func TestRecentViolationsSmoke(t *testing.T) {
	violations, err := violation.RecentViolations(time.Hour, 50)
	if err != nil {
		t.Fatalf("RecentViolations(): %v", err)
	}
	for _, v := range violations {
		if v.Message == "" {
			t.Fatal("violation has empty message")
		}
	}
	t.Logf("found %d sandbox violations in the last hour", len(violations))
}
