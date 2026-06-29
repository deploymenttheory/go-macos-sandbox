//go:build darwin

package violation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ebitengine/purego/objc"

	"github.com/deploymenttheory/go-bindings-macosplatform/bindings/runtime/purego"
	foundation "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/foundation"
	oslog "github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/framework/oslog"
	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/obj"
)

const (
	// The kernel reports App Sandbox violations to the unified log under this
	// subsystem and category. See Apple's "Discovering and diagnosing App Sandbox
	// violations" documentation.
	violationSubsystem = "com.apple.sandbox.reporting"
	violationCategory  = "violation"

	defaultViolationMaxRows = 1000
)

// A Violation is one App Sandbox denial recorded in the unified log.
type Violation struct {
	// Time is when the violation was logged.
	Time time.Time
	// Process and PID identify the offending process (best-effort).
	Process string
	PID     int
	// Operation is the denied sandbox operation, e.g. "network-outbound".
	Operation string
	// Path is the resource the operation targeted, when the message includes one.
	Path string
	// Message is the full composed log message, preserved verbatim.
	Message string
}

// matches "deny(1) network-outbound /private/var/run/mDNSResponder"
var violationDenyRe = regexp.MustCompile(`deny\(\d+\)\s+(\S+)(?:\s+([^\n]*))?`)

// matches "SampleApp(12447)" in the text preceding the deny clause
var violationProcessRe = regexp.MustCompile(`([^\s()]+)\((\d+)\)`)

// RecentViolations returns App Sandbox violations logged within the last since
// duration, up to maxRows entries (most recent window first). It reads the local
// unified log store, so it observes violations from any process on the system, not
// only the current one. A non-positive maxRows uses a default cap.
func RecentViolations(since time.Duration, maxRows int) ([]Violation, error) {
	if maxRows <= 0 {
		maxRows = defaultViolationMaxRows
	}

	store, err := oslog.LocalStoreAndReturnError()
	if err != nil {
		return nil, fmt.Errorf("open unified log store: %w", err)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: local store is nil", ErrLogStore)
	}

	var position *oslog.LogPosition
	if since > 0 {
		start := time.Now().Add(-since)
		position = store.PositionWithDate(
			foundation.DateWithTimeIntervalSince1970(float64(start.Unix())),
		)
	}

	// The values are interpolated as quoted literals, so the resulting predicate
	// string contains no '%' or '$' format characters.
	predicate := foundation.PredicateWithFormat(fmt.Sprintf(
		"subsystem == %q AND category == %q", violationSubsystem, violationCategory))
	if predicate == nil {
		return nil, fmt.Errorf("%w: invalid predicate", ErrLogStore)
	}

	enumerator, err := store.EntriesEnumeratorWithOptionsPositionPredicateError(
		0,
		position,
		predicate,
	)
	if err != nil {
		return nil, fmt.Errorf("enumerate log entries: %w", err)
	}
	if enumerator == nil {
		return nil, nil
	}
	enum := foundation.EnumeratorFromID(obj.ID(enumerator))
	if enum == nil {
		return nil, nil
	}

	var results []Violation
	for {
		next := enum.NextObject()
		if next == nil {
			break
		}
		if !next.IsKind("OSLogEntryLog") {
			continue
		}
		entry := oslog.LogEntryLogFromID(obj.ID(next))
		if entry == nil {
			continue
		}
		results = append(results, violationFromEntry(entry))
		if len(results) >= maxRows {
			break
		}
	}
	return results, nil
}

func violationFromEntry(entry *oslog.LogEntryLog) Violation {
	id := obj.ID(entry)
	message := entry.ComposedMessage()

	violation := Violation{
		Time:    entryDate(entry),
		Process: violationSendString(id, "process"),
		PID:     violationSendInt(id, "processIdentifier"),
		Message: message,
	}

	violation.Operation, violation.Path = parseViolationOperation(message)

	// The structured fields are sometimes empty on these synthetic entries; recover
	// the process name and pid from the message body when needed.
	if violation.Process == "" || violation.PID == 0 {
		process, pid := parseViolationProcess(message)
		if violation.Process == "" {
			violation.Process = process
		}
		if violation.PID == 0 {
			violation.PID = pid
		}
	}
	return violation
}

func parseViolationOperation(message string) (operation, path string) {
	match := violationDenyRe.FindStringSubmatch(message)
	if match == nil {
		return "", ""
	}
	return match[1], strings.TrimSpace(match[2])
}

func parseViolationProcess(message string) (string, int) {
	prefix := message
	if idx := strings.Index(message, "deny("); idx > 0 {
		prefix = message[:idx]
	}
	match := violationProcessRe.FindStringSubmatch(prefix)
	if match == nil {
		return "", 0
	}
	pid, _ := strconv.Atoi(match[2])
	return match[1], pid
}

func entryDate(entry *oslog.LogEntryLog) time.Time {
	dateObj := entry.Date()
	if dateObj == nil {
		return time.Time{}
	}
	date := foundation.DateFromID(obj.ID(dateObj))
	if date == nil {
		return time.Time{}
	}
	seconds := date.TimeIntervalSince1970()
	return time.Unix(0, int64(seconds*float64(time.Second)))
}

func violationSendString(id objc.ID, selector string) string {
	ret := objc.Send[objc.ID](id, objc.RegisterName(selector))
	if ret == 0 {
		return ""
	}
	return purego.GoString(ret)
}

func violationSendInt(id objc.ID, selector string) int {
	return objc.Send[int](id, objc.RegisterName(selector))
}
