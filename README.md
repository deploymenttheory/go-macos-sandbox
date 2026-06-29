# go-macos-sandbox

Standalone Go module for inspecting and working with the **macOS App Sandbox**:
entitlement introspection, code-signature inspection, security-scoped bookmarks,
and sandbox container/violation discovery. Built on
[`go-bindings-macosplatform`](https://github.com/deploymenttheory/go-bindings-macosplatform);
**darwin-only** (every file is `//go:build darwin`).

It exists so multiple consumers (e.g. `go-macos-observability`, `guestweave-macos`)
etc can share these macOS sandbox primitives instead of each re-implementing them.

## Packages

| Package | Purpose |
|---|---|
| `entitlements` | Well-known App Sandbox entitlement key constants + shared error vocabulary |
| `process` | Sandbox status & entitlements for the current process / any PID (csops(2) + SecTask) |
| `codesign` | Code signature & embedded entitlements of on-disk binaries; helper-tool verification |
| `bookmark` | Create/resolve security-scoped bookmarks for user-selected files |
| `searchpath` | Standard container directories (Documents, Application Support, ...) |
| `container` | Discover & parse App Sandbox containers and `Container.plist` |
| `violation` | Read sandbox violation (deny) records from the unified log |

Internal packages (`internal/cfconv`, `internal/plistutil`, `internal/procpath`)
are implementation details and not part of the public API.

## Dependency graph (acyclic)

```
entitlements (leaf)
  ← internal/cfconv ← codesign ← process (← internal/procpath)
container → entitlements, internal/plistutil
bookmark · searchpath · violation → SDK only
```

## Usage

```go
import "github.com/deploymenttheory/go-macos-sandbox/process"

sandboxed, err := process.IsSandboxedSelf()
```

## Requirements

- macOS (darwin), cgo-free — uses `purego` via the bindings SDK.
- Go 1.26+.
