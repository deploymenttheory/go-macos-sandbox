//go:build darwin

package container

import "errors"

// ErrContainerNotFound is returned when a sandbox container URL cannot be resolved.
var ErrContainerNotFound = errors.New("sandbox container not found")
