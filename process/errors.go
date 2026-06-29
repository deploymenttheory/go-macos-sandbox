//go:build darwin

package process

import "errors"

var (
	// ErrInvalidPID is returned when a process identifier is not positive.
	ErrInvalidPID = errors.New("invalid pid")

	// ErrCSOps is returned when the csops(2) system call fails.
	ErrCSOps = errors.New("csops operation failed")
)
