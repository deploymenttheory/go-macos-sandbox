//go:build darwin

package violation

import "errors"

// ErrLogStore is returned when the unified log store cannot be queried.
var ErrLogStore = errors.New("unified log store error")
