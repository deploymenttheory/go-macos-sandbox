//go:build darwin

package bookmark

import "errors"

// ErrNotSecurityScoped is returned when a URL is not security-scoped.
var ErrNotSecurityScoped = errors.New("URL is not security-scoped")
