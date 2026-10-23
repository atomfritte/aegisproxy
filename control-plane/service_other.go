//go:build !windows

package main

import (
	"context"
	"errors"
)

// runAsWindowsService is a no-op outside Windows; the "service" argument is refused there.
func runAsWindowsService(_ func(ctx context.Context) error, force bool) (bool, error) {
	if force {
		return true, errors.New("the service argument is only available on Windows")
	}
	return false, nil
}
