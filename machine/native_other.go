//go:build !linux && !darwin && !windows

package machine

func nativeID() (string, string, error) { return "unsupported platform", "", ErrUnavailable }
