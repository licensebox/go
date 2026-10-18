package machine

import (
	"context"
	"os/exec"
	"time"
)

func nativeID() (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Use the system binary directly, never a shell or a PATH override.
	b, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "macos-platform", "", ErrUnavailable
	}
	id, err := platformUUID(b)
	return "macos-platform", id, err
}
