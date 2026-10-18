package policy

import "errors"

// Heartbeat is an optional product policy for applications that explicitly
// monitor long-running work. Zero disables it; clients never start a monitor
// merely because a policy is present.
type Heartbeat struct {
	IntervalSeconds int `json:"interval_seconds"`
	GraceSeconds    int `json:"grace_seconds"`
}

func (p Heartbeat) Enabled() bool { return p.IntervalSeconds != 0 || p.GraceSeconds != 0 }

// Validate checks the centrally configured check cadence and maximum permitted
// time without contact. Signed lease expiry is capped by GraceSeconds.
func (p Heartbeat) Validate() error {
	if !p.Enabled() {
		return nil
	}
	if p.IntervalSeconds < 30 || p.IntervalSeconds > 86400 {
		return errors.New("heartbeat interval must be 30 to 86400 seconds")
	}
	if p.GraceSeconds < p.IntervalSeconds || p.GraceSeconds > 31536000 {
		return errors.New("heartbeat contact grace must be at least the interval and at most 31536000 seconds")
	}
	return nil
}
