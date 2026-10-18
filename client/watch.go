package client

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// WatchOptions configures an explicitly started monitor. OnCheck runs on a
// monitor worker and must return promptly. It never runs under the client lock.
type WatchOptions struct {
	// Interval defaults to the signed server interval, or five minutes when no
	// policy is configured. A configured server interval caps a slower choice.
	Interval time.Duration
	OnCheck  func(HeartbeatResult)
}

// Watch performs an initial noninteractive Heartbeat and returns a context for
// protected work plus a stop function. Revocation, module loss or the last signed
// expiry cancels that context; inspect context.Cause to explain why. The caller
// decides how to checkpoint/pause/stop work. No process is terminated.
//
// No monitor exists until Watch is called. Always call stop when work finishes.
// Its expiry timer is independent of HTTP and observer callbacks, so a slow
// check cannot extend the last verified authorization deadline.
func (c *Client) Watch(parent context.Context, module string, options WatchOptions) (context.Context, context.CancelFunc, error) {
	if options.Interval < 0 || options.Interval > 0 && options.Interval < time.Second {
		return nil, nil, errors.New("licensebox: heartbeat interval must be at least one second")
	}
	initial, err := c.Heartbeat(parent, module)
	if err != nil {
		return nil, nil, err
	}
	work, cancel := context.WithCancelCause(parent)
	stop := func() { cancel(context.Canceled) }
	type event struct {
		result HeartbeatResult
		err    error
	}
	results := make(chan event, 1)
	observe := func(r HeartbeatResult) (err error) {
		defer func() {
			if recover() != nil {
				err = errors.New("licensebox: heartbeat observer failed")
			}
		}()
		if options.OnCheck != nil {
			r.Lease = copyHeartbeatLease(r.Lease)
			options.OnCheck(r)
		}
		return nil
	}
	remaining := func(r HeartbeatResult) time.Duration {
		return r.Lease.Expires.Sub(r.observedAt) - time.Since(r.observedWall)
	}
	// Keep one monotonic deadline. Offline results cannot restart its allowance
	// when the host wall clock moves backward or stops advancing.
	deadlineAt := initial.observedWall.Add(initial.Lease.Expires.Sub(initial.observedAt))
	interval := func(r HeartbeatResult) time.Duration {
		d := options.Interval
		if d == 0 {
			d = 5 * time.Minute
		}
		if p := r.Lease.Heartbeat; p != nil {
			limit := time.Duration(p.IntervalSeconds) * time.Second
			if options.Interval == 0 || d > limit {
				d = limit
			}
		}
		left := time.Until(deadlineAt)
		// Renew ahead of expiry; a grant with less than a second remaining is
		// simply bounded by the independent expiry timer rather than busy-polled.
		if left > time.Second {
			d = min(d, left/2)
		} else {
			d = min(d, left)
		}
		return max(d, time.Millisecond)
	}
	go func() {
		deadline := time.NewTimer(max(time.Until(deadlineAt), 0))
		next := time.NewTimer(interval(initial))
		defer deadline.Stop()
		defer next.Stop()
		inFlight := false
		launch := func(first *HeartbeatResult) {
			inFlight = true
			go func() {
				var item event
				if first != nil {
					item.result = *first
				} else {
					item.result, item.err = c.Heartbeat(work, module)
				}
				if item.err == nil {
					item.err = observe(item.result)
				}
				select {
				case results <- item:
				case <-work.Done():
				}
			}()
		}
		if options.OnCheck != nil {
			launch(&initial)
		}
		for {
			select {
			case <-work.Done():
				return
			case <-deadline.C:
				cancel(fmt.Errorf("%w: heartbeat contact deadline elapsed", ErrOffline))
				return
			case <-next.C:
				if !inFlight {
					launch(nil)
				}
			case item := <-results:
				inFlight = false
				if work.Err() != nil {
					return
				}
				// A late result cannot bridge an elapsed authorization deadline,
				// even when select chooses it before an already-ready timer.
				if !time.Now().Before(deadlineAt) {
					cancel(ErrOffline)
					return
				}
				if item.err != nil {
					cancel(item.err)
					return
				}
				left := remaining(item.result)
				if left <= 0 {
					cancel(ErrOffline)
					return
				}
				if item.result.Online {
					deadlineAt = item.result.observedWall.Add(item.result.Lease.Expires.Sub(item.result.observedAt))
					if !deadline.Stop() {
						select {
						case <-deadline.C:
						default:
						}
					}
					deadline.Reset(max(time.Until(deadlineAt), 0))
				}
				if !next.Stop() {
					select {
					case <-next.C:
					default:
					}
				}
				next.Reset(interval(item.result))
			}
		}
	}()
	return work, stop, nil
}
