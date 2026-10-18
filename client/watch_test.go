package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type heartbeatTransport func(*http.Request) (*http.Response, error)

func (f heartbeatTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func signedInWatchClient(t *testing.T, life time.Duration) (setup, *Client) {
	t.Helper()
	st := newSetup(t)
	st.srv.set(func(s *server) { s.life = life })
	c := st.run(t)
	if _, err := c.Lease(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st, c
}

func TestWatchDeadlineIndependentOfHungNetwork(t *testing.T) {
	st, c := signedInWatchClient(t, 2500*time.Millisecond)
	started, finished := make(chan struct{}), make(chan struct{})
	calls := 0
	c.cfg.HTTP = &http.Client{Transport: heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return http.DefaultTransport.RoundTrip(r)
		}
		close(started)
		<-r.Context().Done()
		close(finished)
		return nil, r.Context().Err()
	})}
	work, stop, err := c.Watch(context.Background(), "core", WatchOptions{Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not force renewal")
	}
	select {
	case <-work.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("hung HTTP extended signed authorization")
	}
	if !errors.Is(context.Cause(work), ErrOffline) {
		t.Fatalf("deadline cause: %v", context.Cause(work))
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("expiry did not cancel in-flight HTTP")
	}
	if signs, _ := st.srv.count(); signs != 1 {
		t.Fatal("monitor activated another identity")
	}
}

func TestWatchObserverCannotChangeDeadlineOrClientGrant(t *testing.T) {
	_, c := signedInWatchClient(t, 300*time.Millisecond)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	work, stop, err := c.Watch(context.Background(), "core", WatchOptions{OnCheck: func(r HeartbeatResult) {
		defer close(done)
		r.Lease.Expires = r.Lease.Expires.Add(24 * time.Hour)
		r.Lease.Modules[0] = "forged"
		close(entered)
		<-release
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	<-entered
	select {
	case <-work.Done():
	case <-time.After(time.Second):
		t.Fatal("blocked observer extended deadline")
	}
	if !errors.Is(context.Cause(work), ErrOffline) {
		t.Fatalf("observer deadline: %v", context.Cause(work))
	}
	c.mu.Lock()
	hasCore := c.checked != nil && c.checked.Has("core") && !c.checked.Has("forged")
	c.mu.Unlock()
	if !hasCore {
		t.Fatal("observer mutated client authorization")
	}
}

func TestWatchExplicitStopAndObserverFailure(t *testing.T) {
	for _, panicObserver := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "observer panic"}[panicObserver], func(t *testing.T) {
			_, c := signedInWatchClient(t, time.Hour)
			opts := WatchOptions{}
			if panicObserver {
				opts.OnCheck = func(HeartbeatResult) { panic("consumer callback") }
			}
			work, stop, err := c.Watch(context.Background(), "core", opts)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if !panicObserver {
				stop()
			}
			select {
			case <-work.Done():
			case <-time.After(time.Second):
				t.Fatal("monitor did not cancel")
			}
			if panicObserver && errors.Is(context.Cause(work), context.Canceled) {
				t.Fatal("observer failure lost cause")
			}
			if !panicObserver && !errors.Is(context.Cause(work), context.Canceled) {
				t.Fatal(context.Cause(work))
			}
		})
	}
}

func TestWatchDoesNotActivateMissingIdentity(t *testing.T) {
	st := newSetup(t)
	_, _, err := st.run(t).Watch(context.Background(), "core", WatchOptions{})
	if !errors.Is(err, ErrNotSignedIn) {
		t.Fatal(err)
	}
	if signs, renewals := st.srv.count(); signs != 0 || renewals != 0 {
		t.Fatal("monitor started sign-in")
	}
}

func TestWatchOfflineChecksCannotRestartDeadlineWhenClockStops(t *testing.T) {
	st, c := signedInWatchClient(t, 1500*time.Millisecond)
	// The saved clock can stop advancing after the OS wall clock rolls back.
	// New offline observations must retain the initial monotonic deadline.
	c.cfg.HTTP = &http.Client{Transport: fixedHTTPResponse{503, `{"error":"unavailable"}`}}
	began := time.Now()
	work, stop, err := c.Watch(context.Background(), "core", WatchOptions{Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-work.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("offline checks restarted the signed allowance")
	}
	if !errors.Is(context.Cause(work), ErrOffline) {
		t.Fatal(context.Cause(work))
	}
	if time.Since(began) > 1900*time.Millisecond {
		t.Fatal("authorization extended past original deadline")
	}
	if _, renewals := st.srv.count(); renewals != 0 {
		t.Fatal("offline fixture unexpectedly renewed")
	}
}

type stalledRefusalBody struct{}

func (stalledRefusalBody) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (stalledRefusalBody) Close() error             { return nil }
func TestHeartbeatPreservesRefusalHeadersWhenBodyTimesOut(t *testing.T) {
	_, c := signedInWatchClient(t, time.Hour)
	c.cfg.HTTP = &http.Client{Transport: heartbeatTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Status: "403 Forbidden", Header: make(http.Header), Body: stalledRefusalBody{}}, nil
	})}
	result, err := c.Heartbeat(context.Background(), "core")
	var refused *PolicyError
	if err == nil || result.Online || !errors.As(err, &refused) || refused.Code != "http_error" {
		t.Fatalf("stalled refusal used offline fallback: %+v %v", result, err)
	}
}
