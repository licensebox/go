package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixedHTTPResponse struct {
	status int
	body   string
}

func (f fixedHTTPResponse) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Status: http.StatusText(f.status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func TestNonJSONRefusalDoesNotPermitOfflineFallback(t *testing.T) {
	st := newSetup(t)
	if _, err := st.run(t).Lease(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := st.run(t)
	c.cfg.HTTP = &http.Client{Transport: fixedHTTPResponse{403, "Forbidden"}}
	_, err := c.Require(context.Background(), "core")
	var refused *apiError
	if !errors.As(err, &refused) || refused.status != 403 {
		t.Fatalf("HTTP refusal used cached lease: %v", err)
	}
}

func TestExpiredLeaseAndServerOutageReturnsOffline(t *testing.T) {
	st := newSetup(t)
	if _, err := st.run(t).Lease(context.Background()); err != nil {
		t.Fatal(err)
	}
	*st.clock = st.clock.Add(25 * time.Hour)
	c := st.run(t)
	c.cfg.HTTP = &http.Client{Transport: fixedHTTPResponse{503, `{"error":"unavailable"}`}}
	if _, err := c.Require(context.Background(), "core"); !errors.Is(err, ErrOffline) {
		t.Fatalf("server outage past expiry: %v", err)
	}
}
