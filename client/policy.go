package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrMachineChanged  = errors.New("licensebox: these credentials belong to another machine; explicitly sign in to activate this machine")
	ErrSeatTransferred = errors.New("licensebox: this licence seat is allocated to another machine; explicitly sign in to transfer it back")
	ErrLocationDenied  = errors.New("licensebox: use from this location is not permitted or cannot be verified")
)

// PolicyError is an explicit server refusal, never an offline condition.
// The refusal is retained until a successful renewal or explicit sign-in.
type PolicyError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *PolicyError) Error() string { return "licensebox: " + e.Detail }
func (e *PolicyError) Is(target error) bool {
	return e.Code == "machine_changed" && target == ErrMachineChanged || e.Code == "seat_transferred" && target == ErrSeatTransferred ||
		(e.Code == "location_denied" || e.Code == "location_unknown") && target == ErrLocationDenied
}

func (c *Client) denialPath() string { return filepath.Join(c.cfg.Dir, "policy-denial") }

func (c *Client) denial() error {
	b, err := os.ReadFile(c.denialPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var e PolicyError
	if json.Unmarshal(b, &e) != nil || e.Code == "" || e.Detail == "" {
		return errors.New("licensebox: saved policy refusal is damaged; connect to renew the licence")
	}
	return &e
}

func (c *Client) rememberDenial(e *apiError) error {
	p := &PolicyError{Code: e.Code, Detail: e.Detail}
	if p.Detail == "" {
		p.Detail = e.Code
	}
	b, _ := json.Marshal(p)
	if err := c.write(c.denialPath(), string(b)); err != nil {
		return fmt.Errorf("%w (could not save refusal: %v)", p, err)
	}
	return p
}

func (c *Client) clearDenial() error {
	err := os.Remove(c.denialPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
