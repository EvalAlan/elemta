package queue

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"testing"
)

func TestIsTemporaryFailureClassification(t *testing.T) {
	p := &Processor{}

	temp := []error{
		&TemporaryError{msg: "mock"},
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		&net.DNSError{Err: "no such host", Name: "target.invalid", IsNotFound: true},
		&textproto.Error{Code: 451, Msg: "try later"},
		fmt.Errorf("failed to connect: %w", errors.New("connection refused")),
		errors.New("450 4.2.0 greylisted, try again"),
		errors.New("i/o timeout"),
		errors.New("EOF"),
		errors.New("something unrecognized entirely"), // default -> temporary
	}
	for _, e := range temp {
		if !p.isTemporaryFailure(e) {
			t.Errorf("expected temporary for %v", e)
		}
	}

	perm := []error{
		&PermanentError{msg: "recipient domain does not exist", err: &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}},
		&textproto.Error{Code: 550, Msg: "no such user"},
		errors.New("550 5.1.1 user unknown"),
		errors.New("554 5.7.1 rejected"),
	}
	for _, e := range perm {
		if p.isTemporaryFailure(e) {
			t.Errorf("expected permanent for %v", e)
		}
	}

	if p.isTemporaryFailure(nil) {
		t.Error("nil error should not be temporary")
	}
}

func TestCalculateNextRetryHonorsSchedule(t *testing.T) {
	m := &Manager{retrySchedule: []int{10, 20, 40}}

	// Delays follow the configured schedule and increase across attempts;
	// attempts beyond the schedule repeat the final interval.
	a1 := m.calculateNextRetry(1) // ~10s
	a2 := m.calculateNextRetry(2) // ~20s
	a3 := m.calculateNextRetry(3) // ~40s
	a4 := m.calculateNextRetry(4) // repeats ~40s
	if !(a1.Before(a2) && a2.Before(a3)) {
		t.Errorf("expected increasing retry delays: a1=%v a2=%v a3=%v", a1, a2, a3)
	}
	if a4.Before(a2) {
		t.Errorf("expected attempts beyond schedule to repeat the last interval, a4=%v a2=%v", a4, a2)
	}
}
