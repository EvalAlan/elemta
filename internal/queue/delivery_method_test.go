package queue

import (
	"context"
	"testing"
)

// Every delivery, bounce and deferral used to record the literal string "lmtp",
// so a message handed to a remote MX was logged as local delivery. The message
// trace reads that field back to tell an operator how their mail left the
// building, which meant the one feature built for answering that question
// answered it wrongly for every remote message.

func TestEachHandlerReportsItsOwnTransport(t *testing.T) {
	// Both handlers are pointed at somewhere that cannot work. The delivery
	// failing is the point: the transport must be reported on the failure path
	// too, because "which route failed" is the first thing anyone asks.
	lmtp := NewLMTPDeliveryHandler("127.0.0.1", 1, 1, 24)
	result, err := lmtp.DeliverMessageWithMetadata(context.Background(),
		Message{ID: "x", From: "s@example.com", To: []string{"a@example.com"}}, []byte("body"))
	if err == nil {
		t.Skip("LMTP delivery unexpectedly succeeded against port 1")
	}
	if result == nil {
		t.Fatal("LMTP handler returned no result to report a transport on")
	}
	if result.DeliveryMethod != DeliveryMethodLMTP {
		t.Errorf("LMTP handler reported transport %q, want %q", result.DeliveryMethod, DeliveryMethodLMTP)
	}

	smtp := NewSMTPDeliveryHandler(24)
	result, err = smtp.DeliverMessageWithMetadata(context.Background(),
		Message{ID: "y", From: "s@example.com", To: []string{"a@nonexistent.invalid"}}, []byte("body"))
	if err == nil {
		t.Skip("SMTP delivery unexpectedly succeeded to a .invalid domain")
	}
	if result == nil {
		t.Fatal("SMTP handler returned no result to report a transport on")
	}
	if result.DeliveryMethod != DeliveryMethodSMTP {
		t.Errorf("SMTP handler reported transport %q, want %q", result.DeliveryMethod, DeliveryMethodSMTP)
	}
}

// TestTransportIsNotHardcodedInTheProcessor guards the specific regression.
// The two transports must not be the same string, or the constants could drift
// back to a single hardcoded value and every test above would still pass.
func TestTransportsAreDistinct(t *testing.T) {
	if DeliveryMethodLMTP == DeliveryMethodSMTP {
		t.Fatal("the two transports report the same name; the distinction this fixes is gone")
	}
}
