package queue

import (
	"context"
	"strings"
	"testing"
)

func TestMessageRequiresTLS(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want bool
	}{
		{name: "no annotations", msg: Message{}, want: false},
		{name: "require tls true", msg: Message{Annotations: map[string]string{"require_tls": "true"}}, want: true},
		{name: "require tls numeric", msg: Message{Annotations: map[string]string{"require_tls": "1"}}, want: true},
		{name: "require tls false", msg: Message{Annotations: map[string]string{"require_tls": "false"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messageRequiresTLS(tt.msg); got != tt.want {
				t.Fatalf("messageRequiresTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeliverMessageWithMetadata_RejectsRequireTLS(t *testing.T) {
	h := NewSMTPDeliveryHandler(0)
	msg := Message{
		ID:   "msg-1",
		From: "sender@example.com",
		To:   []string{"recipient@example.net"},
		Annotations: map[string]string{
			"require_tls": "true",
		},
	}

	result, err := h.DeliverMessageWithMetadata(context.Background(), msg, []byte("hello"))
	if err == nil {
		t.Fatal("expected REQUIRETLS enforcement error, got nil")
	}
	if result == nil {
		t.Fatal("expected delivery result, got nil")
	}
	if result.Success {
		t.Fatal("expected unsuccessful delivery result")
	}
	if !strings.Contains(err.Error(), "REQUIRETLS") {
		t.Fatalf("expected error to mention REQUIRETLS, got: %v", err)
	}
}
