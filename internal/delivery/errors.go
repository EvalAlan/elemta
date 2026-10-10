package delivery

import (
	"fmt"
	"time"
)

// ErrorType classifies a delivery error.
type ErrorType string

// ErrorTypePolicy marks a refusal by a delivery policy such as MTA-STS.
const ErrorTypePolicy ErrorType = "policy"

// DeliveryError represents a structured delivery error
type DeliveryError struct {
	Type       ErrorType     `json:"type"`
	Code       int           `json:"code,omitempty"`
	Message    string        `json:"message"`
	Details    string        `json:"details,omitempty"`
	Temporary  bool          `json:"temporary"`
	Retryable  bool          `json:"retryable"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// Error implements the error interface
func (e *DeliveryError) Error() string {
	return fmt.Sprintf("%s error: %s", e.Type, e.Message)
}
