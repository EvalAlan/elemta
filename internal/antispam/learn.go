package antispam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The classes Rspamd can be taught.
const (
	LearnSpam = "spam"
	LearnHam  = "ham"
)

// ErrLearnRefused means Rspamd will never accept this message, so sending it
// again is pointless. Everything else Learn returns is worth a retry.
var ErrLearnRefused = errors.New("rspamd refused the message")

// Learner teaches Rspamd's classifier through its controller. Scanning uses
// the normal worker on another port, which has no learning endpoints.
type Learner struct {
	address  string
	password string
	client   *http.Client
}

// NewLearner returns a client for the controller at address, such as
// http://elemta-rspamd:11334. The password is the controller's
// enable_password; learning changes shared state, so Rspamd requires it.
func NewLearner(address, password string) *Learner {
	return &Learner{
		address:  strings.TrimRight(address, "/"),
		password: password,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Learn teaches Rspamd that msg, a complete message, is of the given class.
//
// The statuses below were read from a running Rspamd rather than its
// documentation. 208 is the common one: a message delivered to several people
// who all report it is learned once. 204 is a message too short to tokenise.
// A 401 stays retryable, because a wrong password is a deployment mistake that
// gets fixed, and dropping users' feedback meanwhile would hide it.
func (l *Learner) Learn(ctx context.Context, class string, msg []byte) error {
	var path string
	switch class {
	case LearnSpam:
		path = "/learnspam"
	case LearnHam:
		path = "/learnham"
	default:
		return fmt.Errorf("rspamd: unknown class %q", class)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.address+path, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("rspamd: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Password", l.password)
	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("rspamd: learn: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("rspamd: learn: %s: check the controller password", resp.Status)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: %s", ErrLearnRefused, resp.Status)
	default:
		return fmt.Errorf("rspamd: learn: unexpected status %s", resp.Status)
	}
}
