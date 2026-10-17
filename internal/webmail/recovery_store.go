package webmail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/valkey-io/valkey-go"
)

// RecoveryStore lives outside the mailbox: a locked-out user cannot open IMAP.
// Take and Claim must be atomic across all webmail instances.
type RecoveryStore interface {
	Get(context.Context, string) (string, error)
	Put(context.Context, string, string, time.Duration) error
	Take(context.Context, string) (string, error)
	Claim(context.Context, string, string, time.Duration) (bool, error)
}

type valkeyRecovery struct{ client valkey.Client }

func recoveryKey(key string) string { return "elemta:webmail:recovery:" + key }
func accountKey(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:])
}
func tokenKey(token string) string { return "token:" + accountKey(token) }
func (v valkeyRecovery) Get(ctx context.Context, key string) (string, error) {
	s, err := v.client.Do(ctx, v.client.B().Get().Key(recoveryKey(key)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return "", nil
	}
	return s, err
}
func (v valkeyRecovery) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	b := v.client.B().Set().Key(recoveryKey(key)).Value(value)
	if ttl > 0 {
		return v.client.Do(ctx, b.Ex(ttl).Build()).Error()
	}
	return v.client.Do(ctx, b.Build()).Error()
}
func (v valkeyRecovery) Take(ctx context.Context, key string) (string, error) {
	s, err := v.client.Do(ctx, v.client.B().Arbitrary("GETDEL").Keys(recoveryKey(key)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return "", nil
	}
	return s, err
}
func (v valkeyRecovery) Claim(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	err := v.client.Do(ctx, v.client.B().Set().Key(recoveryKey(key)).Value(value).Nx().Ex(ttl).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	return err == nil, err
}
