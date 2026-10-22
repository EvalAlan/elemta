package auth

// Sessions shared between dashboard instances.
//
// The dashboard kept its sessions in the process's memory, so a second
// instance behind the same address didn't know anyone was signed in and a
// restart signed everyone out. With a shared backend (Valkey) every
// instance reads the same sessions. Each request reads the backend rather
// than a local copy, so signing out or revoking a user's sessions on one
// instance holds on all of them at once; the dashboard's traffic is
// administrators', small enough for that.
//
// A session is stored under a hash of its ID, so reading the store doesn't
// yield cookies that would sign someone in.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// SessionBackend stores sessions for every instance.
type SessionBackend interface {
	Save(ctx context.Context, s *Session) error
	Load(ctx context.Context, id string) (*Session, error) // nil, nil when absent
	Delete(ctx context.Context, id string) error
	DeleteUser(ctx context.Context, username string) (int, error)
}

// SetBackend makes the manager keep its sessions in b.
func (sm *SessionManager) SetBackend(b SessionBackend) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.shared = b
}

const sharedTimeout = 3 * time.Second

func sessionKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

type valkeySessions struct {
	client valkey.Client
	prefix string
}

// NewValkeySessionBackend connects to Valkey at addr.
func NewValkeySessionBackend(addr string) (SessionBackend, error) {
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	if err != nil {
		return nil, fmt.Errorf("dashboard sessions: connect to Valkey %s: %w", addr, err)
	}
	return &valkeySessions{client: client, prefix: "elemta:dashboard:"}, nil
}

func (v *valkeySessions) Save(ctx context.Context, s *Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	key := sessionKey(s.ID)
	users := v.prefix + "user:" + s.Username
	cmds := valkey.Commands{
		v.client.B().Set().Key(v.prefix + "session:" + key).Value(string(data)).Px(ttl).Build(),
		v.client.B().Sadd().Key(users).Member(key).Build(),
		v.client.B().Pexpire().Key(users).Milliseconds(ttl.Milliseconds()).Build(),
	}
	for _, r := range v.client.DoMulti(ctx, cmds...) {
		if err := r.Error(); err != nil {
			return err
		}
	}
	return nil
}

func (v *valkeySessions) Load(ctx context.Context, id string) (*Session, error) {
	data, err := v.client.Do(ctx, v.client.B().Get().Key(v.prefix+"session:"+sessionKey(id)).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (v *valkeySessions) Delete(ctx context.Context, id string) error {
	return v.client.Do(ctx, v.client.B().Del().Key(v.prefix+"session:"+sessionKey(id)).Build()).Error()
}

func (v *valkeySessions) DeleteUser(ctx context.Context, username string) (int, error) {
	users := v.prefix + "user:" + username
	keys, err := v.client.Do(ctx, v.client.B().Smembers().Key(users).Build()).AsStrSlice()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		deleted, err := v.client.Do(ctx, v.client.B().Del().Key(v.prefix+"session:"+k).Build()).AsInt64()
		if err != nil {
			return n, err
		}
		n += int(deleted)
	}
	return n, v.client.Do(ctx, v.client.B().Del().Key(users).Build()).Error()
}
