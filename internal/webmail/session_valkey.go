package webmail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// valkeySessions keeps session records in Valkey, one key per session with
// the idle TTL as its expiry.
type valkeySessions struct {
	client valkey.Client
	prefix string
}

// NewValkeySessionStore connects to Valkey at addr.
func NewValkeySessionStore(addr string) (SessionStore, error) {
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	if err != nil {
		return nil, fmt.Errorf("webmail: connect to Valkey %s: %w", addr, err)
	}
	return &valkeySessions{client: client, prefix: "elemta:webmail:session:"}, nil
}

func (v *valkeySessions) Load(ctx context.Context, id string) (*SessionRecord, error) {
	data, err := v.client.Do(ctx, v.client.B().Get().Key(v.prefix+id).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec SessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	revoked, err := v.client.Do(ctx, v.client.B().Get().Key(v.prefix+"revoked:"+accountKey(strings.ToLower(rec.Address))).Build()).ToString()
	if err != nil && !valkey.IsValkeyNil(err) {
		return nil, err
	}
	if revoked != "" {
		n, e := strconv.ParseInt(revoked, 10, 64)
		if e != nil {
			return nil, e
		}
		if rec.Created.UnixNano() <= n {
			return nil, nil
		}
	}
	return &rec, nil
}

func (v *valkeySessions) Save(ctx context.Context, rec *SessionRecord, ttl time.Duration) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return v.client.Do(ctx, v.client.B().Set().Key(v.prefix+rec.ID).Value(string(data)).Ex(ttl).Build()).Error()
}

func (v *valkeySessions) Delete(ctx context.Context, id string) error {
	return v.client.Do(ctx, v.client.B().Del().Key(v.prefix+id).Build()).Error()
}

// loadSessionKey reads the 32-byte session sealing key (base64) from path,
// creating it with a fresh random key if the file doesn't exist yet. Pods
// that share sessions must share this file (a Kubernetes Secret, or a
// volume they all mount).
func loadSessionKey(path string) ([]byte, error) {
	// #nosec G304 -- the path is the operator's session_key_file setting
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("webmail: session key directory: %w", err)
		}
		// O_EXCL: if another pod created it first, use theirs.
		// #nosec G304 -- the path is the operator's session_key_file setting
		f, cerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if cerr == nil {
			_, werr := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
			cerr := f.Close()
			if werr != nil || cerr != nil {
				return nil, fmt.Errorf("webmail: write session key: %w", errors.Join(werr, cerr))
			}
			return key, nil
		}
		if !errors.Is(cerr, os.ErrExist) {
			return nil, fmt.Errorf("webmail: create session key: %w", cerr)
		}
		// #nosec G304 -- as above
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("webmail: read session key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("webmail: session key %s must hold 32 base64-encoded bytes", path)
	}
	return key, nil
}

func (v *valkeySessions) RevokeUser(ctx context.Context, address string, ttl time.Duration) error {
	return v.client.Do(ctx, v.client.B().Set().Key(v.prefix+"revoked:"+accountKey(address)).Value(strconv.FormatInt(time.Now().UnixNano(), 10)).Ex(ttl+time.Minute).Build()).Error()
}
