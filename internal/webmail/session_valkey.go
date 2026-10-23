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

	"github.com/EvalAlan/elemta/internal/valkeyaddr"
	"github.com/valkey-io/valkey-go"
)

// valkeySessions keeps session records in Valkey, one key per session with
// the idle TTL as its expiry.
type valkeySessions struct {
	client valkey.Client
	prefix string
}

// startupWait is how long starting up waits for Valkey to accept a
// connection before giving up (valkeyaddr.Dial).
const startupWait = 30 * time.Second

// NewValkeySessionStore connects to Valkey at addr.
func NewValkeySessionStore(addr string) (SessionStore, error) {
	client, err := valkeyaddr.Dial(addr, func(o *valkey.ClientOption) { o.DisableCache = true }, startupWait)
	if err != nil {
		return nil, fmt.Errorf("webmail: connect to Valkey %s: %w", valkeyaddr.Display(addr), err)
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
	const saveMonotonic = `
local old = redis.call('GET', KEYS[1])
if old then
  local previous = cjson.decode(old)
  local seen = previous.seen_ns or '0'
  if #seen > #ARGV[2] or (#seen == #ARGV[2] and seen > ARGV[2]) then
    return 0
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
return 1`
	seen := rec.SeenNanos
	if seen == "" {
		seen = strconv.FormatInt(rec.LastSeen.UnixNano(), 10)
	}
	return v.client.Do(ctx, v.client.B().Eval().Script(saveMonotonic).Numkeys(1).Key(v.prefix+rec.ID).
		Arg(string(data), seen, strconv.FormatInt(ttl.Milliseconds(), 10)).Build()).Error()
}

func (v *valkeySessions) Delete(ctx context.Context, id string) error {
	return v.client.Do(ctx, v.client.B().Del().Key(v.prefix+id).Build()).Error()
}

func (v *valkeySessions) pendingKey(token string) string { return v.prefix + "pending:" + token }

func (v *valkeySessions) pendingPut(ctx context.Context, token string, sealed []byte, ttl time.Duration) error {
	const script = `redis.call('HSET', KEYS[1], 'data', ARGV[1], 'attempts', 0); redis.call('PEXPIRE', KEYS[1], ARGV[2]); return 1`
	return v.client.Do(ctx, v.client.B().Eval().Script(script).Numkeys(1).Key(v.pendingKey(token)).Arg(string(sealed), strconv.FormatInt(ttl.Milliseconds(), 10)).Build()).Error()
}

func (v *valkeySessions) pendingGet(ctx context.Context, token string) ([]byte, error) {
	b, err := v.client.Do(ctx, v.client.B().Hget().Key(v.pendingKey(token)).Field("data").Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	return b, err
}

func (v *valkeySessions) pendingFail(ctx context.Context, token string, max int) bool {
	const script = `if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local n = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if n >= tonumber(ARGV[1]) then redis.call('DEL', KEYS[1]); return 0 end
return 1`
	n, err := v.client.Do(ctx, v.client.B().Eval().Script(script).Numkeys(1).Key(v.pendingKey(token)).Arg(strconv.Itoa(max)).Build()).AsInt64()
	return err == nil && n == 1
}

func (v *valkeySessions) pendingDrop(ctx context.Context, token string) bool {
	n, err := v.client.Do(ctx, v.client.B().Del().Key(v.pendingKey(token)).Build()).AsInt64()
	return err == nil && n == 1
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
