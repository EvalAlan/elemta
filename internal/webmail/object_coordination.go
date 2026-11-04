package webmail

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

// IMAP has no compare-and-swap for an object represented by a message. All
// webmail and DAV writes therefore share this lock, including the DAV read
// that checks the client's ETag. Valkey carries it across webmail replicas.
type objectCoordinator struct {
	locks  [256]sync.Mutex
	valkey *valkeySessions
}

func (c *objectCoordinator) localLock(key string) *sync.Mutex {
	hash := sha256.Sum256([]byte(key))
	return &c.locks[hash[0]]
}

func (c *objectCoordinator) withLock(ctx context.Context, owner string, collection Collection, store Mailstore, fn func() error) error {
	key := strings.ToLower(owner) + "\x00" + string(collection)
	local := c.localLock(key)
	local.Lock()
	defer local.Unlock()
	if c.valkey == nil {
		return fn()
	}
	requestCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lockKey := "elemta:webmail:object-lock:" + accountKey(key)
	token, err := randomToken(24)
	if err != nil {
		return err
	}
	for {
		err = c.valkey.client.Do(ctx, c.valkey.client.B().Set().Key(lockKey).Value(token).Nx().Ex(2*time.Minute).Build()).Error()
		if err == nil {
			break
		}
		if !valkey.IsValkeyNil(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	// A lost lock must interrupt the IMAP operation before another writer can
	// take ownership. Renew well before the lease expires.
	stop := make(chan struct{})
	finished := make(chan struct{})
	lost := make(chan error, 1)
	go func() {
		defer close(finished)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				refresh, done := context.WithTimeout(requestCtx, 5*time.Second)
				const script = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('EXPIRE', KEYS[1], 120) end; return 0`
				n, err := c.valkey.client.Do(refresh, c.valkey.client.B().Eval().Script(script).Numkeys(1).Key(lockKey).Arg(token).Build()).AsInt64()
				done()
				if err != nil || n != 1 {
					_ = store.Close()
					lost <- errors.New("webmail: object write coordination lost")
					return
				}
			}
		}
	}()
	err = fn()
	close(stop)
	<-finished
	select {
	case lostErr := <-lost:
		err = errors.Join(err, lostErr)
	default:
	}
	release, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	const releaseScript = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end; return 0`
	if releaseErr := c.valkey.client.Do(release, c.valkey.client.B().Eval().Script(releaseScript).Numkeys(1).Key(lockKey).Arg(token).Build()).Error(); releaseErr != nil {
		err = errors.Join(err, releaseErr)
	}
	return err
}

type coordinatedMailstore struct {
	Mailstore
	owner string
	coord *objectCoordinator
}

func (s coordinatedMailstore) PutObject(ctx context.Context, c Collection, obj Object) error {
	return s.coord.withLock(ctx, s.owner, c, s.Mailstore, func() error { return s.Mailstore.PutObject(ctx, c, obj) })
}

func (s coordinatedMailstore) DeleteObject(ctx context.Context, c Collection, id string) error {
	return s.coord.withLock(ctx, s.owner, c, s.Mailstore, func() error { return s.Mailstore.DeleteObject(ctx, c, id) })
}

func (s coordinatedMailstore) DAVTransaction(ctx context.Context, c Collection, fn func(ObjectStore) error) error {
	return s.coord.withLock(ctx, s.owner, c, s.Mailstore, func() error { return fn(s.Mailstore) })
}

func coordinatedObjectDialer(coord *objectCoordinator, security *securityClient, dial Dialer) Dialer {
	return func(ctx context.Context, user, password string) (Mailstore, error) {
		st, err := dial(ctx, user, password)
		if err != nil {
			return nil, err
		}
		owner := strings.ToLower(user)
		// A shared mailbox ("member|mailbox") is opened for its mail only,
		// never its objects, and the mailbox already checked the grant at
		// IMAP login. The security API knows plain accounts, so asking it
		// would refuse every shared mailbox.
		if isCalendarLogin(user) {
			id, err := calendarOwnerID(ctx, security, user, password)
			if err != nil {
				_ = st.Close()
				return nil, errors.New("webmail: cannot resolve object owner")
			}
			owner = id
		} else if security != nil && !strings.Contains(user, "|") {
			check, err := security.check(ctx, user, password)
			if err != nil || check.AccountID == "" {
				_ = st.Close()
				return nil, errors.New("webmail: cannot resolve object owner")
			}
			owner = check.AccountID
		}
		return coordinatedMailstore{Mailstore: st, owner: owner, coord: coord}, nil
	}
}
