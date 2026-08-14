package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// Enqueue tombstones record that a message ID was consumed, so a repeated
// enqueue of the same ID is recognised rather than silently duplicating mail.
// Detecting the *conflicting* case — the same ID carrying different bytes —
// only needs to compare content, not keep it.
//
// It used to keep it. Every tombstone stored the whole message body forever,
// in both the SQLite and Postgres backends, and nothing ever deleted a
// tombstone. Measured on a development queue after two days of load testing:
// 296,707 tombstones holding 1.9GB of message bodies, 93% of a 2.6GB database,
// for 62,464 live messages. That is a disk leak that ends in a full disk, and
// on the way there it slows every enqueue, because each one probes an index
// that never stops growing.
//
// A digest answers the same question in 32 bytes.

// tombstoneRetentionHours bounds how long a consumed identity is remembered.
//
// The tombstone protects against a duplicate enqueue of an ID the queue has
// already handled. That is a retry, and retries happen within minutes or hours
// — not days. A day is generous and keeps the table small enough to stay in
// cache. Set alongside the processor's own cleanup age so the two prune
// together.
const tombstoneRetentionHours = 24

// tombstoneDigest is what a tombstone stores in place of the message body.
func tombstoneDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// sameTombstoneContent reports whether a stored tombstone refers to these exact
// bytes.
//
// Rows written before tombstones stored a digest kept the whole body and have
// no digest, so those are still compared by content. Both forms are accepted
// rather than migrated: the rows age out within tombstoneRetentionHours, and a
// migration that rewrites a multi-gigabyte table on startup is a worse thing to
// own than a branch that deletes itself.
func sameTombstoneContent(storedDigest string, storedContent, content []byte) bool {
	if storedDigest != "" {
		return storedDigest == tombstoneDigest(content)
	}
	return bytes.Equal(storedContent, content)
}

// Retaining the message body in a tombstone is a rollback guarantee, and it is
// expensive.
//
// A binary rolled back to a build that predates ContentHash reads only the
// body. If it finds an empty one it decides every retry conflicts and starts
// refusing mail, which is why TestNewTombstoneRemainsReadableByOldBinaries
// exists. The cost is a full-size copy of every message written on every
// successful delivery: measured at 2,243 bytes per tombstone and 885MB across
// 452,502 of them on a development queue.
//
// Which trade is right depends on how far back a deployment can roll, so it is
// configurable. The flag is phrased negatively — drop rather than retain — so
// that the Go zero value keeps the body. A backend built as a struct literal,
// which the tests do, must not silently opt into the unsafe side.
//
// Pruning bounds the disk cost either way, and incidentally bounds the rollback
// window: nothing older than the retention period survives to be misread.
type tombstoneBodyPolicy struct {
	dropBody bool
}

// bodyFor returns what should be stored as the tombstone body.
func (p tombstoneBodyPolicy) bodyFor(content []byte) []byte {
	if p.dropBody {
		return []byte{}
	}
	return content
}
