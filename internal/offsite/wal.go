package offsite

// Continuous archiving of the mailbox database's write-ahead log (WAL), so a
// restore can reach any moment rather than the last six-hourly backup.
//
// Postgres hands each finished WAL file to its archive_command, which copies
// it into a local directory (docker-compose.yml). PushWAL seals each one, the
// same way as a backup (gzip, then age to the public key), uploads it as
// <prefix>wal/<name>.gz.age, checks the object arrived whole, and only then
// deletes the local copy. A restore fetches them back (FetchWAL, which needs
// the age identity, so it runs where the private key is) and replays them on
// top of the base backup in the newest six-hourly backup before the target.
//
// Every name is checked against what Postgres writes, so nothing else in the
// directory can be uploaded, and only objects named so are listed, so pruning
// can't reach anything else in the bucket.

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/minio/minio-go/v7"
)

// walSegmentSize is the size of every WAL segment file: the Postgres default,
// which the stack doesn't change. An archived segment of another size was cut
// short (a crash between copying and syncing it) and would break replay at
// that point, so it is refused rather than uploaded.
const walSegmentSize = 16 << 20

var (
	walSegmentName = regexp.MustCompile(`^[0-9A-F]{24}$`)
	walOtherName   = regexp.MustCompile(`^([0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup)$`)
)

// IsWALName reports whether name is a file Postgres archives: a segment, a
// timeline history file or a base backup's label.
func IsWALName(name string) bool {
	return walSegmentName.MatchString(name) || walOtherName.MatchString(name)
}

const walDir = "wal/"

func (c *Client) walKey(name string) string { return c.cfg.Prefix + walDir + name + ".gz.age" }

// WALObject is one archived WAL file in the bucket.
type WALObject struct {
	Name     string // as Postgres named it
	Key      string
	Size     int64
	Uploaded time.Time
}

// SealFile writes the file at path to w, gzipped and encrypted to the age
// recipient.
func SealFile(w io.Writer, path, recipient string) error {
	r, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
	if err != nil {
		return fmt.Errorf("offsite: age recipient: %w", err)
	}
	f, err := os.Open(path) // #nosec G304 -- a name PushWAL checked, in the directory it was given
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(enc)
	if _, err := io.Copy(zw, f); err != nil {
		return err
	}
	return errors.Join(zw.Close(), enc.Close())
}

// OpenFile reverses SealFile: it decrypts r with the identities and writes
// the original bytes to w.
func OpenFile(w io.Writer, r io.Reader, ids ...age.Identity) error {
	dec, err := age.Decrypt(r, ids...)
	if err != nil {
		return err
	}
	zr, err := gzip.NewReader(dec)
	if err != nil {
		return err
	}
	// A segment is 16 MiB; the limit keeps a damaged or hostile object from
	// filling the disk.
	n, err := io.Copy(w, io.LimitReader(zr, walSegmentSize+1))
	if err != nil {
		return err
	}
	if n > walSegmentSize {
		return errors.New("offsite: archived WAL file is larger than a segment")
	}
	return zr.Close()
}

// PushWAL uploads every archived WAL file in dir, oldest first, and deletes
// each local copy once its object is confirmed. It stops at the first
// failure, so the files left are always the newest ones. It returns how many
// went up.
func (c *Client) PushWAL(ctx context.Context, dir, recipient string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && IsWALName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// History files before segments of the same timeline doesn't matter to a
	// restore, which fetches everything first; name order is age order within
	// a timeline, which is what "the newest are left" needs.
	sort.Strings(names)
	pushed := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return pushed, err
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			return pushed, err
		}
		if walSegmentName.MatchString(name) && info.Size() != walSegmentSize {
			return pushed, fmt.Errorf("offsite: %s is %d bytes, not a whole segment; left in place", name, info.Size())
		}
		if err := c.putSealed(ctx, c.walKey(name), path, recipient); err != nil {
			return pushed, err
		}
		if err := os.Remove(path); err != nil {
			return pushed, err
		}
		pushed++
	}
	return pushed, nil
}

func (c *Client) putSealed(ctx context.Context, key, path, recipient string) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(SealFile(pw, path, recipient)) }()
	info, err := c.mc.PutObject(ctx, c.cfg.Bucket, key, pr, -1, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		PartSize:    16 << 20,
	})
	_ = pr.CloseWithError(err)
	if err != nil {
		return fmt.Errorf("offsite: upload %s: %w", key, err)
	}
	st, err := c.mc.StatObject(ctx, c.cfg.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return fmt.Errorf("offsite: check %s: %w", key, err)
	}
	if st.Size != info.Size {
		return fmt.Errorf("offsite: %s holds %d bytes, %d were sent", key, st.Size, info.Size)
	}
	return nil
}

// ListWAL returns the archived WAL files in the bucket, in name order.
func (c *Client) ListWAL(ctx context.Context) ([]WALObject, error) {
	var out []WALObject
	prefix := c.cfg.Prefix + walDir
	for o := range c.mc.ListObjects(ctx, c.cfg.Bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		name, ok := strings.CutSuffix(strings.TrimPrefix(o.Key, prefix), ".gz.age")
		if !ok || !IsWALName(name) {
			continue
		}
		out = append(out, WALObject{Name: name, Key: o.Key, Size: o.Size, Uploaded: o.LastModified})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// FetchWAL downloads and opens every archived WAL file whose name sorts at
// or after from (all of them when from is empty) into dir, which a restore
// then names in restore_command. History files are always fetched: replay
// needs them to follow a timeline switch.
func (c *Client) FetchWAL(ctx context.Context, dir, from string, ids ...age.Identity) (int, error) {
	objs, err := c.ListWAL(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range objs {
		if from != "" && o.Name < from && !strings.HasSuffix(o.Name, ".history") {
			continue
		}
		if err := c.fetchOne(ctx, o, filepath.Join(dir, o.Name), ids...); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (c *Client) fetchOne(ctx context.Context, o WALObject, dest string, ids ...age.Identity) error {
	obj, err := c.mc.GetObject(ctx, c.cfg.Bucket, o.Key, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = obj.Close() }()
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- dest is dir plus a checked WAL name
	if err != nil {
		return err
	}
	if err := OpenFile(f, obj, ids...); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("offsite: open %s: %w", o.Key, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// PruneWAL picks the archived WAL files to delete: those uploaded more than
// keep before the newest upload. Measured from the newest, like Prune, so an
// archiver that has been stopped doesn't age everything out on its return.
func PruneWAL(objs []WALObject, keep time.Duration) (drop []WALObject) {
	var newest time.Time
	for _, o := range objs {
		if o.Uploaded.After(newest) {
			newest = o.Uploaded
		}
	}
	cutoff := newest.Add(-keep)
	for _, o := range objs {
		if o.Uploaded.Before(cutoff) {
			drop = append(drop, o)
		}
	}
	return drop
}

// Delete removes one object; DeleteWAL is it for WAL files.
func (c *Client) DeleteWAL(ctx context.Context, o WALObject) error { return c.Delete(ctx, o.Key) }

// segmentNumber turns a segment name into its timeline and position in the
// WAL, so consecutive segments can be checked for gaps. With 16 MiB segments
// each log file holds 256 of them.
func segmentNumber(name string) (timeline uint64, pos uint64, ok bool) {
	if !walSegmentName.MatchString(name) {
		return 0, 0, false
	}
	tl, err1 := strconv.ParseUint(name[:8], 16, 32)
	log, err2 := strconv.ParseUint(name[8:16], 16, 32)
	seg, err3 := strconv.ParseUint(name[16:], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil || seg >= 1<<32/walSegmentSize {
		return 0, 0, false
	}
	return tl, log*(1<<32/walSegmentSize) + seg, true
}

// LatestBaseStart is the first segment the newest base backup needs, from
// the label file Postgres archives when a base backup finishes
// (<segment>.<offset>.backup), or "" when none is archived.
func LatestBaseStart(objs []WALObject) string {
	latest := ""
	for _, o := range objs {
		if strings.HasSuffix(o.Name, ".backup") && o.Name > latest {
			latest = o.Name
		}
	}
	if latest == "" {
		return ""
	}
	return latest[:24]
}

// WALGaps lists the segments missing from the archive from segment from (all
// archived segments when from is "") to the newest, at most limit of them.
// A gap means a restore can't replay past it, so with from the newest base
// backup's start (LatestBaseStart) an empty answer says a restore to the
// latest moment would work. A timeline switch (after a point-in-time
// restore) starts a new run of names and isn't a gap.
func WALGaps(objs []WALObject, from string, limit int) []string {
	byTimeline := map[uint64][]uint64{}
	for _, o := range objs {
		if o.Name < from {
			continue
		}
		if tl, pos, ok := segmentNumber(o.Name); ok {
			byTimeline[tl] = append(byTimeline[tl], pos)
		}
	}
	var timelines []uint64
	for tl := range byTimeline {
		timelines = append(timelines, tl)
	}
	sort.Slice(timelines, func(i, j int) bool { return timelines[i] < timelines[j] })
	var gaps []string
	per := uint64(1 << 32 / walSegmentSize)
	for _, tl := range timelines {
		pos := byTimeline[tl]
		sort.Slice(pos, func(i, j int) bool { return pos[i] < pos[j] })
		for i := 1; i < len(pos); i++ {
			for missing := pos[i-1] + 1; missing < pos[i]; missing++ {
				if len(gaps) == limit {
					return gaps
				}
				gaps = append(gaps, fmt.Sprintf("%08X%08X%08X", tl, missing/per, missing%per))
			}
		}
	}
	return gaps
}
