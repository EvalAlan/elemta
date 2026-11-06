// Package offsite seals backups made by scripts/backup.sh and keeps them in
// an S3 bucket away from the server: encrypted with age, uploaded as they
// are sealed, and pruned to a set of daily and weekly copies.
//
// A backup holds the mailbox metadata, the directory with its password
// hashes and the key that decrypts the message bodies, and the bucket it
// goes to may sit beside those bodies, so it is sealed before it leaves the
// host and only the public half of the key is ever here. Sealing and
// uploading are one stream: no sealed copy is written to the server's disk,
// and nothing beyond this binary needs installing on the host.
package offsite

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config is where backups go. It comes from the environment
// (ConfigFromEnv), as the deployment keeps it in a root-only env file.
type Config struct {
	Endpoint  string // host[:port], no scheme
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	// Insecure talks plain HTTP, for a local test store only.
	Insecure bool
	// Prefix is prepended to object names, so the bucket can hold other
	// things without prune ever touching them.
	Prefix string
}

// ConfigFromEnv reads BACKUP_S3_ENDPOINT, BACKUP_S3_REGION,
// BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY_ID, BACKUP_S3_SECRET_ACCESS_KEY,
// and optionally BACKUP_S3_PREFIX (default "elemta/") and
// BACKUP_S3_INSECURE=true.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Endpoint:  strings.TrimSpace(os.Getenv("BACKUP_S3_ENDPOINT")),
		Region:    strings.TrimSpace(os.Getenv("BACKUP_S3_REGION")),
		Bucket:    strings.TrimSpace(os.Getenv("BACKUP_S3_BUCKET")),
		AccessKey: strings.TrimSpace(os.Getenv("BACKUP_S3_ACCESS_KEY_ID")),
		SecretKey: strings.TrimSpace(os.Getenv("BACKUP_S3_SECRET_ACCESS_KEY")),
		Insecure:  os.Getenv("BACKUP_S3_INSECURE") == "true",
		Prefix:    "elemta/",
	}
	if p, ok := os.LookupEnv("BACKUP_S3_PREFIX"); ok {
		c.Prefix = p
	}
	c.Endpoint = strings.TrimPrefix(strings.TrimPrefix(c.Endpoint, "https://"), "http://")
	var missing []string
	for name, v := range map[string]string{"BACKUP_S3_ENDPOINT": c.Endpoint, "BACKUP_S3_BUCKET": c.Bucket,
		"BACKUP_S3_ACCESS_KEY_ID": c.AccessKey, "BACKUP_S3_SECRET_ACCESS_KEY": c.SecretKey} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return c, fmt.Errorf("offsite: set %s", strings.Join(missing, ", "))
	}
	return c, nil
}

// Seal writes dir, a backup directory, to w as a gzipped tar encrypted to
// the age recipient. The tar holds the directory under its own name, so
// opening it (age -d -i key | tar -xz) gives the same directory back.
// Sockets and other special files are left out; a backup has none, but a
// tar of a live volume can.
//
// The walk and every read go through an os.Root for dir, so nothing outside
// the backup can end up in it: a symlink in the directory, or one swapped in
// while it is being read, can't lead the walk to /etc/shadow or another
// account's files. The process runs as root to read the backup, which is
// what makes that worth guarding.
func Seal(w io.Writer, dir, recipient string) error {
	r, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
	if err != nil {
		return fmt.Errorf("offsite: age recipient: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("offsite: open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Stat("complete"); err != nil {
		return fmt.Errorf("offsite: %s is not a complete backup", dir)
	}
	enc, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(enc)
	tw := tar.NewWriter(zw)
	base := filepath.Base(filepath.Clean(dir))
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = path.Join(base, rel)
		if info.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return errors.Join(err, f.Close())
	})
	if err != nil {
		return err
	}
	return errors.Join(tw.Close(), zw.Close(), enc.Close())
}

// Client talks to the backup bucket.
type Client struct {
	cfg Config
	mc  *minio.Client
}

// New connects to the bucket in c.
func New(c Config) (*Client, error) {
	mc, err := minio.New(c.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKey, c.SecretKey, ""),
		Secure: !c.Insecure,
		Region: c.Region,
	})
	if err != nil {
		return nil, err
	}
	return &Client{cfg: c, mc: mc}, nil
}

// Object is one backup in the bucket.
type Object struct {
	Key  string
	Size int64
	// Taken is when the backup was made, read from its name.
	Taken time.Time
}

// namePattern is how backup-offsite.sh names a sealed backup. Only objects
// named so are listed, and so only they can ever be pruned.
var namePattern = regexp.MustCompile(`^elemta-(\d{8}T\d{6}Z)\.tar\.gz\.age$`)

// ObjectName is the bucket object name for a backup directory's name, which
// must be elemta-<UTC time as 20060102T150405Z>.
func (c *Client) ObjectName(backup string) (string, error) {
	name := backup + ".tar.gz.age"
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("offsite: backup %q isn't named elemta-<20060102T150405Z>", backup)
	}
	return c.cfg.Prefix + name, nil
}

// SealAndUpload seals dir and uploads it as it is sealed, then checks the
// object arrived whole. It returns the object's name and size.
func (c *Client) SealAndUpload(ctx context.Context, dir, recipient string) (string, int64, error) {
	key, err := c.ObjectName(filepath.Base(filepath.Clean(dir)))
	if err != nil {
		return "", 0, err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(Seal(pw, dir, recipient)) }()
	// Size unknown, so minio-go uploads in parts; 16 MiB parts keep memory
	// modest and allow backups up to the part limit times 16 MiB.
	info, err := c.mc.PutObject(ctx, c.cfg.Bucket, key, pr, -1, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		PartSize:    16 << 20,
	})
	_ = pr.CloseWithError(err)
	if err != nil {
		return "", 0, fmt.Errorf("offsite: upload %s: %w", key, err)
	}
	st, err := c.mc.StatObject(ctx, c.cfg.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("offsite: check %s: %w", key, err)
	}
	if st.Size != info.Size {
		return "", 0, fmt.Errorf("offsite: %s holds %d bytes, %d were sent", key, st.Size, info.Size)
	}
	return key, st.Size, nil
}

// List returns the backups in the bucket, newest first.
func (c *Client) List(ctx context.Context) ([]Object, error) {
	var out []Object
	for o := range c.mc.ListObjects(ctx, c.cfg.Bucket, minio.ListObjectsOptions{Prefix: c.cfg.Prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		m := namePattern.FindStringSubmatch(strings.TrimPrefix(o.Key, c.cfg.Prefix))
		if m == nil {
			continue
		}
		t, err := time.Parse("20060102T150405Z", m[1])
		if err != nil {
			continue
		}
		out = append(out, Object{Key: o.Key, Size: o.Size, Taken: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Taken.After(out[j].Taken) })
	return out, nil
}

// Delete removes one backup. In a versioned bucket it stays recoverable
// until the bucket's lifecycle expires the old version.
func (c *Client) Delete(ctx context.Context, key string) error {
	return c.mc.RemoveObject(ctx, c.cfg.Bucket, key, minio.RemoveObjectOptions{})
}

// Prune decides which backups to keep: the newest of each of the last daily
// days that have one, and the newest of each of the last weekly ISO weeks
// that have one. The newest backup of all is always kept, so pruning can
// never leave the bucket empty. objs may be in any order; both results are
// newest first.
func Prune(objs []Object, daily, weekly int) (keep, drop []Object) {
	sorted := append([]Object(nil), objs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Taken.After(sorted[j].Taken) })
	kept := map[string]bool{}
	pick := func(n int, period func(time.Time) string) {
		seen := map[string]bool{}
		for _, o := range sorted {
			p := period(o.Taken)
			if seen[p] {
				continue
			}
			if len(seen) == n {
				return
			}
			seen[p] = true
			kept[o.Key] = true
		}
	}
	pick(daily, func(t time.Time) string { return t.UTC().Format("2006-01-02") })
	pick(weekly, func(t time.Time) string { y, w := t.UTC().ISOWeek(); return fmt.Sprintf("%d-%02d", y, w) })
	if len(sorted) > 0 {
		kept[sorted[0].Key] = true
	}
	for _, o := range sorted {
		if kept[o.Key] {
			keep = append(keep, o)
		} else {
			drop = append(drop, o)
		}
	}
	return keep, drop
}
