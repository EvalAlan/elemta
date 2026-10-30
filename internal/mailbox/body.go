package mailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// BodyStore never updates an existing message: keys are unique upload IDs.
// Metadata publication happens only after Put has completed durably.
type BodyStore interface {
	Identity() string
	Put(context.Context, string, []byte) error
	Get(context.Context, string, int64) ([]byte, error)
	Delete(context.Context, string) error
	Check(context.Context) error
	Close() error
}

var bodyKey = regexp.MustCompile(`^[a-f0-9]{32}$`)

type FileBodies struct {
	root     *os.Root
	identity string
}

func NewFileBodies(path string) (*FileBodies, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return &FileBodies{root: r, identity: "file:" + absolute}, nil
}
func (f *FileBodies) Identity() string { return f.identity }
func (f *FileBodies) Put(ctx context.Context, key string, data []byte) (err error) {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	file, err := f.root.OpenFile(key, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = f.root.Remove(key)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	dir, err := f.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Replace swaps a body by renaming over it, so a reader sees one version or
// the other and a crash leaves the original.
func (f *FileBodies) Replace(ctx context.Context, key string, data []byte) (err error) {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	tmp := key + ".new"
	file, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = f.root.Remove(tmp)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = f.root.Rename(tmp, key); err != nil {
		return err
	}
	dir, err := f.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (f *FileBodies) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	if !bodyKey.MatchString(key) {
		return nil, errors.New("invalid body key")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := f.root.Open(key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return readBounded(r, max)
}
func (f *FileBodies) Delete(ctx context.Context, key string) error {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := f.root.Remove(key)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (f *FileBodies) Check(ctx context.Context) error {
	return checkBodyCanary(ctx, f)
}
func (f *FileBodies) Close() error { return f.root.Close() }

type S3Bodies struct {
	client   *minio.Client
	bucket   string
	identity string
}

func NewS3Bodies(c BodyConfig) (*S3Bodies, error) {
	cl, err := minio.New(c.Endpoint, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv(c.AccessKeyEnv), os.Getenv(c.SecretKeyEnv), ""), Secure: c.Secure, Region: c.Region})
	if err != nil {
		return nil, err
	}
	return &S3Bodies{client: cl, bucket: c.Bucket, identity: "s3:" + c.Endpoint + "/" + c.Bucket}, nil
}
func (s *S3Bodies) Identity() string { return s.identity }
func (s *S3Bodies) Put(ctx context.Context, key string, data []byte) error {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	options := minio.PutObjectOptions{ContentType: "message/rfc822", DisableMultipart: true}
	options.SetMatchETagExcept("*")
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), options)
	return err
}

// Replace overwrites a body. S3 replaces an object whole, so a reader sees one
// version or the other. On a versioned bucket the old version stays until the
// bucket's lifecycle removes it.
func (s *S3Bodies) Replace(ctx context.Context, key string, data []byte) error {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true})
	return err
}
func (s *S3Bodies) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	if !bodyKey.MatchString(key) {
		return nil, errors.New("invalid body key")
	}
	r, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return readBounded(r, max)
}
func (s *S3Bodies) Delete(ctx context.Context, key string) error {
	if !bodyKey.MatchString(key) {
		return errors.New("invalid body key")
	}
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}
func (s *S3Bodies) Check(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("body bucket does not exist")
	}
	return checkBodyCanary(ctx, s)
}
func checkBodyCanary(ctx context.Context, store BodyStore) error {
	key := strings.ReplaceAll(uuid.NewString(), "-", "")
	want := []byte("mailbox-readiness")
	if err := store.Put(ctx, key, want); err != nil {
		return fmt.Errorf("body canary write: %w", err)
	}
	defer func() { _ = store.Delete(context.Background(), key) }()
	got, err := store.Get(ctx, key, int64(len(want)))
	if err != nil {
		return fmt.Errorf("body canary read: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("body canary contents differ")
	}
	if err := store.Delete(ctx, key); err != nil {
		return fmt.Errorf("body canary delete: %w", err)
	}
	return nil
}
func (s *S3Bodies) Close() error { return nil }
func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}
