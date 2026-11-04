package mailbox

// Compressing message bodies. Mail is mostly text, and base64 attachments keep
// a quarter of their size to give back, so this saves real storage.
//
// It sits above encryption, because ciphertext doesn't compress: the store sees
// plaintext go in here, then through encryptedBodies if there is one. Quotas and
// the recorded size and checksum all describe the message itself, so none of
// them change, and a backup holds bodies as stored.
//
// Reading doesn't depend on the setting. A body is either framed or it isn't,
// and the frame says which, so turning compression off leaves everything
// readable and only stops new mail being compressed. For the same reason old
// mail and new can sit side by side, and `mailbox compress-bodies` is optional.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// CompressionZstd is the [bodies] compression setting that turns this on.
const CompressionZstd = "zstd"

// bodyFrame starts a compressed body. A NUL can't begin a real mail header, but
// anyone can APPEND any bytes they like, so packBody frames a body that starts
// this way whatever else it would have done, and it can't be misread.
var bodyFrame = []byte("\x00ELMZ1\x00")

const (
	// bodyMinCompress is too small to be worth it: the frame and zstd's own
	// header eat the saving.
	bodyMinCompress = 256
	// bodyDecoderMemory bounds the window a frame may ask for.
	bodyDecoderMemory = 256 << 20
)

// bodyEncoder is shared: EncodeAll is safe for concurrent use, and building one
// allocates more than compressing a typical message does. Two at once, because
// the service runs with half a gigabyte, and deliveries are bounded anyway.
var bodyEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
	return zstd.NewWriter(nil, zstd.WithEncoderConcurrency(2), zstd.WithEncoderLevel(zstd.SpeedDefault))
})

// frameBody compresses plain into a frame.
func frameBody(plain []byte) ([]byte, error) {
	encoder, err := bodyEncoder()
	if err != nil {
		return nil, err
	}
	return encoder.EncodeAll(plain, bytes.Clone(bodyFrame)), nil
}

// packBody returns what to store for plain. Compressing has to save something
// worthwhile, or the body is left as it is: a photo or a zip gains nothing, and
// each read would still pay to unpack it.
func packBody(plain []byte, compress bool) ([]byte, error) {
	escape := bytes.HasPrefix(plain, bodyFrame)
	if !escape && (!compress || len(plain) < bodyMinCompress) {
		return plain, nil
	}
	framed, err := frameBody(plain)
	if err != nil {
		return nil, err
	}
	if !escape && len(framed) >= len(plain)-len(plain)/20 {
		return plain, nil
	}
	return framed, nil
}

// unpackBody returns a stored body's plaintext, reading no more than max.
func unpackBody(stored []byte, max int64) ([]byte, error) {
	if !bytes.HasPrefix(stored, bodyFrame) {
		if int64(len(stored)) > max {
			return nil, ErrTooLarge
		}
		return stored, nil
	}
	reader, err := zstd.NewReader(bytes.NewReader(stored[len(bodyFrame):]), zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(bodyDecoderMemory))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return readBounded(reader, max)
}

// bodyStoredLimit is the most a body of size bytes can take in the store. Only
// the escape case can make a body bigger, by zstd's worst case and the frame.
func bodyStoredLimit(size int64) int64 { return size + size>>7 + 128 }

// compressedBodies wraps the store, encrypted or not. It's always there, so
// that compressed mail stays readable with the setting off.
type compressedBodies struct {
	BodyStore
	compress bool
}

func (c *compressedBodies) Put(ctx context.Context, key string, plain []byte) error {
	stored, err := packBody(plain, c.compress)
	if err != nil {
		return err
	}
	return c.BodyStore.Put(ctx, key, stored)
}

func (c *compressedBodies) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	stored, err := c.BodyStore.Get(ctx, key, bodyStoredLimit(max))
	if err != nil {
		return nil, err
	}
	return unpackBody(stored, max)
}

// bodyLayers takes a store apart: its encryption, if any, and the store
// underneath, which holds bodies exactly as they sit on disk or in the bucket.
func bodyLayers(s BodyStore) (*encryptedBodies, BodyStore) {
	if c, ok := s.(*compressedBodies); ok {
		s = c.BodyStore
	}
	if e, ok := s.(*encryptedBodies); ok {
		return e, e.BodyStore
	}
	return nil, s
}

// CompressReport is the result of CompressBodies.
type CompressReport struct {
	Checked, Compressed int
	// Before and After are the sizes of the bodies compressed.
	Before, After int64
	// Failed lists bodies left as they were, with the reason.
	Failed []string
}

// CompressBodies compresses bodies stored before compression was turned on. It
// is safe to stop and run again, and safe while the service runs, because a
// reader takes either form and each object is replaced whole. Every body is
// checked against its recorded checksum first and read back after.
func (e *Engine) CompressBodies(ctx context.Context, progress func(done int)) (CompressReport, error) {
	var r CompressReport
	if c, ok := e.Bodies.(*compressedBodies); !ok || !c.compress {
		return r, errors.New("[bodies] compression is not on")
	}
	enc, raw := bodyLayers(e.Bodies)
	replace, ok := raw.(BodyReplacer)
	if !ok {
		return r, errors.New("this body store can't replace bodies")
	}
	todo, err := e.readyBodies(ctx)
	if err != nil {
		return r, err
	}
	for _, m := range todo {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		r.Checked++
		if progress != nil && r.Checked%1000 == 0 {
			progress(r.Checked)
		}
		if err := e.compressBody(ctx, enc, raw, replace, m, &r); err != nil {
			r.Failed = append(r.Failed, fmt.Sprintf("%s: %v", m.Body, err))
		}
	}
	return r, nil
}

func (e *Engine) compressBody(ctx context.Context, enc *encryptedBodies, raw BodyStore, replace BodyReplacer, m Message, r *CompressReport) error {
	stored, err := raw.Get(ctx, m.Body, bodyStoredLimit(m.Size)+bodyOverhead)
	if err != nil {
		return err
	}
	opened := stored
	if enc != nil {
		if opened, err = enc.open(m.Body, stored); err != nil {
			return err
		}
	}
	plain, err := unpackBody(opened, m.Size)
	if err != nil {
		return err
	}
	if int64(len(plain)) != m.Size || checksumOf(plain) != m.Checksum {
		return errors.New("doesn't match its recorded checksum")
	}
	if bytes.HasPrefix(opened, bodyFrame) {
		return nil
	}
	packed, err := packBody(plain, true)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(packed, bodyFrame) {
		return nil
	}
	next := packed
	if enc != nil {
		if next, err = enc.seal(m.Body, packed); err != nil {
			return err
		}
	}
	// As in encryptBody: a replace would put a retired body back.
	var state string
	if err := e.DB.QueryRowContext(ctx, `SELECT state FROM mailbox_bodies WHERE key=$1`, m.Body).Scan(&state); err != nil {
		return err
	}
	if state != "ready" {
		return nil
	}
	if err := replace.Replace(ctx, m.Body, next); err != nil {
		return err
	}
	check, err := e.Bodies.Get(ctx, m.Body, m.Size)
	if err != nil {
		return fmt.Errorf("reading it back: %w", err)
	}
	if checksumOf(check) != m.Checksum {
		return errors.New("reading it back gave different contents")
	}
	r.Compressed++
	r.Before += int64(len(stored))
	r.After += int64(len(next))
	return nil
}
