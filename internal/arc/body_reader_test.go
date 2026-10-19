package arc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestStreamingBodyHash(t *testing.T) {
	bodies := []string{"", "\r\n\r\n", " \t\r\n", "\r\na\t b \t\r\n\r\n", "a\rb\r", "a\nb\n", strings.Repeat("long \t line  \r\n", 50000), strings.Repeat("x", 1024*1024)}
	for _, canon := range []Canonicalization{CanonSimple, CanonRelaxed} {
		for _, body := range bodies {
			want := sha256.Sum256([]byte(canonicalizeBody(body, canon)))
			for _, tinyChunks := range []bool{false, true} {
				var reader io.Reader = strings.NewReader(body)
				if tinyChunks {
					reader = iotest.OneByteReader(reader)
				}
				got, err := bodyHashReader(t.Context(), reader, canon)
				if err != nil || !bytes.Equal(got, want[:]) {
					t.Fatalf("canon=%s size=%d tinyChunks=%v: got=%x want=%x err=%v", canon, len(body), tinyChunks, got, want, err)
				}
			}
		}
	}
	for _, canon := range []Canonicalization{CanonSimple, CanonRelaxed} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := bodyHashReader(ctx, strings.NewReader("body"), canon); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled hash: %v", err)
		}
		if _, err := bodyHashReader(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF), canon); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read error was lost: %v", err)
		}
	}
}

func TestARCReaderLargeBodyAndTampering(t *testing.T) {
	p, _ := newSealer(t, "example.com", "arc", 1024)
	body := strings.Repeat("original body \t\r\n", 40000)
	message := strings.Replace(testMessage, "This is the body.\r\n", body, 1)
	sealed := mustSeal(t, p, message, "example.com; spf=pass")
	if result := p.VerifyReader(t.Context(), strings.NewReader(sealed)); result.Value != ChainPass {
		t.Fatalf("complete stream rejected: %+v", result)
	}
	tampered := []byte(sealed)
	tampered[len(tampered)-10] ^= 1
	if result := p.VerifyReader(t.Context(), bytes.NewReader(tampered)); result.Value != ChainFail {
		t.Fatalf("tampered tail accepted: %+v", result)
	}
	if result := p.VerifyReader(t.Context(), strings.NewReader(sealed[:256*1024])); result.Value != ChainFail {
		t.Fatalf("truncated stream accepted: %+v", result)
	}
	if result := p.VerifyReader(t.Context(), strings.NewReader(strings.Repeat("x", 256*1024+1))); result.Value != ChainFail {
		t.Fatalf("oversized header accepted: %+v", result)
	}
}
