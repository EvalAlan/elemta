package arc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"io"
)

// bodyHashReader keeps pending whitespace and empty lines as counters instead
// of retaining them: only a later nonempty line decides whether they are signed.
func bodyHashReader(ctx context.Context, reader io.Reader, canon Canonicalization) ([]byte, error) {
	hash := sha256.New()
	out := bufio.NewWriter(hash)
	var emptyLines int64
	var lineHasContent, wroteContent, pendingWSP, pendingCR bool
	writeContent := func(c byte) {
		if canon == CanonRelaxed && (c == ' ' || c == '\t') {
			pendingWSP = true
			return
		}
		if !lineHasContent {
			for emptyLines > 0 {
				_, _ = out.WriteString("\r\n")
				emptyLines--
			}
			lineHasContent = true
		}
		if pendingWSP {
			_ = out.WriteByte(' ')
			pendingWSP = false
		}
		_ = out.WriteByte(c)
		wroteContent = true
	}
	endLine := func() {
		if lineHasContent {
			_, _ = out.WriteString("\r\n")
		} else {
			emptyLines++
		}
		lineHasContent = false
		pendingWSP = false
	}
	buf := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := reader.Read(buf)
		for _, c := range buf[:n] {
			if pendingCR {
				pendingCR = false
				if c == '\n' {
					endLine()
					continue
				}
				writeContent('\r')
			}
			switch c {
			case '\r':
				pendingCR = true
			case '\n':
				endLine()
			default:
				writeContent(c)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if pendingCR {
		writeContent('\r')
	}
	if lineHasContent || !wroteContent && canon == CanonSimple {
		_, _ = out.WriteString("\r\n")
	}
	if err := out.Flush(); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}
