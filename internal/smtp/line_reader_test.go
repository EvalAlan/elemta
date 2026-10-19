package smtp

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestBoundedSMTPLineWithoutTerminator(t *testing.T) {
	for _, limit := range []int{512, 64 * 1024} {
		source := strings.NewReader(strings.Repeat("x", 8*1024*1024))
		reader := bufio.NewReader(source)
		line, err := readBoundedSMTPLine(reader, limit)
		if !errors.Is(err, errSMTPLineTooLong) || line != nil {
			t.Fatalf("limit %d: line length %d, error %v", limit, len(line), err)
		}
		if source.Len() == 0 {
			t.Fatalf("limit %d: consumed entire unbounded line", limit)
		}
	}
}

func TestBoundedSMTPLinePreservesFraming(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("DATA\r\nnext\r\n"))
	first, err := readBoundedSMTPLine(reader, 512)
	if err != nil || string(first) != "DATA\r\n" {
		t.Fatalf("first line %q, error %v", first, err)
	}
	second, err := readBoundedSMTPLine(reader, 512)
	if err != nil || string(second) != "next\r\n" {
		t.Fatalf("second line %q, error %v", second, err)
	}
}
