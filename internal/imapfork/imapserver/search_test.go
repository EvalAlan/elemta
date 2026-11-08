package imapserver

import (
	"bufio"
	"errors"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/imapfork/internal/imapwire"
	"github.com/emersion/go-imap/v2"
)

// A malformed search key is the client's mistake, so the reply must be BAD.
// Any error the dispatcher in conn.go can't classify becomes
// NO [SERVERBUG], which tells the client to retry against a broken server
// and puts a spurious "handling SEARCH" line in the server log.
func TestSearchSyntaxErrorsAreClientErrors(t *testing.T) {
	for _, input := range []string{
		"FOO",
		"1:*x",
		"KEYWORD",
		"SINCE 32-Foo-2026",
		"LARGER big",
		"NOT",
		"OR SEEN",
		"(SEEN",
	} {
		t.Run(input, func(t *testing.T) {
			dec := imapwire.NewDecoder(bufio.NewReader(strings.NewReader(input+"\r\n")), imapwire.ConnSideServer)
			var criteria imap.SearchCriteria
			err := readSearchKey(&criteria, dec)
			if err == nil {
				t.Fatalf("readSearchKey(%q) accepted it", input)
			}
			var imapErr *imap.Error
			var decErr *imapwire.DecoderExpectError
			switch {
			case errors.As(err, &imapErr):
				if imapErr.Type != imap.StatusResponseTypeBad {
					t.Fatalf("readSearchKey(%q) = %s %v, want BAD", input, imapErr.Type, imapErr)
				}
			case errors.As(err, &decErr):
			default:
				t.Fatalf("readSearchKey(%q) = %T %v, which the server reports as NO [SERVERBUG]", input, err, err)
			}
		})
	}
}
