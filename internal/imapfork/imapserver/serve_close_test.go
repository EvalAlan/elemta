package imapserver_test

import (
	"net"
	"sync"
	"testing"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
)

// Close running while a Serve is just starting must not race with it (run
// under -race). A server serving several listeners, as the mailbox service
// does for IMAP and IMAPS, met this when it shut down early.
func TestServeAndCloseDontRace(t *testing.T) {
	for range 5000 {
		srv := imapserver.New(&imapserver.Options{})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = srv.Serve(ln) }()
		go func() { defer wg.Done(); _ = srv.Close() }()
		wg.Wait()
		_ = ln.Close()
	}
}
