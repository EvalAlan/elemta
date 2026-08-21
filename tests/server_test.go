package tests

import (
	"bufio"
	"net"
	"testing"

	"github.com/EvalAlan/elemta/internal/smtp"
	"github.com/stretchr/testify/require"
)

// Shared setup for the socket-level tests in this package.
//
// These tests used to bind a fixed port 2525, drop the error from Start() into
// a channel nobody read, and then dial localhost:2525. On a machine running the
// development stack — which listens on 2525 — the bind failed silently and
// every assertion was made against whatever MTA happened to be there. The suite
// passed while testing something else entirely, and would have gone on passing
// with the server under test completely broken.
//
// So: an ephemeral port, loopback only, and a failure to start is a failure to
// test.

// startTestServer starts a server on an ephemeral loopback port and returns a
// connection to it with the greeting already read.
//
// The port is chosen by the kernel, so tests in this package can run alongside
// a running Elemta, alongside each other, and in parallel without colliding.
// Binding loopback rather than every interface keeps a test server off the
// network it is running on.
func startTestServer(t *testing.T, config *smtp.Config) (*smtp.Server, net.Conn, *bufio.Reader) {
	t.Helper()

	server, err := smtp.NewServer(config)
	require.NoError(t, err, "creating the test server")
	t.Cleanup(func() { _ = server.Close() })

	// Start is not blocking: it binds, hands the accept loop to an errgroup and
	// returns. Calling it here rather than in a goroutine means a bind failure
	// is this test's failure, reported at the line that caused it, and that the
	// listener is already in place when Start returns — no sleeping, no polling
	// for an address, nothing to flake.
	require.NoError(t, server.Start(), "starting the test server")

	addr := server.Addr()
	require.NotNil(t, addr, "the server reported no address after a successful start")

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err, "dialling the test server at %s", addr)
	t.Cleanup(func() { _ = conn.Close() })

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err, "reading the greeting")
	require.Contains(t, greeting, "220", "expected a 220 greeting, got %q", greeting)

	return server, conn, reader
}

// TestTestServerUsesAnEphemeralPort is a guard on the fix itself. Without it
// the fixed port could come back in a later edit and the suite would go quiet
// again rather than failing.
func TestTestServerUsesAnEphemeralPort(t *testing.T) {
	config := createTestConfig(t)
	server, _, _ := startTestServer(t, config)

	addr, ok := server.Addr().(*net.TCPAddr)
	require.True(t, ok, "expected a TCP address, got %T", server.Addr())

	require.NotZero(t, addr.Port, "the server should have been assigned a real port")
	require.NotEqual(t, 2525, addr.Port,
		"the test server must not bind the port the development stack uses; "+
			"a fixed port makes the suite test whichever MTA answers first")
	require.True(t, addr.IP.IsLoopback(),
		"the test server should listen on loopback only, got %s", addr.IP)

	// Two servers at once is the case a fixed port makes impossible, and it is
	// what lets these tests run in parallel.
	second, _, _ := startTestServer(t, createTestConfig(t))
	require.NotEqual(t, server.Addr().String(), second.Addr().String(),
		"two test servers must not be handed the same address")
}
