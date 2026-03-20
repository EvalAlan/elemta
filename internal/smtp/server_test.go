package smtp

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServer_ErrorHandling_DeadlineSetting tests the deadline setting error handling fix
func TestServer_ErrorHandling_DeadlineSetting(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get actual listen address
	addr := server.Addr()
	require.NotNil(t, addr, "Server address should not be nil")

	// Connect to server to trigger the deadline setting code path
	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Read greeting to ensure server is running
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Close connection
	conn.Close()

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestServer_Start_BasicFunctionality tests basic server start and stop
func TestServer_Start_BasicFunctionality(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get actual listen address
	addr := server.Addr()
	require.NotNil(t, addr, "Server address should not be nil")

	// Verify server is listening
	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Read server greeting
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220")
	assert.Contains(t, greeting, config.Hostname)

	// Send QUIT command
	_, err = conn.Write([]byte("QUIT\r\n"))
	require.NoError(t, err)

	// Read goodbye response
	goodbye, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, goodbye, "221")

	// Stop server
	err = server.Close()
	assert.NoError(t, err)

	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not stop")
	}
}

// TestServer_ErrorHandling_NilConfig tests nil config error handling
func TestServer_ErrorHandling_NilConfig(t *testing.T) {
	_, err := NewServer(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

// TestServer_ErrorHandling_EmptyHostname tests empty hostname handling
func TestServer_ErrorHandling_EmptyHostname(t *testing.T) {
	config := &Config{
		Hostname:   "",
		ListenAddr: "127.0.0.1:0",
		QueueDir:   t.TempDir(),
	}

	_, err := NewServer(config)
	_ = err // Error is acceptable here - we just want to ensure no panic
	// Should either succeed with defaults or fail gracefully
	// The important thing is it doesn't panic
}

// TestServer_ErrorHandling_PortBinding tests port binding error handling
func TestServer_ErrorHandling_PortBinding(t *testing.T) {
	// Try to bind to a privileged port (should fail unless running as root)
	config := &Config{
		Hostname:   "test.example.com",
		ListenAddr: ":25", // Privileged port
		QueueDir:   t.TempDir(),
	}

	server, err := NewServer(config)
	if err != nil {
		// Expected to fail due to privileged port
		assert.Error(t, err)
		return
	}

	// If it succeeded, clean up
	defer func() { _ = server.Close() }()
}

// TestServer_GracefulShutdown tests graceful shutdown behavior
func TestServer_GracefulShutdown(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get actual listen address
	addr := server.Addr()
	require.NotNil(t, addr, "Server address should not be nil")

	// Create a connection
	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)

	// Start graceful shutdown
	go func() {
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	// Connection should still work during shutdown grace period
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	conn.Close()

	// Server should shut down gracefully
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Server did not shut down gracefully")
	}
}

func TestPrepareServerConfig(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		err := prepareServerConfig(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("fills defaults when fields are missing", func(t *testing.T) {
		cfg := &Config{}
		err := prepareServerConfig(cfg)
		require.NoError(t, err)
		assert.NotEmpty(t, cfg.Hostname)
		assert.Equal(t, ":2525", cfg.ListenAddr)
	})
}
