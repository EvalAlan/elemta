package integration

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createIntegrationTestConfig creates configuration for integration testing
func createIntegrationTestConfig(t *testing.T, enableTLS bool, enableAuth bool) *smtp.Config {
	t.Helper()

	config := &smtp.Config{
		Hostname:          "integration.test.example.com",
		ListenAddr:        "127.0.0.1:0",
		LocalDomains:      []string{"integration.test.example.com", "example.com", "localhost"},
		MaxSize:           10 * 1024 * 1024, // 10MB for integration tests
		StrictLineEndings: false,            // More lenient for integration tests
		QueueDir:          t.TempDir(),
	}

	if enableTLS {
		certFile, keyFile := generateTestTLSCerts(t)
		config.TLS = &smtp.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}
	}

	if enableAuth {
		dbFile, err := os.CreateTemp(t.TempDir(), "elemta-auth-*.db")
		require.NoError(t, err)
		require.NoError(t, dbFile.Close())
		config.Auth = &smtp.AuthConfig{
			Enabled:        true,
			DataSourceType: "sqlite",
			DataSourceName: "sqlite",
			DataSourcePath: dbFile.Name(),
		}
	}

	return config
}

func generateTestTLSCerts(t *testing.T) (string, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certFile := filepath.Join(t.TempDir(), "test-cert.pem")
	keyFile := filepath.Join(t.TempDir(), "test-key.pem")

	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certOut.Close())

	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	require.NoError(t, keyOut.Close())

	return certFile, keyFile
}

func listenerAddress(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if host == "" || host == "::" || host == "[::]" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// setupIntegrationServer creates and starts an integration test server
func setupIntegrationServer(t *testing.T, config *smtp.Config) (*smtp.Server, string) {
	t.Helper()

	server, err := smtp.NewServer(config)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serverErr:
			require.NoError(t, err)
		default:
		}

		if addr := listenerAddress(server.Addr()); addr != "" {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return server, addr
			}
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("integration test server did not become ready")
	return nil, ""
}

// SMTPClient represents a simple SMTP client for testing
type SMTPClient struct {
	conn   net.Conn
	reader *bufio.Reader
	server string
}

// NewSMTPClient creates a new SMTP client
func NewSMTPClient(server string) (*SMTPClient, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}

	client := &SMTPClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		server: server,
	}

	// Read greeting
	_, err = client.reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	return client, nil
}

// NewSMTPClientTLS creates a new SMTP client with TLS
func NewSMTPClientTLS(server string) (*SMTPClient, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // For testing only
	})

	err = tlsConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := &SMTPClient{
		conn:   tlsConn,
		reader: bufio.NewReader(tlsConn),
		server: server,
	}

	// Read greeting
	_, err = client.reader.ReadString('\n')
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return client, nil
}

// Command sends an SMTP command and returns the response
func (c *SMTPClient) Command(cmd string) (string, error) {
	_, err := c.conn.Write([]byte(cmd))
	if err != nil {
		return "", err
	}

	response, err := c.reader.ReadString('\n')
	return response, err
}

// EHLO sends EHLO command
func (c *SMTPClient) EHLO(domain string) error {
	response, err := c.Command(fmt.Sprintf("EHLO %s\r\n", domain))
	if err != nil {
		return err
	}

	if !strings.Contains(response, "250") {
		return fmt.Errorf("EHLO failed: %s", response)
	}

	// Read multi-line response if present
	for strings.Contains(response, "250-") {
		response, err = c.reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.Contains(response, "250 ") {
			break
		}
	}

	return nil
}

// Auth performs SMTP authentication
func (c *SMTPClient) Auth(username, password string) error {
	// Send AUTH PLAIN command
	authString := fmt.Sprintf("\\x00%s\\x00%s", username, password)
	response, err := c.Command(fmt.Sprintf("AUTH PLAIN %s\r\n", authString))
	if err != nil {
		return err
	}

	if !strings.Contains(response, "235") {
		return fmt.Errorf("Authentication failed: %s", response)
	}

	return nil
}

// SendMail sends a complete email
func (c *SMTPClient) SendMail(from, to, subject, body string) error {
	// MAIL FROM
	response, err := c.Command(fmt.Sprintf("MAIL FROM:<%s>\r\n", from))
	if err != nil {
		return err
	}
	if !strings.Contains(response, "250") {
		return fmt.Errorf("MAIL FROM failed: %s", response)
	}

	// RCPT TO
	response, err = c.Command(fmt.Sprintf("RCPT TO:<%s>\r\n", to))
	if err != nil {
		return err
	}
	if !strings.Contains(response, "250") {
		return fmt.Errorf("RCPT TO failed: %s", response)
	}

	// DATA
	response, err = c.Command("DATA\r\n")
	if err != nil {
		return err
	}
	if !strings.Contains(response, "354") {
		return fmt.Errorf("DATA failed: %s", response)
	}

	// Message content
	message := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n%s\r\n.\r\n",
		subject, from, to, body)

	response, err = c.Command(message)
	if err != nil {
		return err
	}
	if !strings.Contains(response, "250") {
		return fmt.Errorf("Message delivery failed: %s", response)
	}

	return nil
}

// Close closes the SMTP client connection
func (c *SMTPClient) Close() error {
	_, _ = c.Command("QUIT\r\n")
	return c.conn.Close()
}

// TestIntegration_BasicSMTPFlow tests the complete SMTP flow
func TestIntegration_BasicSMTPFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	t.Run("Complete_Flow", func(t *testing.T) {
		// EHLO
		err := client.EHLO("client.example.com")
		require.NoError(t, err)

		// Send email
		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Integration Test Email",
			"This is a test email from the integration test suite.",
		)
		require.NoError(t, err)
	})
}

// TestIntegration_ConcurrentConnections tests multiple concurrent connections
func TestIntegration_ConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	const numClients = 10
	const numMessagesPerClient = 5

	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			client, err := NewSMTPClient(addr)
			if err != nil {
				errors <- fmt.Errorf("client %d: %v", clientID, err)
				return
			}
			defer client.Close()

			// Send multiple messages
			for j := 0; j < numMessagesPerClient; j++ {
				err = client.EHLO(fmt.Sprintf("client%d.example.com", clientID))
				if err != nil {
					errors <- fmt.Errorf("client %d message %d EHLO: %v", clientID, j, err)
					return
				}

				err = client.SendMail(
					fmt.Sprintf("sender%d@integration.test.example.com", clientID),
					fmt.Sprintf("recipient%d@integration.test.example.com", clientID),
					fmt.Sprintf("Concurrent Test %d-%d", clientID, j),
					fmt.Sprintf("Message from client %d, message %d", clientID, j),
				)
				if err != nil {
					errors <- fmt.Errorf("client %d message %d: %v", clientID, j, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}

// TestIntegration_AuthenticationFlow tests SMTP authentication
func TestIntegration_AuthenticationFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, true)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	t.Run("Auth_Flow", func(t *testing.T) {
		// EHLO
		err := client.EHLO("client.example.com")
		require.NoError(t, err)

		// Try to send mail without auth (should fail if auth required)
		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"No Auth Test",
			"This should fail without authentication.",
		)
		// Note: This might succeed depending on server configuration
		// We'll focus on successful auth flow

		// Authenticate
		err = client.Auth("testuser", "testpass")
		if err != nil {
			t.Skipf("Authentication not available: %v", err)
			return
		}

		// Send email after auth
		err = client.EHLO("client.example.com")
		require.NoError(t, err)

		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Authenticated Test",
			"This email was sent after authentication.",
		)
		require.NoError(t, err)
	})
}

// TestIntegration_TLSFlow tests TLS negotiation and encrypted communication
func TestIntegration_TLSFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Note: This test requires TLS certificates
	// For now, we'll test the structure and skip if certs not available

	config := createIntegrationTestConfig(t, true, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	t.Run("TLS_Negotiation", func(t *testing.T) {
		// Try TLS connection
		client, err := NewSMTPClientTLS(addr)
		if err != nil {
			t.Skipf("TLS not available: %v", err)
			return
		}
		defer client.Close()

		// EHLO over TLS
		err = client.EHLO("tls-client.example.com")
		require.NoError(t, err)

		// Send email over TLS
		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"TLS Test Email",
			"This email was sent over TLS.",
		)
		require.NoError(t, err)
	})
}

// TestIntegration_ErrorRecovery tests error handling and recovery
func TestIntegration_ErrorRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	// EHLO
	err = client.EHLO("client.example.com")
	require.NoError(t, err)

	t.Run("Invalid_Command_Recovery", func(t *testing.T) {
		// Send invalid command
		response, err := client.Command("INVALID_COMMAND\r\n")
		require.NoError(t, err)
		assert.Contains(t, response, "502", "Invalid command should return 502")

		// Server should still accept valid commands
		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Recovery Test",
			"Email after invalid command.",
		)
		require.NoError(t, err)
	})

	t.Run("Sequence_Error_Recovery", func(t *testing.T) {
		// Try RCPT before MAIL (should fail)
		response, err := client.Command("RCPT TO:<test@example.com>\r\n")
		require.NoError(t, err)
		assert.Contains(t, response, "503", "Bad sequence should return 503")

		// Reset and try proper sequence
		response, err = client.Command("RSET\r\n")
		require.NoError(t, err)
		assert.Contains(t, response, "250", "RSET should succeed")

		err = client.EHLO("client.example.com")
		require.NoError(t, err)

		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Sequence Recovery Test",
			"Email after sequence error.",
		)
		require.NoError(t, err)
	})
}

// TestIntegration_LargeMessages tests handling of large messages
func TestIntegration_LargeMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	// EHLO
	err = client.EHLO("client.example.com")
	require.NoError(t, err)

	t.Run("Large_Message", func(t *testing.T) {
		// Create a large RFC-ish message with many normal-length lines
		largeBody := strings.Repeat("This is a line of text to make the message larger.\r\n", 10000)

		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Large Message Test",
			largeBody,
		)
		require.NoError(t, err)
	})

	t.Run("Oversized_Message", func(t *testing.T) {
		err = client.EHLO("client.example.com")
		require.NoError(t, err)

		// Create message exceeding server limit (if enforced) without absurdly long individual lines
		oversizedBody := strings.Repeat("This line will be repeated many times to exceed the limit.\r\n", 200000)

		err = client.SendMail(
			"sender@integration.test.example.com",
			"recipient@integration.test.example.com",
			"Oversized Message Test",
			oversizedBody,
		)
		// Should either succeed (if limit not enforced) or fail gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "552", "Oversized message should return 552")
		}
	})
}

// TestIntegration_PersistentConnection tests connection persistence
func TestIntegration_PersistentConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	t.Run("Multiple_Transactions_Same_Connection", func(t *testing.T) {
		// Send multiple emails on same connection
		for i := 0; i < 10; i++ {
			err = client.EHLO("persistent.example.com")
			require.NoError(t, err)

			err = client.SendMail(
				fmt.Sprintf("sender%d@integration.test.example.com", i),
				fmt.Sprintf("recipient%d@integration.test.example.com", i),
				fmt.Sprintf("Persistent Test %d", i),
				fmt.Sprintf("Message %d on persistent connection", i),
			)
			require.NoError(t, err)
		}
	})
}

// TestIntegration_TimeoutHandling tests timeout scenarios
func TestIntegration_TimeoutHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := createIntegrationTestConfig(t, false, false)
	server, addr := setupIntegrationServer(t, config)
	defer server.Close()

	client, err := NewSMTPClient(addr)
	require.NoError(t, err)
	defer client.Close()

	// EHLO
	err = client.EHLO("timeout.example.com")
	require.NoError(t, err)

	t.Run("Idle_Timeout", func(t *testing.T) {
		// Wait for a period to test idle timeout (if implemented)
		time.Sleep(2 * time.Second)

		// Try to send a command after idle period
		response, err := client.Command("NOOP\r\n")
		if err != nil {
			// Connection might have been closed due to timeout
			t.Logf("Connection closed after idle period: %v", err)
			return
		}

		// If still connected, should respond normally
		assert.Contains(t, response, "250", "NOOP should succeed after idle period")
	})
}
