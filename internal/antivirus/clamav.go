// Package antivirus provides virus scanning functionality for Elemta
package antivirus

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ClamAVConfig represents the configuration for a ClamAV scanner
type ClamAVConfig struct {
	Address string                 // Address of the scanner (host:port)
	Options map[string]interface{} // Additional scanner options
}

const (
	// defaultClamAVAddress is clamd's usual TCP endpoint.
	defaultClamAVAddress = "localhost:3310"
	// defaultClamAVTimeout bounds a whole scan, connect through verdict.
	defaultClamAVTimeout = 30 * time.Second
	// clamavChunkSize is how much is sent per INSTREAM chunk. clamd's own
	// StreamMaxLength is far larger; this only governs memory held per scan.
	clamavChunkSize = 64 * 1024
)

// ClamAV scans messages with clamd over its INSTREAM protocol.
//
// Nothing is held open between scans. clamd handles one command per
// connection for INSTREAM, so each scan dials, streams, reads the verdict and
// closes. Connect only checks reachability.
type ClamAV struct {
	config    Config
	address   string
	timeout   time.Duration
	scanLimit int64

	mu        sync.RWMutex
	reachable bool
}

// NewClamAV creates a new ClamAV scanner
func NewClamAV(config Config) *ClamAV {
	address := config.Address
	if address == "" {
		address = defaultClamAVAddress
	}

	return &ClamAV{
		config:    config,
		address:   address,
		timeout:   durationOption(config.Options, "timeout", defaultClamAVTimeout),
		scanLimit: int64Option(config.Options, "scan_limit", 0),
	}
}

// Connect checks that clamd is reachable and answering.
//
// It sends a real PING rather than assuming: this used to set a flag and
// return nil, so "connected" meant nothing had been tried.
func (c *ClamAV) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		c.setReachable(false)
		return fmt.Errorf("clamav: connect to %s: %w", c.address, err)
	}
	c.setReachable(true)
	return nil
}

// IsConnected reports whether clamd answered the last time it was contacted.
func (c *ClamAV) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reachable
}

func (c *ClamAV) setReachable(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reachable = v
}

// Close releases the scanner. Connections are per-scan, so there is nothing
// long-lived to tear down.
func (c *ClamAV) Close() error {
	c.setReachable(false)
	return nil
}

// Name returns the name of the scanner
func (c *ClamAV) Name() string {
	if c.config.Name != "" {
		return c.config.Name
	}
	return "clamav"
}

// Type returns the type of the scanner
func (c *ClamAV) Type() string { return "clamav" }

// Ping asks clamd to identify itself.
func (c *ClamAV) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("send PING: %w", err)
	}

	reply, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read PING reply: %w", err)
	}
	if !strings.Contains(reply, "PONG") {
		return fmt.Errorf("unexpected PING reply %q", strings.TrimRight(reply, "\x00"))
	}
	return nil
}

// ScanBytes scans a byte slice for viruses
func (c *ClamAV) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	return c.ScanReader(ctx, strings.NewReader(string(data)))
}

// ScanFile scans a file for viruses.
//
// The file is streamed to clamd; it is never read into memory. This is the
// path a spooled message takes, and it is why a large message can be scanned
// without its size bounding what the server can accept.
func (c *ClamAV) ScanFile(ctx context.Context, path string) (*ScanResult, error) {
	f, err := os.Open(path) // #nosec G304 -- caller supplies a queue-owned path
	if err != nil {
		return nil, fmt.Errorf("clamav: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return c.ScanReader(ctx, f)
}

// ScanReader streams data to clamd and returns its verdict.
func (c *ClamAV) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		c.setReachable(false)
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		c.setReachable(false)
		return nil, fmt.Errorf("clamav: start INSTREAM: %w", err)
	}

	if c.scanLimit > 0 {
		reader = io.LimitReader(reader, c.scanLimit)
	}

	if err := writeInstream(conn, reader); err != nil {
		c.setReachable(false)
		return nil, fmt.Errorf("clamav: %w", err)
	}

	reply, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && !errors.Is(err, io.EOF) {
		c.setReachable(false)
		return nil, fmt.Errorf("clamav: read verdict: %w", err)
	}
	c.setReachable(true)

	return c.parseVerdict(strings.TrimRight(reply, "\x00\n"))
}

// writeInstream sends the body as length-prefixed chunks, terminated by a
// zero-length chunk, which is what INSTREAM expects.
func writeInstream(w io.Writer, reader io.Reader) error {
	buf := make([]byte, clamavChunkSize)
	var header [4]byte

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(header[:], uint32(n)) // #nosec G115 -- n is bounded by len(buf)
			if _, err := w.Write(header[:]); err != nil {
				return fmt.Errorf("write chunk header: %w", err)
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return fmt.Errorf("write chunk: %w", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return fmt.Errorf("read message data: %w", readErr)
		}
	}

	binary.BigEndian.PutUint32(header[:], 0)
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("terminate stream: %w", err)
	}
	return nil
}

// parseVerdict turns clamd's reply into a result.
//
// Replies look like "stream: OK", "stream: Eicar-Test-Signature FOUND" or
// "... ERROR". An unrecognised reply is an error rather than a clean verdict:
// reporting a message clean because the reply could not be understood is the
// one outcome worth refusing to guess at.
func (c *ClamAV) parseVerdict(reply string) (*ScanResult, error) {
	result := &ScanResult{
		Engine:    c.Name(),
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"reply": reply},
	}

	switch {
	case strings.HasSuffix(reply, " OK"):
		result.Clean = true
		return result, nil

	case strings.HasSuffix(reply, " FOUND"):
		signature := strings.TrimSuffix(reply, " FOUND")
		if i := strings.LastIndex(signature, ": "); i >= 0 {
			signature = signature[i+2:]
		}
		result.Clean = false
		result.Infections = []string{signature}
		result.Details["status"] = "VIRUS DETECTED"
		result.Details["name"] = signature
		return result, nil

	case strings.Contains(reply, "ERROR"):
		return nil, fmt.Errorf("clamav reported an error: %s", reply)

	default:
		return nil, fmt.Errorf("clamav returned an unrecognised reply: %q", reply)
	}
}

func (c *ClamAV) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.address, err)
	}
	return conn, nil
}

// durationOption reads a timeout from scanner options, accepting either a
// duration or a plain number of seconds.
func durationOption(options map[string]interface{}, key string, fallback time.Duration) time.Duration {
	switch v := options[key].(type) {
	case time.Duration:
		if v > 0 {
			return v
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case string:
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

// int64Option reads a numeric option regardless of how the config decoder
// happened to type it.
func int64Option(options map[string]interface{}, key string, fallback int64) int64 {
	switch v := options[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return fallback
}
