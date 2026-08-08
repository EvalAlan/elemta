package smtp

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/busybox42/elemta/internal/logging"
)

// buildScanMessage returns a message of roughly sizeKB with no threat matches,
// so the benchmark measures the scan itself rather than the rejection path.
func buildScanMessage(sizeKB int) []byte {
	var b strings.Builder
	b.WriteString("Subject: benchmark\r\nFrom: sender@example.com\r\n\r\n")
	line := "the quick brown fox jumps over the lazy dog and keeps running\r\n"
	for b.Len() < sizeKB*1024 {
		b.WriteString(line)
	}
	return []byte(b.String())
}

// BenchmarkSecurityScan measures the transient allocation of the content scans.
//
// These are substring checks over the whole message. Written naively they
// lowercase the message once per pattern, so the allocation is a multiple of
// the message size rather than a single copy — which for a 25MB message is the
// difference between tens and hundreds of megabytes of garbage per delivery.
func BenchmarkSecurityScan(b *testing.B) {
	sizes := []int{64, 1024, 8192} // KB

	for _, sizeKB := range sizes {
		data := buildScanMessage(sizeKB)
		client, server := net.Pipe()
		b.Cleanup(func() { _ = client.Close(); _ = server.Close() })

		dh := &DataHandler{
			logger:            quietLogger(),
			conn:              server,
			msgLogger:         logging.NewMessageLogger(quietLogger()),
			enhancedValidator: NewEnhancedValidator(quietLogger()),
			config:            &Config{Hostname: "bench.example.com"},
		}
		metadata := &MessageMetadata{
			From:    "sender@example.com",
			To:      []string{"user@example.com"},
			Subject: "benchmark",
			Headers: map[string]string{},
		}

		b.Run(sizeName(sizeKB), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := &SecurityScanResult{Passed: true, Threats: make([]string, 0)}
				// Built inside the loop so the shared views are counted here,
				// the same as the per-pattern copies they replaced.
				view := newScanContent(data)
				if err := dh.performContentAnalysis(context.Background(), view, result); err != nil {
					b.Fatalf("content analysis: %v", err)
				}
				if err := dh.performSpamScan(context.Background(), view, metadata, result); err != nil {
					b.Fatalf("spam scan: %v", err)
				}
			}
		})
	}
}

func sizeName(kb int) string {
	if kb >= 1024 {
		return itoa(kb/1024) + "MB"
	}
	return itoa(kb) + "KB"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}
