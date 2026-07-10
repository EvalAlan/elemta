package plugin

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestARCImpl_ExtractARCHeaders(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    []string
	}{
		{
			name: "message with ARC headers",
			message: "ARC-Seal: i=1; a=rsa-sha256\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha256\r\n" +
				"ARC-Authentication-Results: i=1; mx.example.com\r\n" +
				"Subject: hello\r\n" +
				"\r\n" +
				"body text",
			want: []string{
				"ARC-Seal: i=1; a=rsa-sha256",
				"ARC-Message-Signature: i=1; a=rsa-sha256",
				"ARC-Authentication-Results: i=1; mx.example.com",
			},
		},
		{
			name:    "no ARC headers",
			message: "Subject: hello\r\n\r\nbody text",
			want:    nil,
		},
		{
			name: "ARC headers only counted before blank line",
			message: "Subject: hello\r\n" +
				"\r\n" +
				"ARC-Seal: i=1; a=rsa-sha256\r\n",
			want: nil,
		},
		{
			name: "Authentication-Results counted as ARC header",
			message: "Authentication-Results: mx.example.com; spf=pass\r\n" +
				"\r\n",
			want: []string{"Authentication-Results: mx.example.com; spf=pass"},
		},
	}

	p := NewARCImpl()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, err := p.extractARCHeaders(strings.NewReader(tt.message))
			require.NoError(t, err)
			assert.Equal(t, tt.want, headers)
		})
	}
}

func TestARCImpl_GroupARCHeadersByInstance(t *testing.T) {
	p := NewARCImpl()

	t.Run("groups headers by instance number and sorts", func(t *testing.T) {
		headers := []string{
			"ARC-Seal: i=2; a=rsa-sha256; d=example.com",
			"ARC-Message-Signature: i=1; a=rsa-sha256",
			"ARC-Seal: i=1; a=rsa-sha256; d=first.com",
			"ARC-Authentication-Results: i=1; mx.example.com",
			"ARC-Message-Signature: i=2; a=rsa-sha256",
			"ARC-Authentication-Results: i=2; mx.example.com",
		}

		instances, err := p.groupARCHeadersByInstance(headers)
		require.NoError(t, err)
		require.Len(t, instances, 2)
		assert.Equal(t, 1, instances[0].InstanceNum)
		assert.Equal(t, 2, instances[1].InstanceNum)
		assert.Contains(t, instances[0].SealSignature, "first.com")
		assert.Contains(t, instances[1].SealSignature, "example.com")
	})

	t.Run("missing instance number in ARC-Seal is an error", func(t *testing.T) {
		headers := []string{"ARC-Seal: a=rsa-sha256; d=example.com"}
		_, err := p.groupARCHeadersByInstance(headers)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing instance number")
	})

	t.Run("missing instance number in ARC-Message-Signature is an error", func(t *testing.T) {
		headers := []string{"ARC-Message-Signature: a=rsa-sha256"}
		_, err := p.groupARCHeadersByInstance(headers)
		require.Error(t, err)
	})

	t.Run("missing instance number in ARC-Authentication-Results is an error", func(t *testing.T) {
		headers := []string{"ARC-Authentication-Results: mx.example.com"}
		_, err := p.groupARCHeadersByInstance(headers)
		require.Error(t, err)
	})

	t.Run("empty input produces empty output", func(t *testing.T) {
		instances, err := p.groupARCHeadersByInstance(nil)
		require.NoError(t, err)
		assert.Empty(t, instances)
	})
}

func TestARCImpl_VerifyARCChain(t *testing.T) {
	p := NewARCImpl()

	t.Run("no instances returns ARCNone", func(t *testing.T) {
		result, err := p.verifyARCChain(nil, []byte("msg"))
		require.NoError(t, err)
		assert.Equal(t, ARCNone, result.Result)
		assert.Equal(t, 0, result.InstanceCount)
	})

	t.Run("incomplete instance returns ARCPermError", func(t *testing.T) {
		instances := []ARCInstance{
			{InstanceNum: 1, SealSignature: "ARC-Seal: i=1", MessageSignature: ""},
		}
		result, err := p.verifyARCChain(instances, []byte("msg"))
		require.NoError(t, err)
		assert.Equal(t, ARCPermError, result.Result)
		assert.Contains(t, result.Reason, "Incomplete ARC instance")
	})

	t.Run("non-sequential instance numbers returns ARCPermError", func(t *testing.T) {
		instances := []ARCInstance{
			{InstanceNum: 1, SealSignature: "s1", MessageSignature: "m1", AuthResults: "a1"},
			{InstanceNum: 3, SealSignature: "s3", MessageSignature: "m3", AuthResults: "a3"},
		}
		result, err := p.verifyARCChain(instances, []byte("msg"))
		require.NoError(t, err)
		assert.Equal(t, ARCPermError, result.Result)
		assert.Equal(t, "Non-sequential instance numbers", result.Reason)
	})

	t.Run("valid sequential chain returns ARCPass", func(t *testing.T) {
		instances := []ARCInstance{
			{InstanceNum: 1, SealSignature: "ARC-Seal: i=1; d=first.com", MessageSignature: "m1", AuthResults: "a1"},
			{InstanceNum: 2, SealSignature: "ARC-Seal: i=2; d=second.com", MessageSignature: "m2", AuthResults: "a2"},
		}
		result, err := p.verifyARCChain(instances, []byte("msg"))
		require.NoError(t, err)
		assert.Equal(t, ARCPass, result.Result)
		assert.Equal(t, 2, result.InstanceCount)
		assert.Equal(t, "first.com", result.OldestDomain)
		assert.Equal(t, "second.com", result.LatestDomain)
	})
}

func TestARCImpl_VerifyARC(t *testing.T) {
	p := NewARCImpl()

	t.Run("message with no ARC headers returns ARCNone", func(t *testing.T) {
		result, err := p.VerifyARC(strings.NewReader("Subject: hi\r\n\r\nbody"))
		require.NoError(t, err)
		assert.Equal(t, ARCNone, result.Result)
		assert.Equal(t, "No ARC headers found", result.Reason)
	})

	t.Run("message with complete single-instance chain returns ARCPass", func(t *testing.T) {
		msg := "ARC-Seal: i=1; a=rsa-sha256; d=example.com\r\n" +
			"ARC-Message-Signature: i=1; a=rsa-sha256\r\n" +
			"ARC-Authentication-Results: i=1; mx.example.com\r\n" +
			"Subject: hi\r\n" +
			"\r\n" +
			"body"
		result, err := p.VerifyARC(strings.NewReader(msg))
		require.NoError(t, err)
		assert.Equal(t, ARCPass, result.Result)
		assert.Equal(t, 1, result.InstanceCount)
	})

	t.Run("malformed ARC-Seal header returns ARCPermError without hard error", func(t *testing.T) {
		msg := "ARC-Seal: a=rsa-sha256\r\n\r\n"
		result, err := p.VerifyARC(strings.NewReader(msg))
		require.NoError(t, err)
		assert.Equal(t, ARCPermError, result.Result)
	})
}

func TestARCImpl_ExtractDomain(t *testing.T) {
	p := NewARCImpl()

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"domain present", "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=selector", "example.com"},
		{"domain absent", "ARC-Seal: i=1; a=rsa-sha256", ""},
		{"domain first field", "d=first.example.com; other=stuff", "first.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.extractDomain(tt.header))
		})
	}
}

func TestARCImpl_Init_UsesInjectedDKIMPlugin(t *testing.T) {
	p := NewARCImpl()
	stub := &stubDKIMPlugin{}

	err := p.Init(map[string]interface{}{"dkim_plugin": stub})
	require.NoError(t, err)
	assert.Same(t, stub, p.dkimPlugin)
}

// stubDKIMPlugin is a minimal DKIMPlugin implementation for injection tests.
type stubDKIMPlugin struct{}

func (s *stubDKIMPlugin) GetInfo() PluginInfo               { return PluginInfo{Name: "stub-dkim"} }
func (s *stubDKIMPlugin) Init(map[string]interface{}) error { return nil }
func (s *stubDKIMPlugin) Close() error                      { return nil }
func (s *stubDKIMPlugin) VerifyDKIM(r io.Reader) ([]*DKIMVerifyResult, error) {
	return nil, nil
}
func (s *stubDKIMPlugin) SignDKIM(r io.Reader, w io.Writer, options *DKIMSignOptions) error {
	return nil
}
