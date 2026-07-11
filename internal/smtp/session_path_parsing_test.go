package smtp

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newPathTestHandler(t *testing.T) *CommandHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	config := createTestConfig(t)
	return NewCommandHandler(&Session{config: config, logger: logger}, NewSessionState(logger), nil, nil, config, nil, logger)
}

func TestMailFromStrictPathAndParameters(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, input, code string
		ok                bool
	}{
		{"null reverse path", "FROM:<>", "", true},
		{"mixed case", "fRoM:<user@example.com> sIzE=12 smtputf8", "", true},
		{"tabs tokenize parameters", "FROM:<user@example.com>\tSIZE=12\tRET=FULL", "", true},
		{"missing brackets", "FROM:user@example.com", "501", false},
		{"missing close", "FROM:<user@example.com", "501", false},
		{"stray prefix", "XFROM:<user@example.com>", "501", false},
		{"junk after path", "FROM:<user@example.com>junk", "501", false},
		{"unknown", "FROM:<user@example.com> FOO=bar", "555 5.5.4", false},
		{"substring keyword", "FROM:<user@example.com> XSMTPUTF8", "555 5.5.4", false},
		{"duplicate size", "FROM:<user@example.com> SIZE=1 size=2", "501", false},
		{"duplicate flag", "FROM:<user@example.com> SMTPUTF8 smtputf8", "501", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := newPathTestHandler(t)
			addr, size, err := ch.parseMailFrom(ctx, tc.input)
			if !tc.ok {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.code)
				return
			}
			require.NoError(t, err)
			if strings.Contains(strings.ToUpper(tc.input), "SIZE=12") {
				require.Equal(t, int64(12), size)
			}
			if tc.input == "FROM:<>" {
				require.Empty(t, addr)
			}
		})
	}
}

func TestRcptToStrictPathAndParameters(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, input, code string }{
		{"null forward path", "TO:<>", "501"},
		{"missing brackets", "TO:user@example.com", "501"},
		{"missing close", "TO:<user@example.com", "501"},
		{"stray prefix", "XTO:<user@example.com>", "501"},
		{"junk after path", "TO:<user@example.com>junk", "501"},
		{"unknown", "TO:<user@example.com> FOO=bar", "555 5.5.4"},
		{"substring keyword", "TO:<user@example.com> XNOTIFY=SUCCESS", "555 5.5.4"},
		{"duplicate notify", "TO:<user@example.com> NOTIFY=SUCCESS notify=FAILURE", "501"},
		{"duplicate orcpt", "TO:<user@example.com> ORCPT=rfc822;a@example.com orcpt=rfc822;b@example.com", "501"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newPathTestHandler(t).parseRcptTo(ctx, tc.input)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.code)
		})
	}

	ch := newPathTestHandler(t)
	addr, err := ch.parseRcptTo(ctx, "tO:<user@example.com>\tNoTiFy=SUCCESS,FAILURE\tOrCpT=rfc822;old@example.com")
	require.NoError(t, err)
	require.Equal(t, "user@example.com", addr)
}

func TestReviewedEnvelopeParsing(t *testing.T) {
	ch := newPathTestHandler(t)
	ch.config.MaxSize = 100
	for _, input := range []string{
		`FROM:<"a>b"@example.com>`,
		`FROM:<"a\\\"b"@example.com>`,
	} {
		_, _, err := ch.parseMailFrom(context.Background(), input)
		require.NoError(t, err, input)
	}
	for _, input := range []string{
		"FROM:<a b@example.com>", "FROM:<a@@example.com>", `FROM:<"bad@example.com>`,
		"FROM:<a@example..com>", "FROM:<a@example.com> SIZE=+1", "FROM:<a@example.com> SIZE=101",
		"FROM:<a@example.com> ENVID=bad+GG", "FROM:<a@example.com>\vSIZE=1",
	} {
		_, _, err := ch.parseMailFrom(context.Background(), input)
		require.Error(t, err, input)
	}
	for _, input := range []string{
		"TO:<a@example.com> NOTIFY=SUCCESS,SUCCESS",
		"TO:<a@example.com> ORCPT=rfc822",
		"TO:<a@example.com> ORCPT=rfc822;bad+ZZ",
	} {
		_, err := ch.parseRcptTo(context.Background(), input)
		require.Error(t, err, input)
	}
}

func FuzzParseSMTPPath(f *testing.F) {
	for _, seed := range []string{"FROM:<>", "FROM:<a@example.com> SIZE=1", "TO:<>", "FROM:<missing"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, fields, err := parseSMTPPath(input, "FROM:", true)
		if err == nil {
			require.True(t, strings.HasPrefix(strings.ToUpper(input), "FROM:<"))
			for _, field := range fields {
				require.NotEmpty(t, field)
			}
		}
	})
}
