// Package logship gets every service's log to Elasticsearch or Logstash.
//
// Each service copies its log lines, without waiting, to a bounded queue and
// from there to a capped Valkey stream. The admin console alone empties the
// stream to the destination. So mail never depends on the log cluster: while
// it is down the stream holds the newest lines and counts what it let go.
// Nothing reads the Docker socket and nothing has to share a log volume.
package logship

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Where logs can go.
const (
	KindElasticsearch = "elasticsearch"
	KindLogstash      = "logstash"
)

const (
	keyPolicy = "elemta:logship:policy"
	keyStream = "elemta:logship:stream"
	keyStatus = "elemta:logship:status"
	keyLock   = "elemta:logship:lock"

	// maxStreamLines with maxLineBytes bounds what waiting logs can take of
	// Valkey, which also holds sessions and mustn't be filled by them:
	// about 80 MB at the very worst, a tenth of that for ordinary lines.
	maxStreamLines = 20000
	maxLineBytes   = 4 << 10

	// DefaultIndex is the index prefix; the day is added to it.
	DefaultIndex = "elemta-logs"
)

var indexRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,79}$`)

// Settings is what the administrator chooses.
type Settings struct {
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind"`
	URL     string `json:"url"`
	Index   string `json:"index"`
	// MinLevel is debug, info, warn or error.
	MinLevel string `json:"min_level"`
	// IncludeSubjects ships subjects, which are the content of people's
	// mail; off unless chosen.
	IncludeSubjects bool `json:"include_subjects"`
}

// WithDefaults fills in what was left out.
func (s Settings) WithDefaults() Settings {
	if s.Kind == "" {
		s.Kind = KindElasticsearch
	}
	if s.Index == "" {
		s.Index = DefaultIndex
	}
	if s.MinLevel == "" {
		s.MinLevel = "info"
	}
	s.URL = strings.TrimRight(strings.TrimSpace(s.URL), "/")
	return s
}

// Validate refuses settings that couldn't work.
func (s Settings) Validate() error {
	if s.Kind != KindElasticsearch && s.Kind != KindLogstash {
		return fmt.Errorf("destination must be %s or %s", KindElasticsearch, KindLogstash)
	}
	if !indexRE.MatchString(s.Index) {
		return errors.New("the index prefix takes lower-case letters, digits, - and _, starting with a letter or digit")
	}
	if _, ok := levels[s.MinLevel]; !ok {
		return errors.New("the level must be debug, info, warn or error")
	}
	if s.URL == "" {
		if s.Enabled {
			return errors.New("choose a destination before switching log shipping on")
		}
		return nil
	}
	return checkURL(s.URL)
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("the URL must start with http:// or https:// and name a host")
	}
	if u.User != nil {
		return errors.New("put the user name and password in the credential fields, not in the URL")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the URL can't have a query or fragment")
	}
	return nil
}

// DestinationsEnv lists where logs may be sent. It is in the environment
// because the console can write its own configuration: whoever takes over an
// administrator's session mustn't be able to add to the list, or they could
// have every service's log sent to them, or reach into the private network.
const DestinationsEnv = "ELEMTA_LOG_SHIP_DESTINATIONS"

// ParseDestinations reads the list, separated by commas or spaces, and counts
// what it couldn't use. Those aren't returned: one can hold a password.
func ParseDestinations(list string) (urls []string, unusable int) {
	for _, u := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		u = strings.TrimRight(u, "/")
		switch {
		case checkURL(u) != nil:
			unusable++
		case !slices.Contains(urls, u):
			urls = append(urls, u)
		}
	}
	return urls, unusable
}

// origin is what a credential belongs to.
func (s Settings) origin() string {
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

var levels = map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}

// policy is what the collecting services need: no URL and no credential.
type policy struct {
	Enabled         bool   `json:"enabled"`
	MinLevel        string `json:"min_level"`
	IncludeSubjects bool   `json:"include_subjects"`
}

// Status is how shipping is going.
type Status struct {
	// Available is false without Valkey, which carries the logs.
	Available bool  `json:"available"`
	Waiting   int64 `json:"waiting"`
	Sent      int64 `json:"sent"`
	// Dropped were let go because a queue was full; Rejected were refused by
	// the destination as documents it can't take.
	Dropped       int64      `json:"dropped"`
	Rejected      int64      `json:"rejected"`
	RejectReason  string     `json:"reject_reason,omitempty"`
	LastSuccess   *time.Time `json:"last_success,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	FailingSince  *time.Time `json:"failing_since,omitempty"`
	LastDropped   *time.Time `json:"last_dropped,omitempty"`
	CredentialSet bool       `json:"credential_set"`
}
