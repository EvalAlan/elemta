package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSettingsSave(t *testing.T) {
	const doc = "hostname = \"mail.example.com\"\nmax_size = 52428800\n\n[server]\nmax_size = 26214400\n"
	put := func(s *Server, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handleUpdateConfig(w, r)
		return w
	}
	read := func(path string) string {
		b, err := os.ReadFile(path) // #nosec G304 -- the test's own file
		require.NoError(t, err)
		return string(b)
	}

	// A save of something else leaves the size alone, whatever this process
	// believes it is.
	s, path := testServerWithConfig(t, doc)
	s.mainConfig.MaxSize = 26214400
	require.NoError(t, s.persistConfig())
	require.Equal(t, 1, strings.Count(read(path), "max_size = 52428800"))

	// Changed, as a number or as the string older consoles send.
	for _, body := range []string{`{"max_size":73400320}`, `{"max_size":"73400320"}`} {
		s, path = testServerWithConfig(t, doc)
		s.mainConfig.MaxSize = 52428800
		w := put(s, body)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"requires_restart":true`)
		saved := read(path)
		require.Contains(t, saved, "max_size = 73400320")
		require.NotContains(t, saved, "52428800")
	}

	for _, body := range []string{`{"max_size":"50MB"}`, `{"max_size":12}`, `{"max_size":1.5}`, `{"queue_dir":"/elsewhere"}`, `{"hostname":"changed.example.com","max_size":1}`} {
		s, path = testServerWithConfig(t, doc)
		s.mainConfig.Hostname, s.mainConfig.MaxSize = "mail.example.com", 52428800
		w := put(s, body)
		require.Equal(t, http.StatusBadRequest, w.Code, body)
		require.Equal(t, doc, read(path), body)
		require.Equal(t, "mail.example.com", s.mainConfig.Hostname, "a refused save changed memory: %s", body)
	}
}

type fixedHours struct {
	MetricsStore
	hours []HourlyStatsData
}

func (f fixedHours) GetHourlyStats(context.Context) ([]HourlyStatsData, error) { return f.hours, nil }

func TestThroughputIsADailyAverage(t *testing.T) {
	hours := make([]HourlyStatsData, 24)
	for i := range hours {
		hours[i] = HourlyStatsData{Hour: fmt.Sprint(i), Delivered: 8, Failed: 1, Deferred: 1}
	}
	s := &Server{metricsStore: fixedHours{hours: hours}}
	require.InDelta(t, 10, s.averagePerHour(context.Background()), 0.0001)
	require.Zero(t, (&Server{}).averagePerHour(context.Background()))
}
