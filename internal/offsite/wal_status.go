package offsite

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The WAL goes off-site every 5 minutes from a host timer, and nothing else
// looks at it between the six-hourly backups. If the upload stops, by a
// changed bucket key, a full bucket or a timer nobody re-enabled, every
// restore quietly loses the hours since the last backup, and the WAL piles
// up on the server's disk. WriteWALStatus leaves the result of each run
// where the admin console reads it, so it can warn and email someone.

// WALStatus is the result of the last wal-push, as the admin console reads it.
type WALStatus struct {
	Attempted string `json:"attempted"`
	OK        bool   `json:"ok"`
	// LastSuccess is carried over from the previous file when this run
	// failed, so a run of failures shows how long it has been.
	LastSuccess string `json:"last_success"`
	Uploaded    int    `json:"uploaded"`
	// Waiting is how many WAL files are still on the server after the run.
	Waiting int `json:"waiting"`
}

// WriteWALStatus records a wal-push run in path, replacing it atomically.
// dir is the archive directory, counted for what is still waiting.
func WriteWALStatus(path, dir string, now time.Time, uploaded int, pushErr error) error {
	st := WALStatus{Attempted: now.UTC().Format(time.RFC3339), OK: pushErr == nil, Uploaded: uploaded}
	if st.OK {
		st.LastSuccess = st.Attempted
	} else {
		var prev WALStatus
		// #nosec G304 -- the operator names the status file on the command line
		data, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(data, &prev) == nil {
			st.LastSuccess = prev.LastSuccess
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() && IsWALName(e.Name()) {
				st.Waiting++
			}
		}
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wal-status-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// The admin console runs as another user and only reads it.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // #nosec G302 -- holds times and counts, nothing secret
		return err
	}
	return os.Rename(tmp.Name(), path)
}
