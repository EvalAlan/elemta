package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SQLiteConfig holds sqlite backend settings for queue manager creation.
type SQLiteConfig struct {
	Path          string
	BusyTimeoutMS int
	JournalMode   string
	Synchronous   string
}

// StorageInfo describes queue storage backend characteristics and size metrics.
type StorageInfo struct {
	Backend       string `json:"backend"`
	QueueDir      string `json:"queue_dir,omitempty"`
	SQLitePath    string `json:"sqlite_path,omitempty"`
	DBBytes       int64  `json:"db_bytes"`
	WALBytes      int64  `json:"wal_bytes"`
	SHMBytes      int64  `json:"shm_bytes"`
	PageSize      int64  `json:"page_size"`
	PageCount     int64  `json:"page_count"`
	FreeListCount int64  `json:"freelist_count"`
	MessageRows   int64  `json:"message_rows"`
	ContentRows   int64  `json:"content_rows"`
	ContentBytes  int64  `json:"content_bytes"`
	FileCount     int64  `json:"file_count"`
	MetadataFiles int64  `json:"metadata_files"`
	ContentFiles  int64  `json:"content_files"`
	TotalBytes    int64  `json:"total_bytes"`
}

// NewManagerFromBackend creates a queue manager based on configured backend.
func NewManagerFromBackend(queueDir, backend string, sqliteCfg SQLiteConfig, failedQueueRetentionHours int) (*Manager, error) {
	backend = strings.TrimSpace(strings.ToLower(backend))
	if backend == "" {
		backend = "file"
	}

	switch backend {
	case "file":
		return NewManager(queueDir, failedQueueRetentionHours), nil
	case "sqlite":
		sqlitePath := strings.TrimSpace(sqliteCfg.Path)
		if sqlitePath == "" {
			sqlitePath = filepath.Join(queueDir, "queue.db")
		}

		sqliteBackend, err := NewSQLiteStorageBackend(sqlitePath, sqliteCfg.BusyTimeoutMS, sqliteCfg.JournalMode, sqliteCfg.Synchronous)
		if err != nil {
			return nil, err
		}

		m := NewManagerWithStorage(sqliteBackend, failedQueueRetentionHours)
		if m.queueDir == "" {
			m.queueDir = queueDir
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported queue backend: %s", backend)
	}
}

// BackendType returns the storage backend currently used by the queue manager.
func (m *Manager) BackendType() string {
	switch m.storageBackend.(type) {
	case *FileStorageBackend:
		return "file"
	case *SQLiteStorageBackend:
		return "sqlite"
	default:
		return "unknown"
	}
}

// GetStorageInfo returns backend-specific storage usage metrics.
func (m *Manager) GetStorageInfo() (StorageInfo, error) {
	info := StorageInfo{
		Backend:  m.BackendType(),
		QueueDir: m.queueDir,
	}

	switch backend := m.storageBackend.(type) {
	case *SQLiteStorageBackend:
		sqliteStats, err := backend.StorageStats()
		if err != nil {
			return info, err
		}

		info.SQLitePath = sqliteStats.DBPath
		info.DBBytes = sqliteStats.DBBytes
		info.WALBytes = sqliteStats.WALBytes
		info.SHMBytes = sqliteStats.SHMBytes
		info.PageSize = sqliteStats.PageSize
		info.PageCount = sqliteStats.PageCount
		info.FreeListCount = sqliteStats.FreeListCount
		info.MessageRows = sqliteStats.MessageRows
		info.ContentRows = sqliteStats.ContentRows
		info.ContentBytes = sqliteStats.ContentBytes
		info.TotalBytes = sqliteStats.DBBytes + sqliteStats.WALBytes + sqliteStats.SHMBytes
		if info.QueueDir == "" {
			info.QueueDir = filepath.Dir(sqliteStats.DBPath)
		}
		return info, nil
	case *FileStorageBackend:
		var fileCount int64
		var metadataFiles int64
		var contentFiles int64
		var totalBytes int64

		err := filepath.Walk(backend.queueDir, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fi.IsDir() {
				return nil
			}

			fileCount++
			totalBytes += fi.Size()
			if strings.HasSuffix(path, ".json") {
				metadataFiles++
			}
			if strings.Contains(path, string(filepath.Separator)+"data"+string(filepath.Separator)) {
				contentFiles++
			}
			return nil
		})
		if err != nil {
			return info, err
		}

		info.FileCount = fileCount
		info.MetadataFiles = metadataFiles
		info.ContentFiles = contentFiles
		info.TotalBytes = totalBytes
		if info.QueueDir == "" {
			info.QueueDir = backend.queueDir
		}
		return info, nil
	default:
		return info, nil
	}
}
