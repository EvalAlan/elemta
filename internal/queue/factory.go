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

// PostgresConfig holds postgres backend settings for queue manager creation.
type PostgresConfig struct {
	DSN                    string
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeSeconds int
}

// IndexedFSConfig holds indexed filesystem backend settings for queue manager creation.
type IndexedFSConfig struct {
	IndexPath         string
	ContentDir        string
	SyncMode          string
	RecoveryOnStartup bool
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
// ManagerOption adjusts a manager after its backend is built.
//
// Variadic rather than another positional parameter: this constructor already
// takes six, and a seventh — a bool, at that — is the shape of argument that
// gets passed in the wrong position and silently changes durability behaviour.
type ManagerOption func(*Manager)

// WithTombstoneBody controls whether a consumed-enqueue tombstone keeps a copy
// of the message. Retaining it is the safe default; see tombstoneBodyPolicy for
// what dropping it buys and costs.
func WithTombstoneBody(retain bool) ManagerOption {
	return func(m *Manager) {
		m.SetTombstoneBody(retain)
	}
}

func NewManagerFromBackend(queueDir, backend string, sqliteCfg SQLiteConfig, postgresCfg PostgresConfig, indexedFSCfg IndexedFSConfig, failedQueueRetentionHours int, opts ...ManagerOption) (*Manager, error) {
	backend = strings.TrimSpace(strings.ToLower(backend))
	if backend == "" {
		backend = "file"
	}

	switch backend {
	case "file":
		m := NewManager(queueDir, failedQueueRetentionHours)
		applyManagerOptions(m, opts)
		return m, nil
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
		applyManagerOptions(m, opts)
		if m.queueDir == "" {
			m.queueDir = queueDir
		}
		return m, nil
	case "postgres":
		postgresBackend, err := NewPostgresStorageBackend(postgresCfg)
		if err != nil {
			return nil, err
		}

		m := NewManagerWithStorage(postgresBackend, failedQueueRetentionHours)
		applyManagerOptions(m, opts)
		if m.queueDir == "" {
			m.queueDir = queueDir
		}
		return m, nil
	case "indexedfs":
		indexedBackend, err := NewIndexedFSStorageBackend(queueDir, indexedFSCfg)
		if err != nil {
			return nil, err
		}

		m := NewManagerWithStorage(indexedBackend, failedQueueRetentionHours)
		applyManagerOptions(m, opts)
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
	case *PostgresStorageBackend:
		return "postgres"
	case *IndexedFSStorageBackend:
		return "indexedfs"
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
	case *PostgresStorageBackend:
		pgStats, err := backend.StorageStats()
		if err != nil {
			return info, err
		}
		info.DBBytes = pgStats.TotalRelationBytes
		info.MessageRows = pgStats.MessageRows
		info.ContentRows = pgStats.ContentRows
		info.ContentBytes = pgStats.ContentBytes
		info.TotalBytes = pgStats.TotalRelationBytes
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

func applyManagerOptions(m *Manager, opts []ManagerOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
}

// tombstoneBodySetter is implemented by the backends that write tombstones.
type tombstoneBodySetter interface {
	setTombstoneBody(retain bool)
}

// SetTombstoneBody updates a running manager, so the setting takes effect on a
// config reload rather than only at startup. Without this the control saved,
// reported success, and changed nothing until someone restarted the server.
func (m *Manager) SetTombstoneBody(retain bool) {
	if setter, ok := m.storageBackend.(tombstoneBodySetter); ok {
		setter.setTombstoneBody(retain)
	}
}
