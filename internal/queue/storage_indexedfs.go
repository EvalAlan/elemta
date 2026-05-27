package queue

import "strings"

// IndexedFSStorageBackend is a placeholder high-volume filesystem backend.
//
// Task 2 wiring keeps behavior safe by delegating to FileStorageBackend until
// index-backed storage internals are implemented in follow-up tasks.
type IndexedFSStorageBackend struct {
	*FileStorageBackend
	cfg IndexedFSConfig
}

// NewIndexedFSStorageBackend creates an indexedfs backend wrapper.
func NewIndexedFSStorageBackend(queueDir string, cfg IndexedFSConfig) (*IndexedFSStorageBackend, error) {
	if strings.TrimSpace(cfg.ContentDir) != "" {
		queueDir = cfg.ContentDir
	}

	base := NewFileStorageBackend(queueDir)
	if err := base.EnsureDirectories(); err != nil {
		return nil, err
	}

	return &IndexedFSStorageBackend{
		FileStorageBackend: base,
		cfg:                cfg,
	}, nil
}
