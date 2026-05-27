package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type indexedFSIndexEntry struct {
	QueueType QueueType `json:"queue_type"`
}

type indexedFSIndexState struct {
	Messages map[string]indexedFSIndexEntry `json:"messages"`
}

// IndexedFSStorageBackend keeps metadata index alongside file-backed queue content.
type IndexedFSStorageBackend struct {
	*FileStorageBackend
	cfg       IndexedFSConfig
	indexPath string
	indexFile string
	mu        sync.Mutex
}

func NewIndexedFSStorageBackend(queueDir string, cfg IndexedFSConfig) (*IndexedFSStorageBackend, error) {
	base := NewFileStorageBackend(queueDir)
	if err := base.EnsureDirectories(); err != nil {
		return nil, err
	}

	indexPath := strings.TrimSpace(cfg.IndexPath)
	if indexPath == "" {
		indexPath = filepath.Join(queueDir, "index")
	}
	if err := os.MkdirAll(indexPath, 0700); err != nil {
		return nil, fmt.Errorf("create index directory: %w", err)
	}

	b := &IndexedFSStorageBackend{
		FileStorageBackend: base,
		cfg:                cfg,
		indexPath:          indexPath,
		indexFile:          filepath.Join(indexPath, "messages.json"),
	}
	if cfg.RecoveryOnStartup {
		if err := b.rebuildIndexFromDisk(); err != nil {
			return nil, err
		}
	} else {
		if err := b.ensureIndexFile(); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (b *IndexedFSStorageBackend) Store(msg Message) error {
	if err := b.FileStorageBackend.Store(msg); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		s.Messages[msg.ID] = indexedFSIndexEntry{QueueType: msg.QueueType}
	})
}

func (b *IndexedFSStorageBackend) Update(msg Message) error {
	if err := b.FileStorageBackend.Update(msg); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		s.Messages[msg.ID] = indexedFSIndexEntry{QueueType: msg.QueueType}
	})
}

func (b *IndexedFSStorageBackend) Delete(id string) error {
	if err := b.FileStorageBackend.Delete(id); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		delete(s.Messages, id)
	})
}

func (b *IndexedFSStorageBackend) Move(id string, fromQueue, toQueue QueueType) error {
	if err := b.FileStorageBackend.Move(id, fromQueue, toQueue); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		s.Messages[id] = indexedFSIndexEntry{QueueType: toQueue}
	})
}

func (b *IndexedFSStorageBackend) DeleteAll(queueType QueueType) error {
	if err := b.FileStorageBackend.DeleteAll(queueType); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		for id, entry := range s.Messages {
			if entry.QueueType == queueType {
				delete(s.Messages, id)
			}
		}
	})
}

func (b *IndexedFSStorageBackend) Cleanup(retentionHours int) (int, error) {
	deleted, err := b.FileStorageBackend.Cleanup(retentionHours)
	if err != nil {
		return deleted, err
	}
	if err := b.rebuildIndexFromDisk(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (b *IndexedFSStorageBackend) ensureIndexFile() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := os.Stat(b.indexFile); err == nil {
		return nil
	}
	state := indexedFSIndexState{Messages: map[string]indexedFSIndexEntry{}}
	return b.writeIndexUnlocked(state)
}

func (b *IndexedFSStorageBackend) updateIndex(mut func(*indexedFSIndexState)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, err := b.readIndexUnlocked()
	if err != nil {
		return err
	}
	mut(&state)
	return b.writeIndexUnlocked(state)
}

func (b *IndexedFSStorageBackend) readIndexUnlocked() (indexedFSIndexState, error) {
	data, err := os.ReadFile(b.indexFile)
	if err != nil {
		return indexedFSIndexState{}, fmt.Errorf("read index: %w", err)
	}
	var state indexedFSIndexState
	if err := json.Unmarshal(data, &state); err != nil {
		return indexedFSIndexState{}, fmt.Errorf("unmarshal index: %w", err)
	}
	if state.Messages == nil {
		state.Messages = map[string]indexedFSIndexEntry{}
	}
	return state, nil
}

func (b *IndexedFSStorageBackend) writeIndexUnlocked(state indexedFSIndexState) error {
	if state.Messages == nil {
		state.Messages = map[string]indexedFSIndexEntry{}
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	tmp, err := os.CreateTemp(b.indexPath, ".idxtmp_")
	if err != nil {
		return fmt.Errorf("create temp index: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp index: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp index: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp index: %w", err)
	}
	if err := os.Rename(tmpName, b.indexFile); err != nil {
		return fmt.Errorf("rename index: %w", err)
	}
	return nil
}

func (b *IndexedFSStorageBackend) rebuildIndexFromDisk() error {
	state := indexedFSIndexState{Messages: map[string]indexedFSIndexEntry{}}
	for _, q := range []QueueType{Active, Deferred, Hold, Failed} {
		msgs, err := b.FileStorageBackend.List(q)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			state.Messages[m.ID] = indexedFSIndexEntry{QueueType: m.QueueType}
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writeIndexUnlocked(state)
}
