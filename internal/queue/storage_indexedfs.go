package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
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
	state, err := b.loadIndexSnapshot()
	if err != nil {
		return err
	}

	ids := make([]string, 0)
	for id, entry := range state.Messages {
		if entry.QueueType == queueType {
			ids = append(ids, id)
		}
	}

	toRemove := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := b.FileStorageBackend.Retrieve(id); err != nil {
			toRemove = append(toRemove, id)
			continue
		}
		if err := b.FileStorageBackend.Delete(id); err != nil {
			return err
		}
		_ = b.FileStorageBackend.DeleteContent(id)
		toRemove = append(toRemove, id)
	}

	if len(toRemove) > 0 {
		if err := b.removeIndexEntries(toRemove); err != nil {
			return err
		}
	}
	return nil
}

func (b *IndexedFSStorageBackend) Cleanup(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention hours must be positive")
	}

	state, err := b.loadIndexSnapshot()
	if err != nil {
		return 0, err
	}

	cutoffTime := time.Now().Add(-time.Duration(retentionHours) * time.Hour)
	toRemove := make([]string, 0)
	deletedCount := 0

	for id := range state.Messages {
		msg, err := b.FileStorageBackend.Retrieve(id)
		if err != nil {
			toRemove = append(toRemove, id)
			continue
		}
		if msg.CreatedAt.Before(cutoffTime) {
			if err := b.FileStorageBackend.Delete(id); err == nil {
				deletedCount++
			}
			_ = b.FileStorageBackend.DeleteContent(id)
			toRemove = append(toRemove, id)
		}
	}

	if len(toRemove) > 0 {
		if err := b.removeIndexEntries(toRemove); err != nil {
			return deletedCount, err
		}
	}
	return deletedCount, nil
}

func (b *IndexedFSStorageBackend) Count(queueType QueueType) (int, error) {
	state, err := b.loadIndexSnapshot()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range state.Messages {
		if entry.QueueType == queueType {
			count++
		}
	}
	return count, nil
}

func (b *IndexedFSStorageBackend) List(queueType QueueType) ([]Message, error) {
	state, err := b.loadIndexSnapshot()
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(state.Messages))
	for id, entry := range state.Messages {
		if entry.QueueType == queueType {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	messages := make([]Message, 0, len(ids))
	stale := make([]string, 0)
	for _, id := range ids {
		msg, err := b.FileStorageBackend.Retrieve(id)
		if err != nil {
			stale = append(stale, id)
			continue
		}
		messages = append(messages, msg)
	}

	if len(stale) > 0 {
		_ = b.updateIndex(func(s *indexedFSIndexState) {
			for _, id := range stale {
				delete(s.Messages, id)
			}
		})
	}

	return messages, nil
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

func (b *IndexedFSStorageBackend) loadIndexSnapshot() (indexedFSIndexState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readIndexUnlocked()
}

func (b *IndexedFSStorageBackend) removeIndexEntries(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		for _, id := range ids {
			delete(s.Messages, id)
		}
	})
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
