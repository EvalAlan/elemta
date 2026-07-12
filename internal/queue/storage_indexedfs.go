package queue

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
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
	Checksum uint32                         `json:"checksum"`
}

// IndexedFSStorageBackend keeps metadata index alongside file-backed queue content.
type IndexedFSStorageBackend struct {
	*FileStorageBackend
	cfg       IndexedFSConfig
	indexPath string
	indexFile string
	indexLock string
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
		indexLock:          filepath.Join(indexPath, ".messages.lock"),
	}
	if cfg.RecoveryOnStartup {
		if err := b.rebuildIndexFromDisk(); err != nil {
			return nil, err
		}
	} else {
		if err := b.ensureIndexFile(); err != nil {
			return nil, err
		}
		if err := b.ValidateIndexIntegrity(); err != nil {
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

func (b *IndexedFSStorageBackend) CreateMessageIfAbsent(msg Message, content []byte) (bool, error) {
	created, err := b.FileStorageBackend.CreateMessageIfAbsent(msg, content)
	if err != nil {
		return false, err
	}
	// A matching consumed tombstone is a successful idempotent no-op, not a
	// live index entry. This also repairs an index left behind by a crash.
	// Bypass the index deliberately: this code repairs an index after a crash.
	if _, liveErr := b.FileStorageBackend.Retrieve(msg.ID); liveErr != nil { //nolint:staticcheck // embedded selector is intentional
		if tomb, tombErr := b.tombstoneFor(msg.ID); tombErr != nil {
			return false, tombErr
		} else if tomb != nil {
			if err := b.updateIndex(func(s *indexedFSIndexState) { delete(s.Messages, msg.ID) }); err != nil {
				return false, err
			}
			return false, nil
		}
		return false, liveErr
	}
	if err := b.updateIndex(func(s *indexedFSIndexState) { s.Messages[msg.ID] = indexedFSIndexEntry{QueueType: msg.QueueType} }); err != nil {
		return false, err
	}
	return created, nil
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

// DeleteMessageWithTombstone leaves index removal until the tombstone and both
// queue unlinks are durable. A crash before this final index rewrite is healed
// because indexed retrieval suppresses the tombstoned live/stale entry.
func (b *IndexedFSStorageBackend) DeleteMessageWithTombstone(msg Message, content []byte) error {
	if err := b.FileStorageBackend.DeleteMessageWithTombstone(msg, content); err != nil {
		return err
	}
	return b.updateIndex(func(s *indexedFSIndexState) {
		delete(s.Messages, msg.ID)
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
		if _, err := b.Retrieve(id); err != nil {
			toRemove = append(toRemove, id)
			continue
		}
		if err := b.FileStorageBackend.Delete(id); err != nil {
			return err
		}
		_ = b.DeleteContent(id)
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
		msg, err := b.Retrieve(id)
		if err != nil {
			toRemove = append(toRemove, id)
			continue
		}
		if msg.CreatedAt.Before(cutoffTime) {
			if err := b.FileStorageBackend.Delete(id); err == nil {
				deletedCount++
			}
			_ = b.DeleteContent(id)
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
		msg, err := b.Retrieve(id)
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

// ValidateIndexIntegrity checks the index against on-disk state and auto-heals
// if corruption or divergence is detected. Returns nil if the index is healthy
// or was successfully repaired.
func (b *IndexedFSStorageBackend) ValidateIndexIntegrity() error {
	state, err := b.loadIndexSnapshot()
	if err != nil {
		return b.rebuildIndexFromDisk()
	}

	// Check 1: checksum validation (detects truncated/garbage writes)
	if !b.verifyChecksum(state) {
		return b.rebuildIndexFromDisk()
	}

	// Check 2: disk divergence — verify every indexed entry has a file
	var orphaned []string
	for id := range state.Messages {
		if _, err := b.Retrieve(id); err != nil {
			orphaned = append(orphaned, id)
		}
	}

	if len(orphaned) > 0 {
		// Prune orphaned entries — checksum was valid, so index metadata is
		// correct; only the backing files are missing.
		return b.updateIndex(func(s *indexedFSIndexState) {
			for _, id := range orphaned {
				delete(s.Messages, id)
			}
		})
	}

	return nil
}

// Maintenance performs periodic index housekeeping: compacts the index
// by rewriting it (eliminating fragmentation from many small updates) and
// removes stale entries whose backing files no longer exist.
// Returns the number of stale entries pruned.
func (b *IndexedFSStorageBackend) Maintenance() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	release, err := acquireEnqueueLock(b.indexLock)
	if err != nil {
		return 0, fmt.Errorf("lock index: %w", err)
	}
	defer release()

	state, err := b.readIndexUnlocked()
	if err != nil {
		// Index is corrupt — full rebuild
		if err := b.rebuildIndexFromDiskUnlocked(); err != nil {
			return 0, err
		}
		return 0, nil
	}

	if !b.verifyChecksum(state) {
		if err := b.rebuildIndexFromDiskUnlocked(); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// Prune orphaned index entries (index says file exists but it doesn't)
	var orphaned []string
	for id := range state.Messages {
		if _, err := b.Retrieve(id); err != nil {
			orphaned = append(orphaned, id)
		}
	}

	if len(orphaned) == 0 && state.Checksum != 0 {
		// Index is clean and valid — just rewrite to compact
		return 0, b.writeIndexUnlocked(state)
	}

	for _, id := range orphaned {
		delete(state.Messages, id)
	}
	if err := b.writeIndexUnlocked(state); err != nil {
		return len(orphaned), err
	}
	return len(orphaned), nil
}

// computeChecksum computes a CRC32 over the message map contents.
// Key-order-independent: XOR per-key CRCs so map reordering doesn't change the result.
func (b *IndexedFSStorageBackend) computeChecksum(state *indexedFSIndexState) uint32 {
	var h uint32
	for id, entry := range state.Messages {
		ie := crc32.ChecksumIEEE([]byte(id))
		ie ^= crc32.ChecksumIEEE([]byte(entry.QueueType))
		h ^= ie
	}
	return h
}

// verifyChecksum recomputes and compares the stored checksum.
// A zero checksum indicates a legacy index without checksum support.
func (b *IndexedFSStorageBackend) verifyChecksum(state indexedFSIndexState) bool {
	if state.Checksum == 0 {
		return true
	}
	return state.Checksum == b.computeChecksum(&state)
}

func (b *IndexedFSStorageBackend) ensureIndexFile() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	release, err := acquireEnqueueLock(b.indexLock)
	if err != nil {
		return fmt.Errorf("lock index: %w", err)
	}
	defer release()
	if _, err := os.Stat(b.indexFile); err == nil {
		return nil
	}
	state := indexedFSIndexState{Messages: map[string]indexedFSIndexEntry{}}
	return b.writeIndexUnlocked(state)
}

func (b *IndexedFSStorageBackend) updateIndex(mut func(*indexedFSIndexState)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	release, err := acquireEnqueueLock(b.indexLock)
	if err != nil {
		return fmt.Errorf("lock index: %w", err)
	}
	defer release()
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
	release, err := acquireEnqueueLock(b.indexLock)
	if err != nil {
		return indexedFSIndexState{}, fmt.Errorf("lock index: %w", err)
	}
	defer release()
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
	state.Checksum = b.computeChecksum(&state)
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
	dir, err := os.Open(b.indexPath)
	if err != nil {
		return fmt.Errorf("open index directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync index directory: %w", err)
	}
	return nil
}

func (b *IndexedFSStorageBackend) rebuildIndexFromDisk() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	release, err := acquireEnqueueLock(b.indexLock)
	if err != nil {
		return fmt.Errorf("lock index: %w", err)
	}
	defer release()
	return b.rebuildIndexFromDiskUnlocked()
}

func (b *IndexedFSStorageBackend) rebuildIndexFromDiskUnlocked() error {
	state := indexedFSIndexState{Messages: map[string]indexedFSIndexEntry{}}
	for _, q := range []QueueType{Active, Deferred, Hold, Failed} {
		msgs, err := b.FileStorageBackend.List(q)
		if err != nil {
			// Log and continue: partial rebuild is better than no rebuild.
			continue
		}
		for _, m := range msgs {
			state.Messages[m.ID] = indexedFSIndexEntry{QueueType: m.QueueType}
		}
	}
	return b.writeIndexUnlocked(state)
}
