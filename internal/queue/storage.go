package queue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func validateMessageID(id string) error {
	if id == "" {
		return fmt.Errorf("empty message ID")
	}
	if len(id) > 255 {
		return fmt.Errorf("message ID too long")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") || strings.ContainsRune(id, 0) {
		return fmt.Errorf("invalid characters in message ID %q", id)
	}
	return nil
}

func validateQueueType(q QueueType) error {
	switch q {
	case Active, Deferred, Hold, Failed:
		return nil
	}
	return fmt.Errorf("invalid queue type %q", q)
}

type FileStorageBackend struct{ queueDir string }

type enqueueTombstone struct {
	Message Message `json:"message"`
	Content []byte  `json:"content"`
}

func NewFileStorageBackend(queueDir string) *FileStorageBackend {
	return &FileStorageBackend{queueDir: queueDir}
}

func sameEnqueueMessage(a, b Message) bool {
	// Queue placement and delivery bookkeeping are mutable after enqueue. These
	// are the immutable caller-supplied identity fields.
	if a.ID != b.ID || a.From != b.From || a.Domain != b.Domain || a.Subject != b.Subject || a.Size != b.Size || a.Priority != b.Priority || !a.ReceivedAt.Equal(b.ReceivedAt) || len(a.To) != len(b.To) {
		return false
	}
	for i := range a.To {
		if a.To[i] != b.To[i] {
			return false
		}
	}
	return true
}

// CreateMessageIfAbsent uses mkdir as a cross-process per-ID claim. Content is
// published first; a crash can leave content-only data, which retry verifies and
// completes. Metadata-only entries from older writers are safely repaired.
func (fs *FileStorageBackend) CreateMessageIfAbsent(msg Message, content []byte) (bool, error) {
	if err := validateMessageID(msg.ID); err != nil {
		return false, err
	}
	if err := fs.EnsureDirectories(); err != nil {
		return false, err
	}
	lock, err := acquireEnqueueLock(filepath.Join(fs.queueDir, "tmp", ".enqueue-"+msg.ID))
	if err != nil {
		return false, fmt.Errorf("claim enqueue ID: %w", err)
	}
	defer lock()
	if raw, readErr := os.ReadFile(filepath.Join(fs.queueDir, "tmp", ".consumed-"+msg.ID+".json")); readErr == nil {
		var tomb enqueueTombstone
		if json.Unmarshal(raw, &tomb) != nil || !sameEnqueueMessage(tomb.Message, msg) || !bytes.Equal(tomb.Content, content) {
			return false, fmt.Errorf("message ID %q conflicts with consumed enqueue identity", msg.ID)
		}
		return false, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return false, fmt.Errorf("read enqueue tombstone: %w", readErr)
	}
	existing, metaErr := fs.Retrieve(msg.ID)
	existingContent, contentErr := fs.RetrieveContent(msg.ID)
	if metaErr == nil {
		if !sameEnqueueMessage(existing, msg) {
			return false, fmt.Errorf("message ID %q conflicts with existing metadata", msg.ID)
		}
		if contentErr == nil {
			if !bytes.Equal(existingContent, content) {
				return false, fmt.Errorf("message ID %q conflicts with existing content", msg.ID)
			}
			return false, nil
		}
		if err := fs.StoreContent(msg.ID, content); err != nil {
			return false, fmt.Errorf("repair missing content: %w", err)
		}
		return false, nil
	}
	if contentErr == nil && !bytes.Equal(existingContent, content) {
		return false, fmt.Errorf("message ID %q has conflicting orphan content", msg.ID)
	}
	if contentErr != nil {
		if err := fs.StoreContent(msg.ID, content); err != nil {
			return false, err
		}
	}
	if err := fs.Store(msg); err != nil {
		return false, err
	}
	return true, nil
}

// RecordEnqueueTombstone is called before deletion, under the same stable per-ID
// lock used by enqueue, so a retry observes either the live entry or its ledger.
func (fs *FileStorageBackend) RecordEnqueueTombstone(msg Message, content []byte) error {
	if err := fs.EnsureDirectories(); err != nil {
		return err
	}
	release, err := acquireEnqueueLock(filepath.Join(fs.queueDir, "tmp", ".enqueue-"+msg.ID))
	if err != nil {
		return err
	}
	defer release()
	return fs.recordEnqueueTombstoneLocked(msg, content)
}

func (fs *FileStorageBackend) recordEnqueueTombstoneLocked(msg Message, content []byte) error {
	payload, err := json.Marshal(enqueueTombstone{Message: msg, Content: content})
	if err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := openChildDir(root, "tmp", false)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := atomicWriteAt(dir, ".consumed-"+msg.ID+".json", payload, 0600); err != nil {
		return fmt.Errorf("publish enqueue tombstone: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync tombstone directory: %w", err)
	}
	return nil
}

func (fs *FileStorageBackend) tombstoneFor(id string) (*enqueueTombstone, error) {
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return nil, fmt.Errorf("open queue root: %w", err)
	}
	defer root.Close()
	dir, err := openChildDir(root, "tmp", false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open tombstone directory: %w", err)
	}
	defer dir.Close()
	raw, err := readFileAt(dir, ".consumed-"+id+".json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read enqueue tombstone: %w", err)
	}
	var tomb enqueueTombstone
	if err := json.Unmarshal(raw, &tomb); err != nil || tomb.Message.ID != id {
		return nil, fmt.Errorf("corrupt enqueue tombstone for %q", id)
	}
	return &tomb, nil
}

func (fs *FileStorageBackend) suppressConsumed(msg Message) error {
	tomb, err := fs.tombstoneFor(msg.ID)
	if err != nil {
		return err
	}
	if tomb == nil {
		return nil
	}
	if !sameEnqueueMessage(tomb.Message, msg) {
		return fmt.Errorf("live message %q conflicts with consumed enqueue identity", msg.ID)
	}
	content, contentErr := fs.RetrieveContent(msg.ID)
	if contentErr == nil && !bytes.Equal(tomb.Content, content) {
		return fmt.Errorf("live message %q conflicts with consumed enqueue content", msg.ID)
	}
	if contentErr != nil && !errors.Is(contentErr, os.ErrNotExist) && !strings.Contains(contentErr.Error(), "no such file") {
		return fmt.Errorf("verify consumed message %q content: %w", msg.ID, contentErr)
	}
	return fmt.Errorf("message not found: %s (consumed)", msg.ID)
}

func messageName(id string) (string, error) {
	if err := validateMessageID(id); err != nil {
		return "", err
	}
	return id + ".json", nil
}

func marshalMessage(msg Message) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}
	return data, nil
}

func decodeMessage(data []byte, id string, q QueueType) (Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	if msg.ID != id || msg.QueueType != q {
		return Message{}, fmt.Errorf("corrupt message metadata identity for %q", id)
	}
	return msg, nil
}

func (fs *FileStorageBackend) Store(msg Message) error {
	if err := validateQueueType(msg.QueueType); err != nil {
		return err
	}
	name, err := messageName(msg.ID)
	if err != nil {
		return err
	}
	data, err := marshalMessage(msg)
	if err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, true)
	if err != nil {
		return fmt.Errorf("failed to open queue root: %w", err)
	}
	defer root.Close()
	dir, err := openChildDir(root, string(msg.QueueType), true)
	if err != nil {
		return fmt.Errorf("failed to open queue directory: %w", err)
	}
	defer dir.Close()
	if err := atomicWriteAt(dir, name, data, 0600); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}
	return nil
}

func (fs *FileStorageBackend) Update(msg Message) error {
	if err := validateQueueType(msg.QueueType); err != nil {
		return err
	}
	name, err := messageName(msg.ID)
	if err != nil {
		return err
	}
	data, err := marshalMessage(msg)
	if err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return fmt.Errorf("failed to open queue root: %w", err)
	}
	defer root.Close()
	dir, err := openChildDir(root, string(msg.QueueType), false)
	if err != nil {
		return fmt.Errorf("failed to open queue directory: %w", err)
	}
	defer dir.Close()
	if err := atomicWriteAt(dir, name, data, 0600); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}
	return nil
}

func readMessageAt(dir *os.File, name, id string, q QueueType) (Message, error) {
	data, err := readFileAt(dir, name)
	if err != nil {
		return Message{}, err
	}
	return decodeMessage(data, id, q)
}

func (fs *FileStorageBackend) Retrieve(id string) (Message, error) {
	name, err := messageName(id)
	if err != nil {
		return Message{}, err
	}
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return Message{}, fmt.Errorf("failed to open queue root: %w", err)
	}
	defer root.Close()
	for _, q := range []QueueType{Active, Deferred, Hold, Failed} {
		dir, e := openChildDir(root, string(q), false)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return Message{}, fmt.Errorf("failed to open queue directory: %w", e)
		}
		msg, e := readMessageAt(dir, name, id, q)
		dir.Close()
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return Message{}, fmt.Errorf("failed to read message file: %w", e)
		}
		if e := fs.suppressConsumed(msg); e != nil {
			return Message{}, e
		}
		return msg, nil
	}
	return Message{}, fmt.Errorf("message not found: %s", id)
}

func deleteAt(dir *os.File, name string, missingOK bool) error {
	err := unlinkFileAt(dir, name)
	if missingOK && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (fs *FileStorageBackend) deleteInQueue(root *os.File, q QueueType, id string) error {
	name, err := messageName(id)
	if err != nil {
		return err
	}
	dir, err := openChildDir(root, string(q), false)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := deleteAt(dir, name, false); err != nil {
		return fmt.Errorf("failed to delete message file: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("failed to sync queue directory: %w", err)
	}
	return nil
}

func (fs *FileStorageBackend) Delete(id string) error {
	if err := validateMessageID(id); err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return fmt.Errorf("failed to open queue root: %w", err)
	}
	defer root.Close()
	for _, q := range []QueueType{Active, Deferred, Hold, Failed} {
		err = fs.deleteInQueue(root, q, id)
		if err == nil {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return err
	}
	return fmt.Errorf("message not found: %s", id)
}

func listAt(dir *os.File, q QueueType) ([]Message, error) {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}
	messages := make([]Message, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if err := validateMessageID(id); err != nil {
			return nil, fmt.Errorf("corrupt queue filename %q: %w", name, err)
		}
		// Do not trust d_type (it may be DT_UNKNOWN): open with O_NOFOLLOW and
		// verify the opened descriptor is a regular file.
		data, err := readFileAt(dir, name)
		if err != nil {
			return nil, fmt.Errorf("failed to read queue entry %q: %w", name, err)
		}
		msg, err := decodeMessage(data, id, q)
		if err != nil {
			return nil, fmt.Errorf("corrupt queue entry %q: %w", name, err)
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

func (fs *FileStorageBackend) List(q QueueType) ([]Message, error) {
	if err := validateQueueType(q); err != nil {
		return nil, err
	}
	root, err := openRoot(fs.queueDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return []Message{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := openChildDir(root, string(q), false)
	if errors.Is(err, os.ErrNotExist) {
		return []Message{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	messages, err := listAt(dir, q)
	if err != nil {
		return nil, err
	}
	visible := messages[:0]
	for _, msg := range messages {
		err := fs.suppressConsumed(msg)
		if err == nil {
			visible = append(visible, msg)
			continue
		}
		if strings.Contains(err.Error(), "conflicts") || strings.Contains(err.Error(), "corrupt") {
			return nil, err
		}
	}
	return visible, nil
}
func (fs *FileStorageBackend) Count(q QueueType) (int, error) {
	m, err := fs.List(q)
	return len(m), err
}

func (fs *FileStorageBackend) DeleteAll(q QueueType) error {
	if err := validateQueueType(q); err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := openChildDir(root, string(q), false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			if err := deleteAt(dir, entry.Name(), false); err != nil {
				return fmt.Errorf("failed to delete file %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func (fs *FileStorageBackend) Move(id string, from, to QueueType) error {
	if err := validateQueueType(from); err != nil {
		return err
	}
	if err := validateQueueType(to); err != nil {
		return err
	}
	name, err := messageName(id)
	if err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, true)
	if err != nil {
		return err
	}
	defer root.Close()
	fromDir, err := openChildDir(root, string(from), false)
	if err != nil {
		return err
	}
	defer fromDir.Close()
	toDir, err := openChildDir(root, string(to), true)
	if err != nil {
		return err
	}
	defer toDir.Close()
	msg, err := readMessageAt(fromDir, name, id, from)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}
	msg.QueueType = to
	data, err := marshalMessage(msg)
	if err != nil {
		return err
	}
	if err := atomicWriteAt(toDir, name, data, 0600); err != nil {
		return err
	}
	if err := deleteAt(fromDir, name, false); err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}
	return nil
}

func (fs *FileStorageBackend) StoreContent(id string, data []byte) error {
	if err := validateMessageID(id); err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, true)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := openChildDir(root, "data", true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := atomicWriteAt(dir, id, data, 0600); err != nil {
		return fmt.Errorf("failed to write content file: %w", err)
	}
	return nil
}
func (fs *FileStorageBackend) RetrieveContent(id string) ([]byte, error) {
	if err := validateMessageID(id); err != nil {
		return nil, err
	}
	root, err := openRoot(fs.queueDir, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := openChildDir(root, "data", false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	data, err := readFileAt(dir, id)
	if err != nil {
		return nil, fmt.Errorf("failed to read content file: %w", err)
	}
	return data, nil
}
func (fs *FileStorageBackend) DeleteContent(id string) error {
	if err := validateMessageID(id); err != nil {
		return err
	}
	root, err := openRoot(fs.queueDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := openChildDir(root, "data", false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := deleteAt(dir, id, true); err != nil {
		return fmt.Errorf("failed to delete content file: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("failed to sync content directory: %w", err)
	}
	return nil
}

// DeleteMessageWithTombstone enforces the crash ordering: durable tombstone,
// metadata unlink+directory sync, then content unlink+directory sync.
func (fs *FileStorageBackend) DeleteMessageWithTombstone(msg Message, content []byte) error {
	if err := fs.EnsureDirectories(); err != nil {
		return err
	}
	release, err := acquireEnqueueLock(filepath.Join(fs.queueDir, "tmp", ".enqueue-"+msg.ID))
	if err != nil {
		return err
	}
	defer release()
	if err := fs.recordEnqueueTombstoneLocked(msg, content); err != nil {
		return err
	}
	if err := fs.Delete(msg.ID); err != nil && !strings.Contains(err.Error(), "message not found") {
		return err
	}
	return fs.DeleteContent(msg.ID)
}

func (fs *FileStorageBackend) Cleanup(hours int) (int, error) {
	if hours <= 0 {
		return 0, fmt.Errorf("retention hours must be positive")
	}
	root, err := openRoot(fs.queueDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()
	cutoff, deleted := time.Now().Add(-time.Duration(hours)*time.Hour), 0
	for _, q := range []QueueType{Active, Deferred, Hold, Failed} {
		dir, err := openChildDir(root, string(q), false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		messages, err := listAt(dir, q)
		dir.Close()
		if err != nil {
			return deleted, err
		}
		for _, msg := range messages {
			if !msg.CreatedAt.Before(cutoff) {
				continue
			}
			// Delete exactly the queue entry which List validated; never perform an ID-wide search.
			if err := fs.deleteInQueue(root, q, msg.ID); err != nil {
				return deleted, err
			}
			deleted++
			dataDir, e := openChildDir(root, "data", false)
			if e == nil {
				e = deleteAt(dataDir, msg.ID, true)
				dataDir.Close()
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return deleted, fmt.Errorf("failed to delete message content: %w", e)
			}
		}
	}
	return deleted, nil
}

func (fs *FileStorageBackend) EnsureDirectories() error {
	root, err := openRoot(fs.queueDir, true)
	if err != nil {
		return fmt.Errorf("failed to create base queue directory: %w", err)
	}
	defer root.Close()
	for _, name := range []string{string(Active), string(Deferred), string(Hold), string(Failed), "data", "tmp"} {
		dir, err := openChildDir(root, name, true)
		if err != nil {
			return fmt.Errorf("failed to create queue directory %s: %w", name, err)
		}
		dir.Close()
	}
	return nil
}

// writeFileAtomic remains as a package compatibility shim for older tests.
// All production writes use trusted directory descriptors.
//
//nolint:unused
func (fs *FileStorageBackend) writeFileAtomic(_ string, _ []byte, _ os.FileMode) error {
	return fmt.Errorf("path-based atomic writes are disabled")
}
