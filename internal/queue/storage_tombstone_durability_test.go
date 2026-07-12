package queue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func crashDurabilityMessage(id string) Message {
	return Message{ID: id, QueueType: Active, From: "a@test", To: []string{"b@test"}, Size: 4, Priority: PriorityHigh, ReceivedAt: time.Unix(1, 0).UTC()}
}

func writeCrashTombstone(t *testing.T, dir string, msg Message, content []byte) {
	t.Helper()
	payload, err := json.Marshal(enqueueTombstone{Message: msg, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tmp", ".consumed-"+msg.ID+".json"), payload, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFileTombstoneCrashStatesFailClosedAcrossReopen(t *testing.T) {
	t.Run("partial temp is never visible", func(t *testing.T) {
		dir := t.TempDir()
		fs := NewFileStorageBackend(dir)
		msg := crashDurabilityMessage("partial")
		if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tmp", ".tmp_interrupted"), []byte(`{"message":`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStorageBackend(dir).Retrieve(msg.ID); err != nil {
			t.Fatalf("unpublished temporary tombstone affected live message: %v", err)
		}
	})

	t.Run("durable tombstone wins before unlinks", func(t *testing.T) {
		dir := t.TempDir()
		fs := NewFileStorageBackend(dir)
		msg := crashDurabilityMessage("covered")
		if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
			t.Fatal(err)
		}
		if err := fs.RecordEnqueueTombstone(msg, []byte("body")); err != nil {
			t.Fatal(err)
		}
		reopened := NewFileStorageBackend(dir)
		if _, err := reopened.Retrieve(msg.ID); err == nil || !strings.Contains(err.Error(), "consumed") {
			t.Fatalf("covered live message was not suppressed: %v", err)
		}
		listed, err := reopened.List(Active)
		if err != nil || len(listed) != 0 {
			t.Fatalf("covered live message listed: %#v, %v", listed, err)
		}
	})

	for _, tc := range []struct {
		name string
		make func(t *testing.T, dir string, msg Message)
	}{
		{"corrupt", func(t *testing.T, dir string, msg Message) {
			if err := os.WriteFile(filepath.Join(dir, "tmp", ".consumed-"+msg.ID+".json"), []byte(`{"message":`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"conflicting", func(t *testing.T, dir string, msg Message) {
			other := msg
			other.From = "other@test"
			writeCrashTombstone(t, dir, other, []byte("body"))
		}},
	} {
		t.Run(tc.name+" tombstone quarantines live entry", func(t *testing.T) {
			dir := t.TempDir()
			fs := NewFileStorageBackend(dir)
			msg := crashDurabilityMessage(tc.name)
			if _, err := fs.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
				t.Fatal(err)
			}
			tc.make(t, dir, msg)
			reopened := NewFileStorageBackend(dir)
			if _, err := reopened.Retrieve(msg.ID); err == nil {
				t.Fatal("retrieve did not fail closed")
			}
			if _, err := reopened.List(Active); err == nil {
				t.Fatal("list did not fail closed")
			}
		})
	}
}

func TestIndexedFSTombstoneCrashBeforeUnlinkAndIndexUpdate(t *testing.T) {
	dir := t.TempDir()
	b, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{RecoveryOnStartup: true})
	if err != nil {
		t.Fatal(err)
	}
	msg := crashDurabilityMessage("indexed-covered")
	if _, err := b.CreateMessageIfAbsent(msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	// Simulate power loss after the tombstone directory sync, before either
	// queue unlink and before index removal.
	if err := b.RecordEnqueueTombstone(msg, []byte("body")); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{RecoveryOnStartup: true})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := reopened.List(Active)
	if err != nil || len(listed) != 0 {
		t.Fatalf("recovered index exposed consumed live entry: %#v, %v", listed, err)
	}
	state, err := reopened.loadIndexSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Messages[msg.ID]; ok {
		t.Fatal("rebuild retained tombstoned entry")
	}
}
