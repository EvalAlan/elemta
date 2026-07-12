package queue

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestIndexedFSDistinctConcurrentManagersSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			backend := a
			if i%2 != 0 {
				backend = b
			}
			id := fmt.Sprintf("distinct-%03d", i)
			msg := Message{ID: id, QueueType: Active, From: "a", To: []string{"b"}, ReceivedAt: time.Unix(int64(i+1), 0)}
			_, e := backend.CreateMessageIfAbsent(msg, []byte(id))
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := NewIndexedFSStorageBackend(dir, IndexedFSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	count, err := restarted.Count(Active)
	if err != nil || count != n {
		t.Fatalf("count=%d want=%d err=%v", count, n, err)
	}
	list, err := restarted.List(Active)
	if err != nil || len(list) != n {
		t.Fatalf("list=%d want=%d err=%v", len(list), n, err)
	}
}
