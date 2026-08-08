package api

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newLifecycleTestServer() *Server {
	return &Server{listenAddr: "127.0.0.1:0", webRoot: tEmptyWebRoot}
}

const tEmptyWebRoot = ""

func waitReady(t *testing.T, s *Server) string {
	t.Helper()
	select {
	case <-s.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("server did not become ready")
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	require.NotNil(t, s.listener)
	return s.listener.Addr().String()
}

func TestServerLifecycleReadinessAndStopClosesListener(t *testing.T) {
	s := newLifecycleTestServer()
	require.NoError(t, s.Start())
	addr := waitReady(t, s)

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	require.NoError(t, s.Stop())
	conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener remained reachable after Stop returned")
	}
}

// TestServerLifecycleStopClosesListenerBeforeServeIsScheduled pins the race
// that made the test above fail roughly one run in five.
//
// Start hands the listener to http.Server.Serve on a new goroutine, and
// Shutdown only closes listeners Serve has already registered. A Stop that
// landed before that goroutine was scheduled therefore had nothing to close
// and returned while the port was still accepting connections. Stopping
// immediately, with no chance for the goroutine to run, reproduces it.
func TestServerLifecycleStopClosesListenerBeforeServeIsScheduled(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := newLifecycleTestServer()
		require.NoError(t, s.Start())

		s.lifecycleMu.Lock()
		ln := s.listener
		s.lifecycleMu.Unlock()
		require.NotNil(t, ln)
		addr := ln.Addr().String()

		require.NoError(t, s.Stop())

		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatalf("iteration %d: listener on %s still accepting after Stop returned", i, addr)
		}
	}
}

func TestServerLifecycleConcurrentStartIsDeterministic(t *testing.T) {
	s := newLifecycleTestServer()
	const callers = 12
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Start() }()
	}
	wg.Wait()
	close(errs)

	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, ErrServerAlreadyStarted)
		}
	}
	require.Equal(t, 1, successes)
	waitReady(t, s)
	require.NoError(t, s.Stop())
}

func TestServerLifecycleStopDuringStartWaitsForStartupContinuation(t *testing.T) {
	s := newLifecycleTestServer()
	entered, release := make(chan struct{}), make(chan struct{})
	s.listenerFactory = func() (net.Listener, error) {
		close(entered)
		<-release
		return net.Listen("tcp", "127.0.0.1:0")
	}

	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()
	<-entered

	stopErr := make(chan error, 1)
	go func() { stopErr <- s.Stop() }()
	select {
	case <-stopErr:
		t.Fatal("Stop returned while startup could still publish a listener")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-stopErr)
	require.ErrorIs(t, <-startErr, ErrServerStopped)

	select {
	case <-s.Ready():
		t.Fatal("a cancelled startup published readiness")
	default:
	}
	s.lifecycleMu.Lock()
	require.Nil(t, s.listener)
	s.lifecycleMu.Unlock()
}

func TestServerLifecycleConcurrentStopIsIdempotent(t *testing.T) {
	s := newLifecycleTestServer()
	require.NoError(t, s.Start())
	waitReady(t, s)

	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Stop() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, s.Stop())
}

func TestServerLifecycleFailedListenerFactoryStopsRateLimiter(t *testing.T) {
	s := newLifecycleTestServer()
	s.rateLimiter = NewRateLimitMiddleware(RateLimitConfig{Enabled: true})
	wantErr := errors.New("listener unavailable")
	s.listenerFactory = func() (net.Listener, error) { return nil, wantErr }

	err := s.Start()
	require.ErrorIs(t, err, wantErr)
	select {
	case <-s.rateLimiter.cleanupDone:
	default:
		t.Fatal("Start returned before rate limiter cleanup completed")
	}
	require.NoError(t, s.Stop())
}

func TestServerLifecycleConcurrentStopIsCompletionBarrier(t *testing.T) {
	s := newLifecycleTestServer()
	s.rateLimiter = NewRateLimitMiddleware(RateLimitConfig{Enabled: true})
	cleanupEntered := make(chan struct{})
	releaseCleanup := make(chan struct{})
	s.rateLimiter.beforeCleanupDone = func() {
		close(cleanupEntered)
		<-releaseCleanup
	}
	require.NoError(t, s.Start())
	waitReady(t, s)

	const callers = 16
	returned := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() { returned <- s.Stop() }()
	}
	<-cleanupEntered
	select {
	case err := <-returned:
		t.Fatalf("Stop returned before cleanup completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseCleanup)
	for i := 0; i < callers; i++ {
		require.NoError(t, <-returned)
	}
	select {
	case <-s.rateLimiter.cleanupDone:
	default:
		t.Fatal("all Stop calls returned before rate limiter cleanup completed")
	}
}

func TestServerLifecycleConcurrentStartStopStress(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := newLifecycleTestServer()
		startErr := make(chan error, 1)
		go func() { startErr <- s.Start() }()
		require.NoError(t, s.Stop())
		err := <-startErr
		require.True(t, err == nil || errors.Is(err, ErrServerStopped), "unexpected Start error: %v", err)
		require.NoError(t, s.Stop())
	}
}
