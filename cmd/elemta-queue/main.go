package main

import (
	"log/slog"
	"os"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/queue"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "queue-cli")

	configPath := os.Getenv("ELEMTA_CONFIG_PATH")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	queueManager, err := queue.NewManagerFromBackend(
		cfg.Queue.Dir,
		cfg.Queue.Backend,
		queue.SQLiteConfig{
			Path:          cfg.Queue.SQLite.Path,
			BusyTimeoutMS: cfg.Queue.SQLite.BusyTimeoutMS,
			JournalMode:   cfg.Queue.SQLite.JournalMode,
			Synchronous:   cfg.Queue.SQLite.Synchronous,
		},
		cfg.FailedQueueRetentionHours,
	)
	if err != nil {
		logger.Error("Failed to initialize queue manager", "error", err)
		os.Exit(1)
	}
	defer queueManager.Stop()

	if err := queueManager.UpdateStats(); err != nil {
		logger.Error("Failed to update queue stats", "error", err)
		os.Exit(1)
	}

	stats := queueManager.GetStats()
	logger.Info("Queue stats",
		"backend", queueManager.BackendType(),
		"queue_dir", cfg.Queue.Dir,
		"active_count", stats.ActiveCount,
		"deferred_count", stats.DeferredCount,
		"failed_count", stats.FailedCount,
		"hold_count", stats.HoldCount,
		"total_size", stats.TotalSize,
	)

	storage, err := queueManager.GetStorageInfo()
	if err != nil {
		logger.Warn("Failed to fetch storage stats", "error", err)
	} else {
		logger.Info("Queue storage",
			"backend", storage.Backend,
			"total_bytes", storage.TotalBytes,
			"sqlite_path", storage.SQLitePath,
			"db_bytes", storage.DBBytes,
			"wal_bytes", storage.WALBytes,
			"message_rows", storage.MessageRows,
			"content_rows", storage.ContentRows,
			"content_bytes", storage.ContentBytes,
			"file_count", storage.FileCount,
			"metadata_files", storage.MetadataFiles,
			"content_files", storage.ContentFiles,
		)
	}

	logger.Info("Queue status check completed")
}
