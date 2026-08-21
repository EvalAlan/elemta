# High-Volume Backend Baseline (Task 1)

Date: 2026-05-27T21:00:44+00:00

## Environment

- Host: `Linux docker01 5.14.0-611.55.1.el9_7.aarch64`
- Arch: `linux/arm64`
- Go: `go version go1.25.9 (Red Hat 1.25.9-1.el9_7) linux/arm64`
- Package: `github.com/EvalAlan/elemta/internal/queue`

## Command

```bash
go test ./internal/queue \
  -run '^$' \
  -bench 'BenchmarkFileBackend(Enqueue_16KB|ListActive_1K|ListActive_10K|ListActive_50K|MoveActiveToDeferred|RetrieveByID)$' \
  -benchmem -benchtime=1x -count=1
```

## Results

```text
BenchmarkFileBackendEnqueue_16KB-4                 1   19,768,071 ns/op      32,296 B/op        347 allocs/op
BenchmarkFileBackendListActive_1K-4                1   20,231,034 ns/op   2,284,088 B/op     22,027 allocs/op
BenchmarkFileBackendListActive_10K-4               1  183,745,722 ns/op  23,001,528 B/op    220,033 allocs/op
BenchmarkFileBackendListActive_50K-4               1  891,852,882 ns/op 115,949,720 B/op  1,100,038 allocs/op
BenchmarkFileBackendMoveActiveToDeferred-4         1    4,728,276 ns/op      15,224 B/op        135 allocs/op
BenchmarkFileBackendRetrieveByID-4                 1       76,601 ns/op       2,168 B/op         23 allocs/op
```

## Notes

- Benchmarks were run with `-benchtime=1x` to force single-iteration baseline snapshots and avoid very long runtime on large queue depths.
- Existing file backend emits per-enqueue logs by default; benchmark code suppresses slog output to avoid contaminating results.
- `ListActive_*` cost grows steeply with queue depth (directory scan + JSON unmarshal + in-memory sort), which validates the need for an index-backed backend.
