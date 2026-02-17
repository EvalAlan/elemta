# Elemta Development Quick Start Checklist

**Last Updated:** 2026-02-15

---

## 🔴 CRITICAL - Fix First (Week 1)

### Day 1-2: Debug Relay Permission Logic
- [ ] Add debug logging to `internal/smtp/session_commands.go:899` (`isLocalDomain()`)
- [ ] Verify `config.LocalDomains` is passed to CommandHandler (`internal/smtp/session.go:127-128`)
- [ ] Test recipient email parsing (@ split logic)
- [ ] Direct SMTP connection testing with local domain
- [ ] Run failing tests: `go test ./tests/integration -run TestIntegration_BasicSMTPFlow -v`
- [ ] Run failing tests: `go test ./tests -run TestSMTP_DomainHandling -v`
- [ ] **Goal:** Identify root cause

### Day 3-4: Fix Relay Permission Logic
- [ ] Implement fix based on root cause
- [ ] Update `isLocalDomain()` function
- [ ] Verify all 10 skipped tests now pass
- [ ] Remove `testing.Short()` skip conditions
- [ ] Run full test suite: `go test ./...` (without `-short`)
- [ ] **Goal:** All tests passing (0 skipped)

### Day 5: Security Fixes - Cryptography
- [ ] Replace SHA1 with bcrypt in `internal/auth/auth.go:220,250,276`
- [ ] Remove/replace MD5 in `internal/smtp/session_data.go:8`
- [ ] Update authentication tests
- [ ] Run security scan: `gosec ./...`
- [ ] **Goal:** No weak crypto in codebase

### Day 6: Security Fixes - TLS Hardening
- [ ] Set `ReadHeaderTimeout: 10*time.Second` in `internal/smtp/metrics.go:222`
- [ ] Set `ReadHeaderTimeout: 10*time.Second` in `internal/smtp/tls.go:446`
- [ ] Enforce `MinVersion: tls.VersionTLS12` in `internal/smtp/tls_security.go:93`
- [ ] Set file permissions to 0600 in `internal/message/message.go:62,92`
- [ ] Run security scan: `gosec ./...`
- [ ] **Goal:** Zero HIGH/CRITICAL security warnings

### Day 7: Validation & Documentation
- [ ] Run full test suite: `make test`
- [ ] Run Docker integration tests: `make test-docker`
- [ ] Run linter: `make lint`
- [ ] Update PROGRESS.md with latest fixes
- [ ] Update docs/troubleshooting.md (add relay permission section)
- [ ] **Goal:** Week 1 deliverable complete

---

## 🟠 HIGH PRIORITY (Week 2)

### Integration Test Infrastructure
- [ ] Auto-generate test TLS certificates in `setupIntegrationServer()`
- [ ] Mock LDAP datasource for auth tests
- [ ] Fix integration test server startup issues
- [ ] Verify all 8 integration tests pass:
  - [ ] TestIntegration_BasicSMTPFlow
  - [ ] TestIntegration_ConcurrentConnections
  - [ ] TestIntegration_AuthenticationFlow
  - [ ] TestIntegration_TLSFlow
  - [ ] TestIntegration_ErrorRecovery
  - [ ] TestIntegration_LargeMessages
  - [ ] TestIntegration_PersistentConnection
  - [ ] TestIntegration_TimeoutHandling
- [ ] Run: `go test ./tests/integration -v`
- [ ] **Goal:** Full integration test suite passing

### Security Audit
- [ ] Run full gosec scan: `gosec -fmt=json -out=security-report.json ./...`
- [ ] Review all security warnings
- [ ] Fix remaining HIGH/MEDIUM issues
- [ ] Document any accepted risks
- [ ] **Goal:** Security audit clean

---

## 🟡 MEDIUM PRIORITY (Week 3+)

### DSN Bounce Generation (5-7 days)
- [ ] Create `internal/queue/dsn_generator.go`
- [ ] Read DSN params from queue annotations (RET, ENVID, NOTIFY, ORCPT)
- [ ] Generate RFC 3461-compliant bounce messages
- [ ] Deliver to envelope sender
- [ ] Create tests: `tests/dsn_bounce_test.go`
- [ ] Update docs/rfc-compliance.md (mark as fully implemented)
- [ ] **Goal:** Full DSN implementation

### REQUIRETLS Delivery Enforcement (3-4 days)
- [ ] Read REQUIRETLS annotation from queue
- [ ] Require TLS for downstream connections when set
- [ ] Return 530 error if TLS cannot be established
- [ ] Update `internal/delivery/smtp_delivery.go`
- [ ] Create tests: `tests/requiretls_delivery_test.go`
- [ ] Update docs/rfc-compliance.md (mark as fully implemented)
- [ ] **Goal:** Full REQUIRETLS implementation

### Database Queue Backend (5-7 days)
- [ ] Create `internal/queue/database_backend.go`
- [ ] Implement PostgreSQL support
- [ ] Implement MySQL support
- [ ] Add config option: `queue_backend: "database"` vs `"file"`
- [ ] Implement migration from file-based to DB-based
- [ ] Create tests: `tests/database_queue_test.go`
- [ ] Update documentation
- [ ] **Goal:** Scalable database queue backend

---

## 📋 Quick Commands

### Testing
```bash
# RFC 5321 compliance (should all pass)
go test ./tests -run TestRFC5321 -v

# Unit tests only (fast)
go test ./internal/smtp -short

# Full test suite (includes integration)
go test ./...

# Docker integration tests
make test-docker

# Specific failing test
go test ./tests/integration -run TestIntegration_BasicSMTPFlow -v
go test ./tests -run TestSMTP_DomainHandling -v
```

### Security
```bash
# Security scan
gosec ./...

# With JSON output
gosec -fmt=json -out=security-report.json ./...

# Linting
golangci-lint run --timeout=5m
make lint
```

### Development
```bash
# Build
go build -o elemta cmd/elemta/main.go

# Run
./elemta -config config/elemta.yaml

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f elemta
```

### Git
```bash
# Check status
git status
git log --oneline -5

# Current branch
git branch

# Create feature branch
git checkout -b fix/relay-permission-logic
```

---

## 🎯 Success Criteria

### Week 1 Complete
- ✅ Relay permission logic working
- ✅ All tests passing (0 skipped)
- ✅ Zero weak crypto (SHA1/MD5 removed)
- ✅ TLS hardened (1.2+, ReadHeaderTimeout set)
- ✅ Zero HIGH/CRITICAL security warnings

### Week 2 Complete
- ✅ Integration tests passing (8/8)
- ✅ Security audit clean
- ✅ Documentation updated

### Ready for Production
- ✅ All tests passing
- ✅ Security scan clean
- ✅ Performance baseline established
- ✅ Staging deployment successful
- ✅ Documentation complete

---

## 📚 Key Files to Know

### Critical Files (Fix First)
- `internal/smtp/session_commands.go:899-917` - Relay permission logic (BROKEN)
- `internal/auth/auth.go:220,250,276` - Password hashing (WEAK CRYPTO)
- `internal/smtp/session_data.go:8` - MD5 import (WEAK CRYPTO)
- `internal/smtp/metrics.go:222` - Missing ReadHeaderTimeout
- `internal/smtp/tls.go:446` - Missing ReadHeaderTimeout
- `internal/smtp/tls_security.go:93` - TLS MinVersion too low

### Architecture Files (Main Loop)
- `internal/smtp/session.go` - Main session handler (refactored)
- `internal/smtp/session_state.go` - State machine
- `internal/smtp/session_commands.go` - Command handlers
- `internal/smtp/session_auth.go` - Authentication handler
- `internal/smtp/session_data.go` - Data/message handler

### Test Files
- `tests/rfc5321_test.go` - RFC 5321 compliance tests
- `tests/integration/smtp_flow_test.go` - Integration tests (SKIPPED)
- `tests/smtp_functional_test.go` - Functional tests
- `internal/smtp/session_commands_test.go` - Command handler tests

### Documentation
- `docs/rfc-compliance.md` - RFC compliance status
- `docs/production-deployment.md` - Production deployment guide
- `PROGRESS.md` - Development progress log
- `TASKS.md` - Development tasks tracker
- `STRATEGIC_ROADMAP.md` - Long-term strategic plan (NEW)

---

## 🚨 Known Issues

### CRITICAL
1. **Relay Permission Logic Broken**
   - `isLocalDomain()` returns false for configured local domains
   - Blocks 10 tests
   - **Must fix before production**

### HIGH
2. **Weak Cryptography**
   - SHA1 password hashing vulnerable to cracking
   - MD5 imported (may be unused)

3. **TLS Security**
   - Missing ReadHeaderTimeout (Slowloris vulnerability)
   - TLS MinVersion too low (allows TLS 1.0/1.1)

4. **Integration Tests Disabled**
   - 8 tests skipped due to infrastructure issues
   - Missing TLS certs, LDAP mock

### MEDIUM
5. **DSN Bounces Not Generated**
   - Parameters parsed but no bounce messages sent

6. **REQUIRETLS Not Enforced on Delivery**
   - Parsed at submission, ignored on delivery

---

## 💡 Tips

1. **Always run tests after changes:**
   ```bash
   go test ./tests -run TestRFC5321 -v
   ```

2. **Use make commands for consistency:**
   ```bash
   make test
   make lint
   make build
   ```

3. **Check git status before commits:**
   ```bash
   git status
   git diff
   ```

4. **Follow conventional commit format:**
   ```
   fix(smtp): fix relay permission logic for local domains
   feat(queue): add PostgreSQL queue backend
   docs(readme): update installation instructions
   test(smtp): add relay permission tests
   ```

5. **Document TODOs with context:**
   ```go
   // TODO(relay): Fix isLocalDomain() to check config.LocalDomains
   // Current behavior incorrectly rejects local domains
   ```

---

**Ready to start? Begin with Week 1, Day 1-2: Debug Relay Permission Logic**

See `STRATEGIC_ROADMAP.md` for full detailed plan.
