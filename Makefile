.PHONY: all help build clean clean-certs certs install install-dev install-dev-full install-dev-postgres \
	configure-queue-backend configure-plugins bootstrap-admin reset-admin-password ensure-dev-certs ensure-dev-env refresh-dev-env print-dev-summary check-tools \
	uninstall run test test-load test-race-smoke test-docker up down down-volumes restart logs logs-elemta status \
	rebuild rebuild-dev docker docker-build docker-run docker-stop docker-setup docker-down update lint lint-fix fmt

# Core paths/config
COMPOSE_FILE ?= deployments/compose/docker-compose.yml
DEV_ENV_FILE ?= .env
DEV_MIN_SERVICES ?= elemta elemta-web elemta-dovecot elemta-ldap valkey

# Development TLS certificate.
#
# Seven days on purpose. The dashboard warns below fourteen, so a dev stack sits
# permanently inside the warning window — which means the expiry panel is
# exercised every day rather than being a code path nobody sees until a real
# certificate runs out. Override with CERT_DAYS for a longer-lived one.
CERT_DAYS ?= 7

# Plugins enabled by a development deploy. A stack with everything switched off
# exercises none of it, so the first sign a plugin is broken would be someone
# turning it on in production. Override individually: make install-dev PLUGIN_RBL=off
PLUGIN_RATE_LIMITER ?= on
PLUGIN_CLAMAV ?= on
PLUGIN_RSPAMD ?= on
PLUGIN_ACCESS_CONTROL ?= on
PLUGIN_RBL ?= on
PLUGIN_MASS_MAILER ?= on

# The dashboard's first account.
#
# The password is generated rather than fixed. A well-known default on a service
# that can flush queues and send bulk mail is a bad thing to have on a laptop
# and a worse thing to have on a host somebody exposed by accident. Override
# with ADMIN_PASSWORD to choose your own.
ADMIN_USER ?= admin
ADMIN_PASSWORD ?=

# Queue backend config
QUEUE_BACKEND ?= sqlite
QUEUE_POSTGRES_DSN ?= postgres://elemta:elemta@elemta-postgres:5432/elemta_queue?sslmode=disable
POSTGRES_CONTAINER_NAME ?= elemta-postgres
POSTGRES_USER ?= elemta
POSTGRES_PASSWORD ?= elemta
POSTGRES_DB ?= elemta_queue
POSTGRES_VOLUME ?= elemta_pg

# Default target
all: build

# Help target
help:
	@echo "Elemta - High Performance SMTP Server"
	@echo ""
	@echo "⚡ Quick Start:"
	@echo "  make install-dev              # Minimal dev stack, plugins on, prints a dashboard login"
	@echo "  make install-dev-full         # Everything, incl. ClamAV, Rspamd, Roundcube"
	@echo "  make install-dev-postgres     # Dev stack with a Postgres queue"
	@echo "  make install                  # Interactive production setup"
	@echo ""
	@echo "🔑 Accounts & Access:"
	@echo "  Web UI            http://localhost:8025  (login required — there is no guest access)"
	@echo "  bootstrap-admin       - Create the dashboard account; prints the password once"
	@echo "  reset-admin-password  - Generate and print a new password for it"
	@echo "                          ADMIN_USER=name ADMIN_PASSWORD=secret to choose your own"
	@echo "  The dashboard login is NOT the mailbox login. Mailbox users live in LDAP;"
	@echo "  the dashboard account lives in the users file and is managed with:"
	@echo "    docker exec -it elemta-web /app/elemta --config /app/runtime-config/elemta.toml \\"
	@echo "      user list|add|passwd|remove --file /app/runtime-config/users.json"
	@echo "  A running server reads that file at startup, so restart elemta-web after changing it."
	@echo ""
	@echo "🐳 Services:"
	@echo "  up             - Start services (requires .env)"
	@echo "  down           - Stop services, keep volumes"
	@echo "  down-volumes   - Stop services and DELETE volumes (queue, config and login all go)"
	@echo "  restart        - Restart all services"
	@echo "  rebuild        - Rebuild images and restart"
	@echo "  rebuild-dev    - Quick rebuild (dev only, skips cert check)"
	@echo "  status         - Show service status"
	@echo "  logs           - Follow all logs        logs-elemta - Elemta SMTP logs only"
	@echo ""
	@echo "⚙️  Configuration:"
	@echo "  configure-plugins        - Apply the PLUGIN_* settings below to config/elemta.toml"
	@echo "  configure-queue-backend  - Set the queue backend (QUEUE_BACKEND=file|sqlite|postgres)"
	@echo "  refresh-dev-env          - Refresh backend/compose keys in .env"
	@echo "  certs / clean-certs      - Generate or remove the dev TLS certificate"
	@echo ""
	@echo "🔧 Build & Test:"
	@echo "  build          - Build all binaries (server, queue, cli)   clean - Remove artifacts"
	@echo "  test           - Go unit tests            test-docker    - Integration suite"
	@echo "  test-load      - SMTP load tests          test-race-smoke - Session race checks"
	@echo "  test-auth      - Authentication tests     test-security  - Security tests"
	@echo "  lint / lint-fix / fmt   - Code quality"
	@echo ""
	@echo "🎛️  Variables (override on the command line):"
	@echo "  ADMIN_USER=admin              Dashboard account name"
	@echo "  ADMIN_PASSWORD=               Dashboard password (generated when empty)"
	@echo "  CERT_DAYS=$(CERT_DAYS)                  Dev certificate lifetime, in days"
	@echo "  QUEUE_BACKEND=$(QUEUE_BACKEND)         file | sqlite | postgres"
	@echo "  PLUGIN_RATE_LIMITER=$(PLUGIN_RATE_LIMITER)      PLUGIN_CLAMAV=$(PLUGIN_CLAMAV)   PLUGIN_RSPAMD=$(PLUGIN_RSPAMD)"
	@echo "  PLUGIN_ACCESS_CONTROL=$(PLUGIN_ACCESS_CONTROL)    PLUGIN_RBL=$(PLUGIN_RBL)      PLUGIN_MASS_MAILER=$(PLUGIN_MASS_MAILER)"
	@echo "    e.g. make install-dev PLUGIN_RBL=off CERT_DAYS=90"
	@echo ""
	@echo "💡 Things that surprise people:"
	@echo "  • Editing config/elemta.toml does not change a running stack. The services read a"
	@echo "    copy on a shared volume, seeded once, because the web UI writes to it too."
	@echo "    'make install-dev' re-seeds from the file; 'up' and 'restart' do not."
	@echo "  • Scanner, allow/deny and blocklist changes apply on their own within ~5 seconds —"
	@echo "    no restart. Listen address, size limits, timeouts and the queue backend do need"
	@echo "    a restart, and the reload log says so."
	@echo "  • The dev TLS certificate expires in $(CERT_DAYS) days on purpose, so the expiry warning on"
	@echo "    the Health page is exercised. It is regenerated when it lapses."
	@echo "  • The dev stack is self-signed and binds 0.0.0.0. Fine on a laptop; bind 127.0.0.1"
	@echo "    in the compose file if the machine is not isolated."
	@echo "  • The RBL plugin ships in tag mode (adds a header, refuses nothing). Turn on"
	@echo "    'Refuse listed senders' in Settings once you trust what it is flagging."

build:
	@echo "Building elemta server and utilities..."
	go build -o bin/elemta ./cmd/elemta
	go build -o bin/elemta-queue ./cmd/elemta-queue
	go build -o bin/elemta-cli ./cmd/elemta-cli
	@echo "Build complete."

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	@echo "Clean complete."

clean-certs:
	@echo "Removing test TLS certificates..."
	@rm -f config/test.crt config/test.key
	@echo "Test certificates removed"

certs:
	@echo "🔐 Generating self-signed TLS certificates..."
	@if ! command -v openssl >/dev/null 2>&1; then \
		echo "❌ Error: openssl not found. Please install openssl first."; \
		exit 1; \
	fi
	@openssl req -x509 -newkey rsa:4096 -nodes \
		-keyout config/test.key \
		-out config/test.crt \
		-days $(CERT_DAYS) \
		-subj '/CN=mail.dev.evil-admin.com/O=Elemta Dev/C=US' \
		-addext 'subjectAltName=DNS:mail.dev.evil-admin.com,DNS:*.dev.evil-admin.com' 2>/dev/null
	@chmod 600 config/test.key
	@chmod 644 config/test.crt
	@echo "✅ TLS certificates generated at config/test.{crt,key} (valid $(CERT_DAYS) days)"

# Install targets
install-bin: build
	@echo "Installing elemta server and utilities..."
	cp bin/elemta $(GOPATH)/bin/
	cp bin/elemta-queue $(GOPATH)/bin/
	cp bin/elemta-cli $(GOPATH)/bin/
	@echo "Install complete."

# Local server run (for debugging outside Docker)
run: build
	@echo "Running Elemta server locally (not in Docker)..."
	@echo "⚠️  For normal use, run: make up"
	./bin/elemta server --dev

# Test targets
test:
	@echo "Running Go tests..."
	@echo "⚠️  Note: Some packages require Docker services to be running"
	@echo "For complete integration tests, run: make test-docker"
	@go test -v -short -timeout 60s ./internal/antispam ./internal/api ./internal/auth ./internal/cache ./internal/context ./internal/datasource ./internal/delivery ./internal/plugin ./internal/queue 2>&1; \
	status=$$?; \
	echo ""; \
	if [ $$status -eq 0 ]; then \
		echo "✅ All unit tests passed"; \
	else \
		echo "⚠️  Some unit tests failed (exit code: $$status)"; \
		echo "Note: Integration tests may require Docker services"; \
	fi; \
	echo "💡 Run 'make test-docker' for full integration test suite (21 tests)"; \
	exit $$status

test-centralized:
	@echo "Running centralized test suite..."
	./tests/run_centralized_tests.sh

init-test-env:
	@echo "🔧 Initializing test environment..."
	@./scripts/init-ldap-users.sh
	@echo "✅ Test environment ready"

test-docker: init-test-env
	@echo "Running Docker deployment tests..."
	./tests/run_centralized_tests.sh --deployment docker-dev

test-auth: ## Quick authentication test
	@echo "Running authentication test..."
	./install/test-auth.sh

test-security:
	@echo "Running security tests..."
	./tests/run_centralized_tests.sh --category security

test-load:
	@echo "Running SMTP load tests..."
	@echo "⚠️  Note: Requires Docker services running (make docker-setup)"
	python3 tests/performance/smtp_load_test.py

test-race-smoke:
	@echo "Running targeted SMTP/session race smoke checks..."
	go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'
	go test ./tests/integration -race -run 'TestIntegration_PersistentConnection|TestIntegration_TimeoutHandling'

test-all: test test-centralized
	@echo "All tests completed."

# Code quality targets
lint:
	@echo "Running golangci-lint..."
	@echo "ℹ️  Run this before committing to catch lint errors early"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./cmd/... ./internal/... --timeout=10m; \
	else \
		echo "⚠️  golangci-lint not installed. Install with:"; \
		echo "    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./cmd/... ./internal/... --fix --timeout=10m; \
	else \
		echo "⚠️  golangci-lint not installed"; \
		exit 1; \
	fi

fmt:
	@echo "Formatting Go code..."
	@go fmt ./...
	@echo "Running goimports..."
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "⚠️  goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# Docker targets
docker: docker-build up

docker-build:
	@echo "Building Docker image..."
	docker compose -f $(COMPOSE_FILE) build

# Advanced/internal targets (not shown in help)

# Legacy CLI targets (cli tools built by main 'build' target)
cli-install: build
	@echo "Installing elemta-cli to $(GOPATH)/bin..."
	@cp bin/elemta-cli $(GOPATH)/bin/ 2>/dev/null || echo "⚠️  GOPATH not set, skipping install"

# Legacy docker targets (use 'up'/'down' instead)
docker-run: up
docker-stop: down

# Kibana setup targets
setup-kibana:
	@echo "🔧 Setting up Kibana data views..."
	./scripts/setup-kibana-data-views.sh

configure-queue-backend:
	@echo "⚙️  Configuring queue backend: $(QUEUE_BACKEND)"
	@if [ "$(QUEUE_BACKEND)" != "file" ] && [ "$(QUEUE_BACKEND)" != "sqlite" ] && [ "$(QUEUE_BACKEND)" != "postgres" ]; then \
		echo "❌ Invalid QUEUE_BACKEND='$(QUEUE_BACKEND)'. Use file|sqlite|postgres"; \
		exit 1; \
	fi
	@python3 ./scripts/configure_queue_backend.py "$(QUEUE_BACKEND)" "$(QUEUE_POSTGRES_DSN)" "config/elemta.toml"
	@if [ "$(QUEUE_BACKEND)" = "postgres" ]; then \
		echo "ℹ️  Postgres backend selected. Ensure DSN is reachable:"; \
		echo "   $(QUEUE_POSTGRES_DSN)"; \
	fi

configure-plugins:
	@echo "🔌 Configuring plugins for this deployment"
	@python3 ./scripts/configure_plugins.py config/elemta.toml \
		rate_limiter=$(PLUGIN_RATE_LIMITER) \
		clamav=$(PLUGIN_CLAMAV) \
		rspamd=$(PLUGIN_RSPAMD) \
		access_control=$(PLUGIN_ACCESS_CONTROL) \
		rbl=$(PLUGIN_RBL) \
		mass_mailer=$(PLUGIN_MASS_MAILER)

# Create the dashboard's first account, once. The users file lives on the
# runtime volume, so this runs inside the container: it has to be written by the
# user that reads it, and the host cannot write there.
bootstrap-admin:
	@# Whether an *account* exists, not whether the file does: the runtime setup
	@# leaves an empty `{}` there so the service can start locked, and testing
	@# for the file would read that as an account and skip the bootstrap.
	@needs_account=1; \
	if docker exec elemta-web test -e /app/runtime-config/users.json 2>/dev/null; then \
		if ! docker exec elemta-web /app/elemta --config /app/runtime-config/elemta.toml \
			user list --file /app/runtime-config/users.json 2>/dev/null | grep -q '^No users'; then \
			needs_account=0; \
		fi; \
	fi; \
	if [ "$$needs_account" = "0" ]; then \
		echo "ℹ️  Dashboard account already exists (make reset-admin-password to change it)"; \
	else \
		PW="$(ADMIN_PASSWORD)"; \
		if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
		if printf '%s\n' "$$PW" | docker exec -i elemta-web /app/elemta --config /app/runtime-config/elemta.toml \
			user add $(ADMIN_USER) --file /app/runtime-config/users.json >/dev/null 2>&1; then \
			echo ""; \
			echo "🔑 Dashboard login created"; \
			echo "   URL:      http://localhost:8025/"; \
			echo "   Username: $(ADMIN_USER)"; \
			echo "   Password: $$PW"; \
			echo "   (shown once — make reset-admin-password if you lose it)"; \
			echo ""; \
			echo "🔄 Restarting the web service so it picks up the new account..."; \
			docker compose -f $(COMPOSE_FILE) restart elemta-web >/dev/null 2>&1 || true; \
		else \
			echo "❌ Could not create the dashboard account"; \
		fi; \
	fi

# Set a new password for the dashboard account, for when the generated one is
# lost — which is the normal outcome of a password shown once.
reset-admin-password:
	@PW="$(ADMIN_PASSWORD)"; \
	if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
	if ! docker ps --format '{{.Names}}' | grep -q '^elemta-web$$'; then \
		echo "❌ elemta-web is not running — start the stack first (make up)"; \
		exit 1; \
	fi; \
	OUT=$$(printf '%s\n' "$$PW" | docker exec -i elemta-web /app/elemta --config /app/runtime-config/elemta.toml \
		user passwd $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
	if [ $$? -ne 0 ]; then \
		OUT=$$(printf '%s\n' "$$PW" | docker exec -i elemta-web /app/elemta --config /app/runtime-config/elemta.toml \
			user add $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
		if [ $$? -ne 0 ]; then \
			echo "❌ Could not set the password:"; \
			echo "$$OUT" | sed 's/^/   /'; \
			exit 1; \
		fi; \
		echo "ℹ️  No account existed, so one was created."; \
	fi; \
	echo ""; \
	echo "🔑 Dashboard login"; \
	echo "   URL:      http://localhost:8025/"; \
	echo "   Username: $(ADMIN_USER)"; \
	echo "   Password: $$PW"; \
	echo ""; \
	docker compose -f $(COMPOSE_FILE) restart elemta-web >/dev/null 2>&1; \
	echo "🔄 Web service restarted so the change takes effect."


check-tools:
	@for tool in docker python3 openssl; do \
		if ! command -v $$tool >/dev/null 2>&1; then \
			echo "❌ Missing required tool: $$tool"; \
			exit 1; \
		fi; \
	done

# A short-lived dev certificate has to be replaced once it lapses, or the stack
# comes up with TLS that fails every handshake. Checking the date rather than
# just the file is the difference between a warning and a broken deployment.
ensure-dev-certs:
	@if [ ! -f config/test.crt ] || [ ! -f config/test.key ]; then \
		echo "🔐 Missing test certs, generating..."; \
		$(MAKE) certs; \
	elif ! openssl x509 -checkend 0 -noout -in config/test.crt >/dev/null 2>&1; then \
		echo "🔐 Test certificate has expired, regenerating..."; \
		$(MAKE) certs; \
	else \
		echo "ℹ️  Using existing TLS certificate (expires $$(openssl x509 -enddate -noout -in config/test.crt | cut -d= -f2))"; \
	fi

ensure-dev-env:
	@if [ ! -f $(DEV_ENV_FILE) ]; then \
		echo "📝 Creating $(DEV_ENV_FILE) for development..."; \
		printf "# Elemta Development Environment - Auto-generated\n" > $(DEV_ENV_FILE); \
		printf "ENVIRONMENT=development\n" >> $(DEV_ENV_FILE); \
		printf "HOSTNAME=mail.dev.evil-admin.com\n" >> $(DEV_ENV_FILE); \
		printf "LISTEN_PORT=2525\n" >> $(DEV_ENV_FILE); \
		printf "LOG_LEVEL=DEBUG\n" >> $(DEV_ENV_FILE); \
		printf "DEV_MODE=true\n" >> $(DEV_ENV_FILE); \
		printf "TEST_MODE=true\n" >> $(DEV_ENV_FILE); \
		printf "AUTH_REQUIRED=false\n" >> $(DEV_ENV_FILE); \
		printf "LDAP_HOST=elemta-ldap\n" >> $(DEV_ENV_FILE); \
		printf "DELIVERY_HOST=elemta-dovecot\n" >> $(DEV_ENV_FILE); \
		printf "COMPOSE_PROJECT_NAME=elemta\n" >> $(DEV_ENV_FILE); \
		printf "COMPOSE_FILE=$(COMPOSE_FILE)\n" >> $(DEV_ENV_FILE); \
		echo "✅ $(DEV_ENV_FILE) created"; \
	else \
		echo "ℹ️  Using existing $(DEV_ENV_FILE)"; \
	fi

refresh-dev-env:
	@touch $(DEV_ENV_FILE)
	@for kv in \
		"QUEUE_BACKEND=$(QUEUE_BACKEND)" \
		"QUEUE_POSTGRES_DSN=$(QUEUE_POSTGRES_DSN)" \
		"COMPOSE_FILE=$(COMPOSE_FILE)"; do \
		key=$${kv%%=*}; \
		if grep -q "^$${key}=" $(DEV_ENV_FILE); then \
			sed -i "s|^$${key}=.*|$${kv}|" $(DEV_ENV_FILE); \
		else \
			echo "$${kv}" >> $(DEV_ENV_FILE); \
		fi; \
	done

print-dev-summary:
	@echo ""
	@echo "✅ Development Environment Ready!"
	@echo "=================================="
	@echo "   📧 SMTP:      localhost:2525"
	@echo "   📊 Metrics:   http://localhost:8080/metrics"
	@echo "   🌐 Web UI:    http://localhost:8025  (login required)"
	@echo ""
	@echo "   👤 Mailbox user:   user@example.com / password   (for sending/receiving mail)"
	@echo "   🔑 Dashboard login: printed above by bootstrap-admin — a different account"
	@echo "                       make reset-admin-password if you missed it"
	@echo ""
	@echo "📋 Next Steps:"
	@echo "   make status      # Check service health"
	@echo "   make logs        # View logs"
	@echo "   make test-load   # Run load tests"
	@echo "   make help        # Variables, plugin toggles, and the gotchas"

install-dev: check-tools docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🚀 Elemta Development Setup (Minimal)"
	@echo "======================================"
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-plugins
	@echo "🚀 Starting services..."
	@# ELEMTA_CONFIG_RESEED makes this install authoritative: the services read a
	@# configuration on a shared volume, which is seeded once and then owned by
	@# whatever the web UI saves. Without this, the settings configured above
	@# would be ignored on every deploy after the first.
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d --no-deps $(DEV_MIN_SERVICES)
	@echo "⏳ Waiting for services to become healthy..."
	@sleep 5
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) bootstrap-admin
	@$(MAKE) print-dev-summary

install-dev-postgres:
	@echo "🐘 Elemta Development Setup (Postgres Queue)"
	@echo "============================================"
	@$(MAKE) install-dev QUEUE_BACKEND=sqlite
	@NET=$$(docker inspect -f '{{range $$k,$$v := .NetworkSettings.Networks}}{{println $$k}}{{end}}' elemta-web 2>/dev/null | head -n1); \
	if [ -z "$$NET" ]; then \
		echo "❌ Could not detect Docker network from elemta-web"; \
		exit 1; \
	fi; \
	echo "🔎 Using network: $$NET"; \
	if docker ps -a --format '{{.Names}}' | grep -q '^$(POSTGRES_CONTAINER_NAME)$$'; then \
		echo "♻️  Recreating $(POSTGRES_CONTAINER_NAME)"; \
		docker rm -f $(POSTGRES_CONTAINER_NAME) >/dev/null 2>&1 || true; \
	fi; \
	docker run -d --name $(POSTGRES_CONTAINER_NAME) \
		--network "$$NET" \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRES_DB=$(POSTGRES_DB) \
		-v $(POSTGRES_VOLUME):/var/lib/postgresql/data \
		postgres:16 >/dev/null; \
	echo "✅ Started $(POSTGRES_CONTAINER_NAME)"; \
	echo "⏳ Waiting for Postgres readiness..."; \
	for i in $$(seq 1 30); do \
		if docker exec $(POSTGRES_CONTAINER_NAME) pg_isready -U $(POSTGRES_USER) -d $(POSTGRES_DB) >/dev/null 2>&1; then \
			echo "✅ Postgres is ready"; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "❌ Postgres did not become ready in time"; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@$(MAKE) refresh-dev-env QUEUE_BACKEND=postgres QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=postgres QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@docker compose -f $(COMPOSE_FILE) restart elemta elemta-web
	@echo "✅ Postgres queue dev setup complete"
	@echo "   DSN: $(QUEUE_POSTGRES_DSN)"
	@echo "   Verify: docker exec -it $(POSTGRES_CONTAINER_NAME) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c 'select count(*) from queue_messages;'"

install-dev-full: check-tools docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🚀 Elemta Development Setup (Full)"
	@echo "=================================="
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-plugins
	@echo "🚀 Starting services..."
	@# See install-dev: without the reseed the settings configured above are
	@# ignored on every deploy after the first.
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) bootstrap-admin
	@$(MAKE) print-dev-summary
	@echo "   ✉️  Roundcube: http://localhost:8026"

docker-setup: install-dev-full

# Modern Docker commands
up:
	@echo "🚀 Starting Elemta services..."
	docker compose -f $(COMPOSE_FILE) up -d
	@echo "✅ Services started"

down:
	@echo "🛑 Stopping Elemta services..."
	docker compose -f $(COMPOSE_FILE) down
	@echo "✅ Services stopped"

down-volumes:
	@echo "🛑 Stopping Elemta services and removing volumes..."
	docker compose -f $(COMPOSE_FILE) down -v
	@echo "✅ Services stopped and volumes removed"

restart:
	@echo "🔄 Restarting Elemta services..."
	docker compose -f $(COMPOSE_FILE) restart
	@echo "✅ Services restarted"

logs:
	@echo "📋 Showing Elemta logs (Ctrl+C to exit)..."
	docker compose -f $(COMPOSE_FILE) logs -f

logs-elemta:
	@echo "📋 Showing Elemta SMTP server logs..."
	docker compose -f $(COMPOSE_FILE) logs -f elemta

status:
	@echo "📊 Elemta Services Status:"
	@docker compose -f $(COMPOSE_FILE) ps

rebuild:
	@echo "🔨 Rebuilding and restarting Elemta..."
	@$(MAKE) down
	docker compose -f $(COMPOSE_FILE) build --no-cache elemta elemta-web
	@$(MAKE) up
	@echo "✅ Rebuild complete"

rebuild-dev:
	@echo "🔨 Quick rebuild for development..."
	@$(MAKE) down
	docker compose -f $(COMPOSE_FILE) build elemta elemta-web
	@$(MAKE) up
	@echo "✅ Development rebuild complete"

docker-down: down-volumes

# Installation and update targets
install:
	@echo "🚀 Elemta Production Installation"
	@echo "=================================="
	@if [ -f .env ]; then \
		echo "⚠️  .env file already exists."; \
		read -p "Overwrite? (y/N): " confirm; \
		if [ "$$confirm" != "y" ] && [ "$$confirm" != "Y" ]; then \
			echo "Installation cancelled."; \
			exit 1; \
		fi; \
	fi
	@echo ""
	@echo "📝 Production Configuration"
	@echo "This will create a production-ready .env file."
	@echo ""
	@read -p "Hostname [mail.example.com]: " hostname; \
	hostname=$${hostname:-mail.example.com}; \
	read -p "SMTP Port [25]: " smtp_port; \
	smtp_port=$${smtp_port:-25}; \
	read -p "Admin Email [admin@example.com]: " admin_email; \
	admin_email=$${admin_email:-admin@example.com}; \
	read -p "Enable Let's Encrypt? (y/N): " letsencrypt; \
	if [ "$$letsencrypt" = "y" ] || [ "$$letsencrypt" = "Y" ]; then \
		letsencrypt_enabled=true; \
	else \
		letsencrypt_enabled=false; \
	fi; \
	read -p "LDAP Host [ldap]: " ldap_host; \
	ldap_host=$${ldap_host:-ldap}; \
	read -p "LDAP Base DN [dc=example,dc=com]: " ldap_base; \
	ldap_base=$${ldap_base:-dc=example,dc=com}; \
	echo ""; \
	echo "📝 Generating .env..."; \
	cat .env.example | sed \
		-e "s/HOSTNAME=.*/HOSTNAME=$$hostname/" \
		-e "s/LISTEN_PORT=.*/LISTEN_PORT=$$smtp_port/" \
		-e "s/LETSENCRYPT_EMAIL=.*/LETSENCRYPT_EMAIL=$$admin_email/" \
		-e "s/LETSENCRYPT_DOMAIN=.*/LETSENCRYPT_DOMAIN=$$hostname/" \
		-e "s/LETSENCRYPT_ENABLED=.*/LETSENCRYPT_ENABLED=$$letsencrypt_enabled/" \
		-e "s/LDAP_HOST=.*/LDAP_HOST=$$ldap_host/" \
		-e "s/LDAP_BASE_DN=.*/LDAP_BASE_DN=$$ldap_base/" \
		> .env
	@echo "✅ .env created successfully"
	@echo ""
	@echo "📋 Next Steps:"
	@echo "   1. Review and edit .env for your environment"
	@echo "   2. Configure TLS certificates (or enable Let's Encrypt)"
	@echo "   3. Update LDAP credentials in .env"
	@echo "   4. Run: make up"
	@echo ""
	@echo "🔐 Security Reminders:"
	@echo "   • Change default passwords in .env"
	@echo "   • Configure TLS certificates for production"
	@echo "   • Review memory and connection limits"
	@echo "   • Set up monitoring and alerts"


uninstall:
	@echo "🗑️  Uninstalling Elemta..."
	./install/uninstall.sh

# Legacy update targets (use 'make rebuild' instead)
update: rebuild
update-backup: rebuild  
update-restart: restart 