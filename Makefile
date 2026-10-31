.PHONY: mailbox-dev-up mailbox-dev-down mailbox-dev-status mailbox-dev-s3 test-mailbox test-webmail-browser all help gotchas ensure-dev-secrets ldap-service-accounts build clean clean-certs certs install install-dev install-dev-full install-dev-postgres install-dev-mailauth \
	elk-up elk-down elk-status elk-dashboard elk-dashboard-check rspamd-train sink-up sink-down configure-delivery-target \
	mailauth-check mailauth-check-fail stop-mailauth-services \
	configure-queue-backend configure-plugins bootstrap-admin reset-admin-password ensure-dev-certs ensure-dev-env refresh-dev-env print-dev-summary check-tools \
	install-dev-bench setup run test test-race-smoke up down down-volumes restart logs logs-elemta status \
	rebuild rebuild-dev docker-build lint lint-fix fmt

# Core paths/config
.DEFAULT_GOAL := all
.PHONY: mailbox-ha-dev-up mailbox-ha-dev-down mailbox-ha-dev-status

mailbox-ha-dev-up: ensure-dev-secrets ldap-service-accounts
	./scripts/mailbox-ha-dev.sh up

mailbox-ha-dev-down:
	./scripts/mailbox-ha-dev.sh down

mailbox-ha-dev-status:
	./scripts/mailbox-ha-dev.sh ps
mailbox-dev-up: ensure-dev-secrets ldap-service-accounts
	./scripts/mailbox-dev.sh up

mailbox-dev-down:
	./scripts/mailbox-dev.sh down

mailbox-dev-status:
	./scripts/mailbox-dev.sh ps

mailbox-dev-s3: ensure-dev-secrets ldap-service-accounts
	./scripts/mailbox-dev.sh s3

test-mailbox:
	go test -race ./internal/mailbox/...

COMPOSE_FILE ?= deployments/compose/docker-compose.yml
MAILAUTH_COMPOSE_FILE ?= deployments/compose/docker-compose-mailauth.yml
ELK_COMPOSE_FILE ?= deployments/compose/docker-compose-elk.yml
MAILAUTH_LAB_DIR ?= /tmp/elemta-mailauth-lab
DEV_ENV_FILE ?= .env
# The normal dev stack keeps only services used by mail delivery and webmail.
# The discarding sink is started explicitly by the benchmark targets.
DEV_MIN_SERVICES ?= elemta-dns elemta elemta-admin elemta-webmail elemta-mailbox-db mailbox-server elemta-mailbox elemta-ldap valkey
DEV_FULL_SERVICES ?= $(DEV_MIN_SERVICES) elemta-clamav elemta-rspamd
# The benchmarking stack: everything that scans, nothing that stores.
DEV_BENCH_SERVICES ?= $(DEV_MIN_SERVICES) elemta-clamav elemta-rspamd elemta-sink

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
PLUGIN_SPF ?= on
PLUGIN_DKIM ?= on
PLUGIN_DMARC ?= on
PLUGIN_ARC ?= on

# The dashboard's first account.
#
# The password is generated rather than fixed. A well-known default on a service
# that can flush queues and send bulk mail is a bad thing to have on a laptop
# and a worse thing to have on a host somebody exposed by accident. Override
# with ADMIN_PASSWORD to choose your own.
ADMIN_USER ?= admin
ADMIN_PASSWORD ?=

# Queue backend config
QUEUE_BACKEND ?= file
QUEUE_POSTGRES_DSN ?= postgres://elemta:elemta@elemta-postgres:5432/elemta_queue?sslmode=disable
POSTGRES_CONTAINER_NAME ?= elemta-postgres
POSTGRES_USER ?= elemta
POSTGRES_PASSWORD ?= elemta
POSTGRES_DB ?= elemta_queue
POSTGRES_VOLUME ?= elemta_pg

# Default target
all: build

# The knowledge that is not derivable from reading the targets. Split out of
# help because 26 lines of prose under 65 lines of target list means neither
# gets read.
gotchas:
	@echo "💡 Things that surprise people:"
	@echo "  • Benchmarks against mailbox storage include its metadata and body-write costs."
	@echo "    'make sink-up' points delivery at a sink that absorbs ~4500/s, so the number"
	@echo "    is about Elemta. Mail is discarded while it is on; 'make sink-down' undoes it."
	@echo "  • Editing config/elemta.toml does not change a running stack. The services read a"
	@echo "    copy on a shared volume, seeded once, because the web UI writes to it too."
	@echo "    'make install-dev' re-seeds from the file; 'up' and 'restart' do not."
	@echo "  • Scanner, allow/deny, blocklist and inbound mail-auth verification changes apply"
	@echo "    on their own within ~5 seconds. Listen address, size limits, timeouts, queue"
	@echo "    backend and ARC sealing need a restart; the UI and logs say so."
	@echo "  • 'install-dev-mailauth' is a different stack, not an add-on. Delivery mode is a"
	@echo "    single global setting, so it sends over remote SMTP to a sink at :8029 instead"
	@echo "    of over LMTP to the mailbox service. That is what makes DKIM signing and ARC sealing"
	@echo "    visible. Run any other install-dev target to go back; it cleans up for you."
	@echo "  • Logs are line-delimited JSON on stdout and in /app/logs/elemta.log. Only"
	@echo "    'level' from [logging] is read; type/output/file are ignored and the server"
	@echo "    warns if they are set. Shipping is 'make elk-up', which reads the log volume"
	@echo "    rather than making the mail server depend on a log store being up."
	@echo "  • The dev TLS certificate expires in $(CERT_DAYS) days on purpose, so the expiry warning on"
	@echo "    the Health page is exercised. It is regenerated when it lapses."
	@echo "  • The dev stack is self-signed and binds 0.0.0.0. Fine on a laptop; bind 127.0.0.1"
	@echo "    in the compose file if the machine is not isolated."
	@echo "  • The RBL plugin ships in tag mode (adds a header, refuses nothing). Turn on"
	@echo "    'Refuse listed senders' in Settings once you trust what it is flagging."
	@echo "  • The Mass Mailer opens with a demo campaign — a draft addressed to this"
	@echo "    stack's own mailboxes, never sent. Delete it and it stays gone until the"
	@echo "    campaign list is empty again; ELEMTA_DEMO_DATA=false turns it off."

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
		-subj '/CN=mail.dev.example.net/O=Elemta Dev/C=US' \
		-addext 'subjectAltName=DNS:mail.dev.example.net,DNS:*.dev.example.net' 2>/dev/null
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
# Drives the webmail pages in headless Chromium against an in-memory server;
# needs chromium or google-chrome on PATH (or CHROME_PATH).
test-webmail-browser:
	go test -tags browser -run Browser -count=1 ./internal/webmail/

# The same unit tests CI runs. Packages that need Postgres (the mailbox
# service) skip without ELEMTA_TEST_MAILBOX_DSN; see docs/testing.md.
test:
	go test -short ./...

test-race-smoke:
	@echo "Running targeted SMTP/session race smoke checks..."
	go test ./internal/smtp -race -run 'TestHandleUnknown|TestCommandSequencing|TestConnectionDraining'
	go test ./tests/integration -race -run 'TestIntegration_PersistentConnection|TestIntegration_TimeoutHandling'

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

docker-build:
	@echo "Building Docker image..."
	docker compose -f $(COMPOSE_FILE) build

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
		spf=$(PLUGIN_SPF) \
		dkim=$(PLUGIN_DKIM) \
		dmarc=$(PLUGIN_DMARC) \
		arc=$(PLUGIN_ARC) \
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
	if docker exec elemta-admin test -e /app/runtime-config/users.json 2>/dev/null; then \
		if ! docker exec elemta-admin /app/elemta --config /app/runtime-config/elemta.toml \
			user list --file /app/runtime-config/users.json 2>/dev/null | grep -q '^No users'; then \
			needs_account=0; \
		fi; \
	fi; \
	if [ "$$needs_account" = "0" ]; then \
		echo "ℹ️  Dashboard account already exists (make reset-admin-password to change it)"; \
	else \
		PW="$(ADMIN_PASSWORD)"; \
		if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
		if printf '%s\n' "$$PW" | docker exec -i elemta-admin /app/elemta --config /app/runtime-config/elemta.toml \
			user add $(ADMIN_USER) --file /app/runtime-config/users.json >/dev/null 2>&1; then \
			echo ""; \
			echo "🔑 Dashboard login created"; \
			echo "   URL:      $(K8S_ADMIN_URL)"; \
			echo "   Username: $(ADMIN_USER)"; \
			echo "   Password: $$PW"; \
			echo "   (shown once — make reset-admin-password if you lose it)"; \
			echo ""; \
			echo "🔄 Restarting the web service so it picks up the new account..."; \
			docker compose -f $(COMPOSE_FILE) restart elemta-admin >/dev/null 2>&1 || true; \
		else \
			echo "❌ Could not create the dashboard account"; \
		fi; \
	fi

# Set a new password for the dashboard account, for when the generated one is
# lost — which is the normal outcome of a password shown once.
reset-admin-password:
	@PW="$(ADMIN_PASSWORD)"; \
	if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
	if ! docker ps --format '{{.Names}}' | grep -q '^elemta-admin$$'; then \
		echo "❌ elemta-admin is not running — start the stack first (make up)"; \
		echo "   On Kubernetes, use make k8s-reset-admin-password"; \
		exit 1; \
	fi; \
	OUT=$$(printf '%s\n' "$$PW" | docker exec -i elemta-admin /app/elemta --config /app/runtime-config/elemta.toml \
		user passwd $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
	if [ $$? -ne 0 ]; then \
		OUT=$$(printf '%s\n' "$$PW" | docker exec -i elemta-admin /app/elemta --config /app/runtime-config/elemta.toml \
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
	echo "   URL:      $(K8S_ADMIN_URL)"; \
	echo "   Username: $(ADMIN_USER)"; \
	echo "   Password: $$PW"; \
	echo ""; \
	docker compose -f $(COMPOSE_FILE) restart elemta-admin >/dev/null 2>&1; \
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

# Per-service LDAP credentials for the dev stack (deployments/compose/.secrets/,
# never committed). Generated once; existing ones are kept.
ensure-dev-secrets:
	@./scripts/dev-secrets.sh

# Create or re-sync the least-privilege LDAP service accounts and access
# rules (also run by every install-dev target via init-ldap-if-needed.sh).
ldap-service-accounts:
	@./scripts/ldap-service-accounts.sh

ensure-dev-env:
	@if [ ! -f $(DEV_ENV_FILE) ]; then \
		echo "📝 Creating $(DEV_ENV_FILE) for development..."; \
		printf "# Elemta Development Environment - Auto-generated\n" > $(DEV_ENV_FILE); \
		printf "ENVIRONMENT=development\n" >> $(DEV_ENV_FILE); \
		printf "HOSTNAME=mail.dev.example.net\n" >> $(DEV_ENV_FILE); \
		printf "LISTEN_PORT=2525\n" >> $(DEV_ENV_FILE); \
		printf "LOG_LEVEL=DEBUG\n" >> $(DEV_ENV_FILE); \
		printf "DEV_MODE=true\n" >> $(DEV_ENV_FILE); \
		printf "TEST_MODE=true\n" >> $(DEV_ENV_FILE); \
		printf "AUTH_REQUIRED=false\n" >> $(DEV_ENV_FILE); \
		printf "LDAP_HOST=elemta-ldap\n" >> $(DEV_ENV_FILE); \
		printf "DELIVERY_HOST=elemta-mailbox\n" >> $(DEV_ENV_FILE); \
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
	@echo "   ✉️  Webmail:   http://localhost:8027  (sign in as the mailbox user)"
	@echo ""
	@# Report where mail actually goes rather than asserting it. The two installs
	@# differ on this, and a summary that guesses is worse than none.
	@target=$$(docker exec elemta-node0 sh -c "sed -n '/^\[delivery\]/,/^\[/p' /app/runtime-config/elemta.toml | grep -m1 '^host'" 2>/dev/null | sed 's/.*= *//; s/"//g'); \
	@if [ "$$target" = "elemta-sink" ]; then \
			echo "   📭 Delivery:  a DISCARDING SINK. Delivered mail is not stored anywhere."; \
			echo "                 make sink-down   → real mailboxes";
	elif [ -n "$$target" ]; then \
		echo "   📬 Delivery:  $$target — mail lands in real mailboxes."; \
		echo "                 make sink-up     → discard instead, for throughput work"; \
	fi
	@echo ""
	@echo "   👤 Mailbox user:   user@example.com / password   (for sending/receiving mail)"
	@echo "   🔑 Dashboard login: printed above by bootstrap-admin — a different account"
	@echo "                       make reset-admin-password if you missed it"
	@echo ""
	@echo "📋 Next Steps:"
	@echo "   make status      # Check service health"
	@echo "   make logs        # View logs"
	@echo "   make help        # Variables, plugin toggles, and the gotchas"

# Help target
help:
	@echo "Elemta - self-hosted email: MTA, mailbox service, webmail and admin console"
	@echo ""
	@echo "⚡ Quick Start:"
	@echo "  make install                  # Setup wizard: a dev stack, or a mail server for a real domain"
	@echo "  make install-dev              # Dev stack: MTA, mailbox service, webmail; prints a dashboard login"
	@echo "  make install-dev-full         # Everything, incl. ClamAV, Rspamd"
	@echo "  make install-dev-bench        # Scanners on, delivery DISCARDED — for throughput work"
	@echo "  make install-dev-postgres     # Dev stack with a Postgres queue"
	@echo "  make install-dev-mailauth     # Dev stack for SPF/DKIM/DMARC/ARC: fixed DNS, mail lands at :8029"
	@echo ""
	@echo "📬 Mail and webmail (dev stack):"
	@echo "  Webmail           http://localhost:8027  (user@example.com / password)"
	@echo "  IMAP / SMTP       localhost:993 (TLS) / localhost:2525, submission :2587"
	@echo "  test-mailbox          - Mailbox service tests (set ELEMTA_TEST_MAILBOX_DSN for Postgres)"
	@echo "  test-webmail-browser  - Drive the webmail in headless Chromium"
	@echo "  mailbox-dev-up / -down / -status   - Isolated mailbox service lab (own ports)"
	@echo "  mailbox-ha-dev-up / -down / -status - Isolated high-availability lab"
	@echo ""
	@echo "☁️  One internet-facing server (docs/cloud-dev.md):"
	@echo "  make install, choose 2   - Checks DNS and the host, secures Docker and the firewall,"
	@echo "                             deploys with Let's Encrypt, creates the first accounts"
	@echo "  scripts/cloud-deploy.sh  - Redeploy after an update (run on the server)"
	@echo ""
	@echo "🔑 Accounts & Access:"
	@echo "  Web UI            http://localhost:8025  (login required — there is no guest access)"
	@echo "  bootstrap-admin       - Create the dashboard account; prints the password once"
	@echo "  reset-admin-password  - Generate and print a new password for it"
	@echo "                          ADMIN_USER=name ADMIN_PASSWORD=secret to choose your own"
	@echo "  The dashboard login is NOT the mailbox login. Mailbox users live in LDAP;"
	@echo "  the dashboard account lives in the users file and is managed with:"
	@echo "    docker exec -it elemta-admin /app/elemta --config /app/runtime-config/elemta.toml \\"
	@echo "      user list|add|passwd|remove --file /app/runtime-config/users.json"
	@echo "  A running server reads that file at startup, so restart elemta-admin after changing it."
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
	@echo "📊 Logs & Observability:"
	@echo "  elk-up         - Elasticsearch + Kibana + Filebeat, reading the log volume"
	@echo "  elk-dashboard  - Import the Elemta overview dashboard into Kibana"
	@echo "  elk-dashboard-check - Verify every dashboard panel has data behind it"
	@echo "  sink-up        - Discard delivered mail (~4500/s) so benchmarks measure Elemta"
	@echo "  sink-down      - Delivery to the mailbox service again"
	@echo "  rspamd-train   - Train Bayes from a labelled corpus and measure it on held-out mail"
	@echo "                   SPAM_DIR=/path/to/spam [HAM_DIR=... TRAIN=2000 TEST=200]"
	@echo "  elk-status     - Cluster health and how many events are indexed"
	@echo "  elk-down       - Stop them (indexed logs are kept in their volume)"
	@echo "  Kibana http://localhost:5601 > Discover > elemta-*   Elasticsearch :9200"
	@echo "  Adds to whatever dev stack is running; it changes nothing about Elemta."
	@echo ""
	@echo "🔧 Build & Test:"
	@echo "  build          - Build all binaries (server, queue, cli)   clean - Remove artifacts"
	@echo "  test           - Go unit tests, as CI     test-race-smoke - Session race checks"
	@echo "  Load, stress and queue benchmarks live in the separate elemta-tests repository."
	@echo "  lint / lint-fix / fmt   - Code quality"
	@echo "  On an install-dev-mailauth stack:"
	@echo "    mailauth-check       - Send a message that should pass SPF, DKIM and DMARC"
	@echo "    mailauth-check-fail  - Send one that fails SPF and DMARC; it is still accepted"
	@echo "                           because enforcement is off. Read both at :8029"
	@echo ""
	@echo "🎛️  Variables (override on the command line):"
	@echo "  ADMIN_USER=admin              Dashboard account name"
	@echo "  ADMIN_PASSWORD=               Dashboard password (generated when empty)"
	@echo "  CERT_DAYS=$(CERT_DAYS)                  Dev certificate lifetime, in days"
	@echo "  QUEUE_BACKEND=$(QUEUE_BACKEND)           file | sqlite | postgres"
	@echo "  PLUGIN_RATE_LIMITER=$(PLUGIN_RATE_LIMITER)      PLUGIN_CLAMAV=$(PLUGIN_CLAMAV)   PLUGIN_RSPAMD=$(PLUGIN_RSPAMD)"
	@echo "  PLUGIN_ACCESS_CONTROL=$(PLUGIN_ACCESS_CONTROL)    PLUGIN_RBL=$(PLUGIN_RBL)      PLUGIN_MASS_MAILER=$(PLUGIN_MASS_MAILER)"
	@echo "  PLUGIN_SPF=$(PLUGIN_SPF)  PLUGIN_DKIM=$(PLUGIN_DKIM)  PLUGIN_DMARC=$(PLUGIN_DMARC)  PLUGIN_ARC=$(PLUGIN_ARC)"
	@echo "    e.g. make install-dev PLUGIN_RBL=off CERT_DAYS=90"
	@echo ""
	@echo "The targets above run the Docker Compose stack, the default. To run the same"
	@echo "dev stack on Kubernetes instead, use the k8s-* targets:"
	@echo ""
	@$(MAKE) --no-print-directory k8s-help
	@echo ""
	@echo "💡 make gotchas   - The things that surprise people (config reload, discarded"
	@echo "                    delivery, cert expiry, what [logging] ignores). Worth reading"
	@echo "                    once."

install-dev: check-tools ensure-dev-secrets docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🚀 Elemta Development Setup (Minimal)"
	@echo "======================================"
	@$(MAKE) stop-mailauth-services
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

# A stack for measuring throughput: scanners on, delivery discarded.
#
# Separate from install-dev-full rather than a flag on it, because "mail is
# thrown away" is not a detail to bury in an option. Anyone running this has
# said so.
install-dev-bench: check-tools ensure-dev-secrets docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🚀 Elemta Development Setup (Benchmarking)"
	@echo "=========================================="
	@$(MAKE) stop-mailauth-services
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-plugins
	@echo "🚀 Starting services..."
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d $(DEV_BENCH_SERVICES)
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) bootstrap-admin
	@# sink-up rather than a configure step: it force-recreates elemta, which is
	@# what actually makes the reseed happen. Compose will not recreate a
	@# container whose spec has not changed, so setting the target without it
	@# leaves the running server delivering to the old destination.
	@$(MAKE) --no-print-directory sink-up
	@$(MAKE) print-dev-summary
	@echo "   Measure with: elemta-tests' stress/bench_queue.py"
	@# The repo config stays as shipped: the sink lives in the seeded copy the
	@# server reads, and a benchmarking run should not rewrite the default
	@# everyone else gets.
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-mailbox DELIVERY_PORT=2424 >/dev/null

install-dev-postgres:
	@echo "🐘 Elemta Development Setup (Postgres Queue)"
	@echo "============================================"
	@$(MAKE) install-dev QUEUE_BACKEND=sqlite
	@NET=$$(docker inspect -f '{{range $$k,$$v := .NetworkSettings.Networks}}{{println $$k}}{{end}}' elemta-admin 2>/dev/null | head -n1); \
	if [ -z "$$NET" ]; then \
		echo "❌ Could not detect Docker network from elemta-admin"; \
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
	@$(MAKE) stop-mailauth-services
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=postgres QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@docker compose -f $(COMPOSE_FILE) restart elemta elemta-admin
	@echo "✅ Postgres queue dev setup complete"
	@echo "   DSN: $(QUEUE_POSTGRES_DSN)"
	@echo "   Verify: docker exec -it $(POSTGRES_CONTAINER_NAME) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c 'select count(*) from queue_messages;'"

install-dev-full: check-tools ensure-dev-secrets docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🚀 Elemta Development Setup (Full)"
	@echo "=================================="
	@$(MAKE) stop-mailauth-services
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-plugins
	@echo "🚀 Starting services..."
	@# See install-dev: without the reseed the settings configured above are
	@# ignored on every deploy after the first.
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d $(DEV_FULL_SERVICES)
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) bootstrap-admin
	@$(MAKE) print-dev-summary
	@echo "   ✉️  Webmail: http://localhost:8027"

# install-dev-mailauth is a dev stack in its own right, not a mode layered on
# another one. Delivery mode is a single global setting, so a stack cannot
# deliver locally over LMTP and out over SMTP at the same time: this install
# sends over remote SMTP to a local sink, which is what makes DKIM signing and
# ARC sealing observable, and is why mail does not reach the webmail here.
#
# Switching back is just running another install-dev target; they remove these
# services for you.
install-dev-mailauth: check-tools ensure-dev-secrets docker-build ensure-dev-certs ensure-dev-env refresh-dev-env
	@echo "🔐 Elemta Development Setup (Mail Authentication)"
	@echo "================================================="
	@$(MAKE) configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) configure-plugins
	@echo "🔐 Generating deterministic DNS, keys and zone data..."
	@MAILAUTH_LAB_DIR=$(MAILAUTH_LAB_DIR) ./scripts/dev/prepare-mailauth-lab.sh >/dev/null
	@echo "🚀 Starting services..."
	@MAILAUTH_LAB_DIR=$(MAILAUTH_LAB_DIR) docker compose -f $(COMPOSE_FILE) -f $(MAILAUTH_COMPOSE_FILE) up -d elemta-mailauth-dns elemta-mailauth-sink
	@# See install-dev: without the reseed the settings configured above are
	@# ignored on every deploy after the first.
	@MAILAUTH_LAB_DIR=$(MAILAUTH_LAB_DIR) ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) -f $(MAILAUTH_COMPOSE_FILE) up -d --force-recreate elemta elemta-admin
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) bootstrap-admin
	@$(MAKE) print-dev-summary
	@echo "   📥 Delivered mail: http://localhost:8029 (this stack does not deliver to webmail)"
	@echo "   ✅ SPF/DMARC pass: pass.auth.test      ❌ fail: fail.auth.test"
	@echo "   Send one: make mailauth-check   or   make mailauth-check-fail"

# Removes the mail-auth services so an ordinary dev install is not left with
# orphaned DNS and sink containers from a previous one.
# ELK adds to whatever dev stack is already running rather than replacing one.
# Nothing about how Elemta runs changes: it already writes line-delimited JSON
# to a shared volume, and Filebeat reads that volume. That is why this is
# elk-up rather than another install-dev target.
elk-up:
	@echo "📊 Starting Elasticsearch, Kibana and Filebeat"
	@# Elasticsearch stores an index per day and Kibana is not small. Warning
	@# here beats the failure mode this replaces, where a full disk surfaced as
	@# bulk-insert timeouts with nothing pointing at the cause.
	@free=$$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR==2 {print int($$4/1048576)}'); \
	if [ -n "$$free" ] && [ "$$free" -lt 10 ]; then \
		echo "⚠️  Only $${free}GB free where Docker stores data."; \
		echo "    Elasticsearch will run, but it has nowhere to grow."; \
		echo "    'docker system df' shows what is reclaimable; build cache is usually most of it."; \
	fi
	@docker compose -f $(COMPOSE_FILE) -f $(ELK_COMPOSE_FILE) up -d elemta-elasticsearch elemta-kibana elemta-filebeat
	@echo "⏳ Waiting for Elasticsearch (first start builds indices; this takes a minute)..."
	@for i in $$(seq 1 60); do 		if curl -fs "http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null 2>&1; then break; fi; 		sleep 2; 	done
	@curl -fs "http://localhost:9200/_cluster/health" >/dev/null 2>&1 		&& echo "✅ Elasticsearch is up at http://localhost:9200" 		|| echo "⚠️  Elasticsearch did not become healthy; check 'docker logs elemta-elasticsearch'"
	@$(MAKE) --no-print-directory elk-data-view
	@$(MAKE) --no-print-directory elk-dashboard
	@echo "   📊 Kibana:        http://localhost:5601  (give it a minute on first start)"
	@echo "   🔎 Logs:          Kibana > Discover > elemta-*"
	@echo "   Both ports bind to 127.0.0.1 only: this stack has no authentication."
	@echo "   Try: make elk-status    to see what has been indexed"

# The data view is what makes Discover usable; without it Kibana shows a setup
# wizard instead of the logs. Created through the API so it is visible here
# rather than buried in the shipper's config.
elk-data-view:
	@# Kibana answers /api/status with 200 long before it can serve the API, so
	@# waiting for the endpoint to respond is not waiting for Kibana. Wait for it
	@# to call itself available, or the data view is created against a Kibana
	@# that refuses it and the failure gets reported as "already exists".
	@ready=""; for i in $$(seq 1 60); do level=$$(curl -fs http://localhost:5601/api/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status']['overall']['level'])" 2>/dev/null); if [ "$$level" = "available" ]; then ready=yes; break; fi; sleep 3; done; \
	if [ -z "$$ready" ]; then echo "⚠️  Kibana did not become available; no data view was created."; echo "    Retry with 'make elk-data-view' once http://localhost:5601 loads."; exit 0; fi; \
	body=$$(curl -s -X POST http://localhost:5601/api/data_views/data_view -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{"data_view":{"title":"elemta-*","name":"Elemta logs","timeFieldName":"@timestamp"}}' 2>/dev/null); \
	if echo "$$body" | grep -q '"id"'; then \
		echo "✅ Kibana data view 'elemta-*' created"; \
	elif echo "$$body" | grep -qi 'duplicate'; then \
		echo "✅ Kibana data view 'elemta-*' already exists"; \
	else \
		echo "⚠️  Kibana refused the data view: $$body"; \
		echo "    Create it under Stack Management > Data Views (pattern elemta-*, time field @timestamp)"; \
	fi

# The dashboard ships as an exported saved-object file rather than being built
# through the API here: building needs a live Kibana and is a development step
# (scripts/dev/build_elk_dashboard.py), while importing is what a user wants.
elk-dashboard:
	@if [ ! -f deployments/elk/elemta-dashboard.ndjson ]; then \
		echo "⚠️  deployments/elk/elemta-dashboard.ndjson is missing."; \
		echo "    Rebuild it against a live Kibana with:"; \
		echo "      python3 scripts/dev/build_elk_dashboard.py"; \
		exit 0; \
	fi; \
	ready=""; for i in $$(seq 1 40); do level=$$(curl -fs http://localhost:5601/api/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['status']['overall']['level'])" 2>/dev/null); if [ "$$level" = "available" ]; then ready=yes; break; fi; sleep 3; done; \
	if [ -z "$$ready" ]; then echo "⚠️  Kibana is not available; the dashboard was not imported."; echo "    Retry with 'make elk-dashboard' once http://localhost:5601 loads."; exit 0; fi; \
	body=$$(curl -s -X POST 'http://localhost:5601/api/saved_objects/_import?overwrite=true' -H 'kbn-xsrf: true' --form file=@deployments/elk/elemta-dashboard.ndjson 2>/dev/null); \
	if echo "$$body" | grep -q '"success":true'; then \
		echo "✅ Dashboard imported: http://localhost:5601/app/dashboards#/view/elemta-overview"; \
	else \
		echo "⚠️  Kibana refused the dashboard import: $$body"; \
	fi

# Train the Bayes classifier from a labelled corpus, and measure whether it
# worked on messages it was not trained on.
#
# Without this the dev Rspamd has no statistical filter and scores real ham
# above real spam: with nothing learned, the score is mostly infrastructure
# symbols that replayed corpus mail trips more than spam does. HAM_DIR and SPAM_DIR must point
# at directories of plain message files; the untroubled corpus ships .7z
# archives that need extracting first.
HAM_DIR ?= /mnt/data/email-corpus/enron/extracted/maildir
SPAM_DIR ?=
rspamd-train:
	@if [ -z "$(SPAM_DIR)" ]; then \
		echo "SPAM_DIR is not set. Point it at a directory of spam messages:"; \
		echo "  make rspamd-train SPAM_DIR=/path/to/extracted/spam"; \
		echo "Optionally HAM_DIR=... (default $(HAM_DIR))"; \
		exit 1; \
	fi
	@python3 scripts/dev/train_rspamd.py --ham-dir "$(HAM_DIR)" --spam-dir "$(SPAM_DIR)" \
		--train $(or $(TRAIN),2000) --test $(or $(TEST),200)

# Checks that each panel would draw something. A panel querying a field nobody
# logs renders an empty chart, which is indistinguishable from a quiet server.
elk-dashboard-check:
	@python3 scripts/dev/check_elk_dashboard.py

# Point delivery at a discarding LMTP sink instead of mailbox storage.
# This isolates SMTP/queue throughput from storage work; the mailbox engines
# keep running so switching back does not require another deployment.
sink-up:
	@docker compose -f $(COMPOSE_FILE) up -d elemta-sink
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-sink DELIVERY_PORT=2424
	@# Without the reseed the setting above is ignored: the services read a copy
	@# of the config on a volume, seeded once. Same trap as install-dev.
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d --force-recreate elemta >/dev/null
	@echo "✅ Delivery goes to the sink (elemta-sink:2424). Mail is discarded."
	@echo "   Benchmark:  elemta-tests' stress/bench_queue.py"
	@echo "   Sink rate:  docker logs -f elemta-sink"

# Real mailboxes: restore the development mailbox service and its reader.
sink-down:
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-mailbox DELIVERY_PORT=2424
	@ELEMTA_CONFIG_RESEED=true docker compose -f $(COMPOSE_FILE) up -d --force-recreate elemta >/dev/null
	@docker compose -f $(COMPOSE_FILE) stop elemta-sink >/dev/null
	@echo "✅ Delivery goes to the mailbox service; mail lands in real mailboxes."
	@echo "   ✉️  Webmail: http://localhost:8027  (user@example.com / password)"

# Rewrites [delivery] host/port. Same approach as configure-plugins: the repo
# config is the source that gets seeded, so it is what has to change.
DELIVERY_HOST ?= elemta-mailbox
DELIVERY_PORT ?= 2424
configure-delivery-target:
	@python3 scripts/dev/set_delivery_target.py "$(DELIVERY_HOST)" "$(DELIVERY_PORT)"

elk-status:
	@# Separates the three states this used to report as one. "No index yet" and
	@# "Elasticsearch is down" look identical from a failed curl, and telling an
	@# operator the store is unreachable when it is merely empty sends them
	@# debugging the wrong thing.
	@health=$$(curl -fs "http://localhost:9200/_cluster/health" 2>/dev/null); \
	if [ -z "$$health" ]; then \
		echo "❌ Elasticsearch is not answering on http://localhost:9200 (is 'make elk-up' running?)"; \
		exit 0; \
	fi; \
	status=$$(echo "$$health" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])"); \
	echo "🔎 Cluster: $$status  (yellow is normal for one node: replicas cannot be allocated)"; \
	if [ "$$status" = "red" ]; then \
		echo "   A red cluster on a dev box is nearly always disk. Check 'df -h' and 'docker system df'."; \
	fi; \
	count=$$(curl -fs "http://localhost:9200/elemta-*/_count" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null); \
	if [ -z "$$count" ]; then \
		echo "🔎 No elemta-* index yet. Filebeat creates it on the first log line it ships."; \
		exit 0; \
	fi; \
	echo "🔎 Indexed: $$count log events"; \
	curl -fs "http://localhost:9200/elemta-*/_search?size=1&sort=@timestamp:desc" 2>/dev/null \
		| python3 -c "import json,sys; h=json.load(sys.stdin)['hits']['hits']; s=h[0]['_source'] if h else None; print('🔎 Latest:', s.get('@timestamp'), s.get('component'), '-', s.get('msg')) if s else print('🔎 Latest: nothing yet')" 2>/dev/null

elk-down:
	@docker compose -f $(COMPOSE_FILE) -f $(ELK_COMPOSE_FILE) rm -sf elemta-elasticsearch elemta-kibana elemta-filebeat >/dev/null 2>&1 || true
	@echo "Stopped the ELK services. Their data volumes are kept;"
	@echo "'docker volume rm compose_elemta_elasticsearch_data' removes the indexed logs."

stop-mailauth-services:
	@MAILAUTH_LAB_DIR=$(MAILAUTH_LAB_DIR) docker compose -f $(COMPOSE_FILE) -f $(MAILAUTH_COMPOSE_FILE) rm -sf elemta-mailauth-dns elemta-mailauth-sink >/dev/null 2>&1 || true

mailauth-check:
	@printf 'EHLO lab\r\nMAIL FROM:<sender@pass.auth.test>\r\nRCPT TO:<user@receiver.auth.test>\r\nDATA\r\nFrom: sender@pass.auth.test\r\nTo: user@receiver.auth.test\r\nSubject: Elemta mail-auth lab\r\nDate: Tue, 11 Aug 2026 12:00:00 -0400\r\nMessage-ID: <mailauth-lab@pass.auth.test>\r\n\r\nSPF, DKIM and DMARC lab message.\r\n.\r\nQUIT\r\n' | nc localhost 2525
	@echo "Message queued. The remote SMTP worker signs it; inspect http://localhost:8029"

mailauth-check-fail:
	@printf 'EHLO lab-fail\r\nMAIL FROM:<sender@fail.auth.test>\r\nRCPT TO:<user@receiver.auth.test>\r\nDATA\r\nFrom: sender@fail.auth.test\r\nTo: user@receiver.auth.test\r\nSubject: Elemta mail-auth negative lab\r\nDate: Tue, 11 Aug 2026 12:01:00 -0400\r\nMessage-ID: <mailauth-fail@fail.auth.test>\r\n\r\nExpected SPF and DMARC failure in reporting mode.\r\n.\r\nQUIT\r\n' | nc localhost 2525
	@echo "Failure example queued. SPF/DMARC fail but reporting mode accepts it."


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
	docker compose -f $(COMPOSE_FILE) build --no-cache elemta mailbox-server
	@$(MAKE) up
	@echo "✅ Rebuild complete"

rebuild-dev:
	@echo "🔨 Quick rebuild for development..."
	@$(MAKE) down
	docker compose -f $(COMPOSE_FILE) build elemta mailbox-server
	@$(MAKE) up
	@echo "✅ Development rebuild complete"

# The setup wizard: a development stack, or a mail server for a real domain
# on an internet-facing host (scripts/setup.sh, docs/installation.md).
install setup:
	@./scripts/setup.sh

# ---------------------------------------------------------------------------
# Kubernetes: the same dev stack on a local cluster (k3s on the dev box), as an
# option next to the Compose one above. Every target is k8s-prefixed; nothing
# above changes. See deployments/kubernetes/README.md.
#
# Each k8s-install-dev* target applies one overlay of deployments/kubernetes/dev:
#   minimal   Elemta, caching DNS, LDAP, mailbox service + Postgres, webmail, Valkey, LMTP sink
#   full      + ClamAV, Rspamd
#   bench     + ClamAV, Rspamd (delivery goes to the sink)
#   postgres  + Postgres for the queue
# Services keep their compose names and host ports, so config/elemta.toml and
# the scripts work against either stack, but not both at once: they want the
# same ports. k8s-install refuses while the Compose stack is up.
# ---------------------------------------------------------------------------
KUBECTL ?= kubectl
K8S_NAMESPACE ?= elemta
K8S_DIR ?= deployments/kubernetes
K8S_OVERLAY ?= minimal
# The overlays read config/elemta.toml and the LDAP, Rspamd files
# from where they live in the repository, outside the kustomization's own
# directory, which kustomize refuses by default.
KUSTOMIZE = $(KUBECTL) kustomize --load-restrictor LoadRestrictionsNone
KC = $(KUBECTL) -n $(K8S_NAMESPACE)
# Applying an overlay removes what the previous one added and this one does
# not. Volumes are not in the list
# on purpose: switching stacks must not take the ClamAV signatures or the
# Rspamd Bayes data with it. k8s-down-volumes does.
K8S_PRUNE = --prune -l app.kubernetes.io/part-of=elemta \
	--prune-allowlist=apps/v1/Deployment --prune-allowlist=core/v1/Service \
	--prune-allowlist=core/v1/ConfigMap --prune-allowlist=core/v1/Secret
# Images the Kubernetes stack builds rather than pulls.
IMAGE_TAG ?= dev
DOCKER_BUILD_FLAGS ?=
# How built images reach the cluster. auto works it out from the node:
#   docker  k3s running on Docker (docker: true in its config) sees them already
#   kind    kind load docker-image
#   k3s     docker save | sudo k3s ctr images import  (asks for sudo)
K8S_IMAGE_LOAD ?= auto
# The overlay currently applied, recorded on the namespace by k8s-apply, so
# targets that change config on a running stack re-apply that one rather than
# the default, which would prune the rest.
K8S_CURRENT_OVERLAY = $$($(KUBECTL) get namespace $(K8S_NAMESPACE) -o jsonpath='{.metadata.annotations.elemta\.dev/overlay}' 2>/dev/null || true)
# The same, for make itself to choose between the two layouts below. Recursive
# (=), so kubectl is only asked when a k8s target uses it.
K8S_HA = $(filter ha,$(shell $(KUBECTL) get namespace $(K8S_NAMESPACE) -o jsonpath='{.metadata.annotations.elemta\.dev/overlay}' 2>/dev/null))
# Where things run. The dev overlays put the MTA and the admin console in one
# pod (deploy/elemta, containers smtp and admin); the replicated one (dev/ha)
# runs them as their own workloads.
K8S_MTA = $(if $(K8S_HA),statefulset/elemta-mta,deploy/elemta)
K8S_MTA_PODS = app.kubernetes.io/name=$(if $(K8S_HA),elemta-mta,elemta)
K8S_ADMIN_TARGET ?= $(if $(K8S_HA),deploy/elemta-admin,deploy/elemta)
# dev/ha serves admin and webmail only through its HTTPS ingress.
K8S_ADMIN_URL = $(if $(K8S_HA),https://admin.elemta.test/,http://localhost:8025/)
K8S_WEBMAIL_URL = $(if $(K8S_HA),https://webmail.elemta.test/,http://localhost:8027)
# What reads the runtime config at start, restarted to take a re-seeded one.
K8S_CONFIG_READERS = $(if $(K8S_HA),statefulset/elemta-mta deploy/elemta-admin deploy/elemta-webmail,deploy/elemta)
# Workloads that run the images built here, restarted after a rebuild
# because the tag does not change.
K8S_OWN_IMAGES = $(if $(K8S_HA),statefulset/elemta-mta statefulset/elemta-ldap deploy/elemta-admin deploy/elemta-webmail deploy/elemta-mailbox deploy/elemta-dns,deploy/elemta deploy/elemta-sink deploy/elemta-mailbox deploy/elemta-webmail deploy/elemta-dns)
K8S_ADMIN_EXEC = $(KC) exec -i $(K8S_ADMIN_TARGET) -c admin -- /app/elemta --config /app/runtime-config/elemta.toml

.PHONY: k8s-help k8s-check k8s-images k8s-load k8s-apply k8s-wait k8s-install \
	k8s-install-dev k8s-install-dev-full k8s-install-dev-bench k8s-install-dev-postgres \
	k8s-up k8s-down k8s-down-volumes k8s-restart k8s-status k8s-logs k8s-logs-elemta \
	k8s-rebuild k8s-rebuild-dev k8s-reseed k8s-sink-up k8s-sink-down \
	k8s-bootstrap-admin k8s-reset-admin-password k8s-print-dev-summary \
	k8s-ha-operator k8s-ha-edge k8s-ha-registry k8s-ha-images k8s-ha-mailbox-config \
	k8s-ha-config k8s-ha-secrets k8s-ha-apply k8s-install-ha k8s-ha-status k8s-ha-ca \
	linode-init linode-config linode-check linode-edge linode-apply linode-admin

k8s-help:
	@echo "☸️  Kubernetes (k3s; see deployments/kubernetes/README.md):"
	@echo "  k8s-install-dev            Minimal stack, plugins on, prints a dashboard login"
	@echo "  k8s-install-dev-full       + ClamAV, Rspamd"
	@echo "  k8s-install-dev-bench      + ClamAV, Rspamd; delivery DISCARDED"
	@echo "  k8s-install-dev-postgres   Postgres queue"
	@echo "  k8s-install-ha             Lean local stack; replicated Postgres, Valkey, and LDAP;"
	@echo "                             HTTPS admin and webmail through HAProxy (*.elemta.test)"
	@echo "  k8s-ha-ca                  Export that stack's development CA, to trust it"
	@echo "  linode-init / linode-config / linode-check / linode-edge / linode-apply / linode-admin"
	@echo "                             Production on Linode (production/linode/README.md)"
	@echo "  k8s-up / k8s-down          Scale to zero and back, volumes kept"
	@echo "  k8s-down-volumes           Delete the namespace and everything in it"
	@echo "  k8s-restart / k8s-status / k8s-logs / k8s-logs-elemta"
	@echo "  k8s-rebuild-dev            Build, load into the cluster, restart (k8s-rebuild: no cache)"
	@echo "  k8s-reseed                 Take config/elemta.toml again, discarding what the UI saved"
	@echo "  k8s-sink-up / k8s-sink-down   Discard delivery, or deliver to the mailbox service again"
	@echo "  k8s-bootstrap-admin / k8s-reset-admin-password"
	@echo "  Dashboard users: kubectl -n $(K8S_NAMESPACE) exec -it $(K8S_ADMIN_TARGET) -c admin -- \\"
	@echo "    /app/elemta --config /app/runtime-config/elemta.toml \\"
	@echo "    user list|add|passwd|remove --file /app/runtime-config/users.json"
	@echo "  See what is running: kubectl -n $(K8S_NAMESPACE) get pods,svc"
	@echo "  Same ports as the Compose stack, so run one or the other ('make down' first)."
	@echo "  K8S_IMAGE_LOAD=$(K8S_IMAGE_LOAD) (auto|docker|kind|k3s|none)  K8S_NAMESPACE=$(K8S_NAMESPACE)  KUBECTL=$(KUBECTL)"

# Fail early and say what to do, rather than letting kubectl print a
# connection-refused trace from the middle of an install.
k8s-check:
	@if ! command -v $(KUBECTL) >/dev/null 2>&1; then \
		echo "❌ kubectl not found. Install it (Arch: sudo pacman -S kubectl)."; \
		exit 1; \
	fi
	@if ! $(KUBECTL) get nodes >/dev/null 2>&1; then \
		echo "❌ No Kubernetes cluster reachable (kubectl context: $$($(KUBECTL) config current-context 2>/dev/null || echo none))."; \
		echo "   Install k3s and copy its kubeconfig: deployments/kubernetes/README.md"; \
		exit 1; \
	fi

# The images the stack builds rather than pulls: Elemta (MTA, admin console
# and webmail), the mailbox service, the directory, and the caching resolver.
k8s-images:
	@echo "🔨 Building images ($(IMAGE_TAG))..."
	docker build $(DOCKER_BUILD_FLAGS) --build-arg VERSION=$$(git rev-parse --short HEAD 2>/dev/null || echo dev) -t elemta:$(IMAGE_TAG) .
	docker build $(DOCKER_BUILD_FLAGS) -t elemta-mailbox:$(IMAGE_TAG) -f docker/mailbox/Dockerfile .
	docker build $(DOCKER_BUILD_FLAGS) -t elemta-ldap:$(IMAGE_TAG) -f docker/ldap/Dockerfile .
	docker build $(DOCKER_BUILD_FLAGS) -t elemta-dns:$(IMAGE_TAG) deployments/dns
	@$(MAKE) --no-print-directory k8s-load

# A cluster does not see Docker's images unless it runs on Docker. Detected
# from the node rather than configured, so the same command works on k3s, k3s
# on Docker, and kind.
k8s-load:
	@mode="$(K8S_IMAGE_LOAD)"; \
	if [ "$$mode" = "auto" ]; then \
		runtime=$$($(KUBECTL) get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null); \
		context=$$($(KUBECTL) config current-context 2>/dev/null); \
		case "$$runtime" in docker://*) mode=docker ;; *) \
			case "$$context" in kind-*) mode=kind ;; *) mode=k3s ;; esac ;; \
		esac; \
	fi; \
	images="elemta:$(IMAGE_TAG) elemta-mailbox:$(IMAGE_TAG) elemta-ldap:$(IMAGE_TAG) elemta-dns:$(IMAGE_TAG)"; \
	case "$$mode" in \
		docker) echo "ℹ️  The cluster runs on Docker; images are already visible to it" ;; \
		none) ;; \
		kind) context=$$($(KUBECTL) config current-context); \
			kind load docker-image --name "$${context#kind-}" $$images ;; \
		k3s) echo "📦 Importing images into k3s (sudo k3s ctr images import)..."; \
			docker save $$images | sudo k3s ctr images import - ;; \
		*) echo "❌ Unknown K8S_IMAGE_LOAD=$$mode (auto|docker|kind|k3s|none)"; exit 1 ;; \
	esac

# Apply one overlay. See K8S_PRUNE for what switching removes.
# The mailbox service's config is config/mailbox-main.toml, the Compose one,
# with the cluster's pod network (k3s's 10.42.0.0/16) allowed to deliver and to
# use the account-security API instead of the Compose network. Generated rather
# than copied, so the two can't drift; the copy is git-ignored.
K8S_POD_CIDR ?= 10.42.0.0/16
k8s-mailbox-config:
	@sed 's|^lmtp_allowed_networks = .*|lmtp_allowed_networks = ["$(K8S_POD_CIDR)", "127.0.0.0/8"]|' \
		config/mailbox-main.toml > $(K8S_DIR)/dev/minimal/mailbox.toml
	@grep -q '"$(K8S_POD_CIDR)"' $(K8S_DIR)/dev/minimal/mailbox.toml || \
		{ echo "❌ config/mailbox-main.toml has no lmtp_allowed_networks line to adapt"; exit 1; }

k8s-apply: k8s-mailbox-config
	@echo "🚀 Applying deployments/kubernetes/dev/$(K8S_OVERLAY)..."
	@$(KUSTOMIZE) $(K8S_DIR)/dev/$(K8S_OVERLAY) | $(KUBECTL) apply $(K8S_PRUNE) -f - | grep -v ' unchanged$$' || true
	@$(KUBECTL) annotate namespace $(K8S_NAMESPACE) elemta.dev/overlay=$(K8S_OVERLAY) --overwrite >/dev/null

# Wait for every Deployment and StatefulSet to roll out. ClamAV downloads its signatures on a
# fresh volume, which is why the timeout is long; nothing else needs it.
k8s-wait:
	@echo "⏳ Waiting for the stack to become ready..."
	@for d in $$($(KC) get deployments,statefulsets -o name); do \
		$(KC) rollout status $$d --timeout=10m >/dev/null || { echo "❌ $$d did not become ready:"; $(KC) describe $$d | tail -15; exit 1; }; \
	done
	@echo "✅ All deployments ready"

# Make the next start take config/elemta.toml again, discarding what the web UI
# saved. Compose does this with ELEMTA_CONFIG_RESEED and a marker in the
# container; every Kubernetes container start is a fresh layer, so here it is
# explicit: remove the seeded copy and restart, and prepare-config.sh seeds a
# new one from the ConfigMap. Re-applies nothing: after editing the file, run
# an install target (or k8s-sink-*, which re-apply).
k8s-reseed:
	@# A rollout still under way (an apply with a new ConfigMap) leaves old
	@# pods that would re-create the file from the old config before the new
	@# ones start, and the new ones then keep it.
	@for w in $(K8S_CONFIG_READERS); do $(KC) rollout status $$w --timeout=5m >/dev/null; done
	@$(KC) exec $(K8S_MTA) -c smtp -- rm -f /app/runtime-config/elemta.toml 2>/dev/null || true
	@$(KC) rollout restart $(K8S_CONFIG_READERS) >/dev/null
	@for w in $(K8S_CONFIG_READERS); do $(KC) rollout status $$w --timeout=5m >/dev/null; done
	@echo "✅ Runtime config re-seeded"

# What every k8s-install-dev* target does, for one overlay: build, configure,
# apply, re-seed, then accounts.
k8s-install: check-tools k8s-check ensure-dev-certs ensure-dev-secrets
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx elemta-node0; then \
		echo "❌ The Compose dev stack is running and holds the same ports. 'make down' first."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory k8s-images
	@$(MAKE) --no-print-directory configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) --no-print-directory configure-plugins
	@$(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$(K8S_OVERLAY)
	@# The directory first: the MTA, mailbox service and webmail bind as their
	@# own service accounts, so on a fresh LDAP volume they can't become ready
	@# until those exist, and waiting for every Deployment first never ends.
	@echo "⏳ Initializing LDAP..."
	@$(KC) rollout status deploy/elemta-ldap --timeout=5m >/dev/null
	@ELEMTA_STACK=k8s K8S_NAMESPACE=$(K8S_NAMESPACE) ./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) --no-print-directory k8s-wait
	@# This install is authoritative: without the reseed the settings configured
	@# above would be ignored on every deploy after the first. And images are
	@# rebuilt under the same tag, so a Deployment whose spec did not change
	@# would keep running the old one. One restart covers both.
	@$(KC) exec deploy/elemta -c smtp -- rm -f /app/runtime-config/elemta.toml
	@$(KC) rollout restart $(K8S_OWN_IMAGES) >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
	@$(MAKE) --no-print-directory k8s-bootstrap-admin

k8s-install-dev:
	@echo "☸️  Elemta Development Setup on Kubernetes (Minimal)"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=minimal
	@$(MAKE) --no-print-directory k8s-print-dev-summary

k8s-install-dev-full:
	@echo "☸️  Elemta Development Setup on Kubernetes (Full)"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=full
	@$(MAKE) --no-print-directory k8s-print-dev-summary
	@echo "   ✉️  Webmail: http://localhost:8027"

# As install-dev-bench: scanners on, delivery discarded, and the repo config
# put back afterwards because the sink lives in the seeded copy.
k8s-install-dev-bench:
	@echo "☸️  Elemta Development Setup on Kubernetes (Benchmarking)"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=bench
	@$(MAKE) --no-print-directory k8s-sink-up
	@$(MAKE) --no-print-directory k8s-print-dev-summary
	@echo "   Measure with: elemta-tests' stress/bench_queue.py (ELEMTA_STACK=k8s)"
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-mailbox DELIVERY_PORT=2424 >/dev/null

# Postgres comes up with the rest. If Elemta wins the race it exits on the
# unreachable backend and Kubernetes restarts it until Postgres answers, so
# there is no sqlite-first two-step as in the Compose version.
k8s-install-dev-postgres:
	@echo "☸️  Elemta Development Setup on Kubernetes (Postgres Queue)"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=postgres QUEUE_BACKEND=postgres QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) --no-print-directory k8s-print-dev-summary
	@echo "   Verify: kubectl -n $(K8S_NAMESPACE) exec deploy/elemta-postgres -- psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c 'select count(*) from queue_messages;'"

# ---------------------------------------------------------------------------
# The replicated deployment (deployments/kubernetes/ha) on this machine's
# k3s, through dev/ha. Separate targets because its pieces differ from the
# dev overlays': an operator runs Postgres, images go through a local
# registry instead of an import (no sudo), and the dashboard is its own
# Deployment.
CNPG_VERSION ?= 1.30.1
CNPG_MANIFEST = https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-$(basename $(CNPG_VERSION))/releases/cnpg-$(CNPG_VERSION).yaml
K8S_REGISTRY ?= localhost:5000
K8S_HA_SECRETS = deployments/compose/.secrets/k8s-ha

# The CloudNativePG operator, once per cluster, in its own namespace.
k8s-ha-operator:
	@if $(KUBECTL) get crd clusters.postgresql.cnpg.io >/dev/null 2>&1; then \
		echo "ℹ️  CloudNativePG already installed"; \
	else \
		echo "📦 Installing the CloudNativePG operator $(CNPG_VERSION)..."; \
		$(KUBECTL) apply --server-side -f $(CNPG_MANIFEST) >/dev/null && \
		$(KUBECTL) -n cnpg-system rollout status deploy/cnpg-controller-manager --timeout=5m; \
	fi

# cert-manager and the HAProxy ingress at the production edge's pinned
# versions, once per cluster, in their own namespaces.
HELM ?= helm
k8s-ha-edge:
	@if $(KUBECTL) get ingressclass haproxy >/dev/null 2>&1 && \
		$(KUBECTL) get crd certificates.cert-manager.io >/dev/null 2>&1; then \
		echo "ℹ️  cert-manager and the HAProxy ingress already installed"; \
	else \
		echo "📦 Installing cert-manager and the HAProxy ingress..."; \
		EDGE_CONTEXT=$$($(KUBECTL) config current-context) HELM=$(HELM) \
			$(K8S_DIR)/production/edge/install-controllers.sh; \
	fi

# A registry on localhost, which k3s's containerd pulls from over plain HTTP
# without configuration, so images reach the cluster without root.
k8s-ha-registry:
	@if ! docker ps --format '{{.Names}}' | grep -qx elemta-registry; then \
		docker rm -f elemta-registry >/dev/null 2>&1 || true; \
		docker run -d --restart unless-stopped --name elemta-registry \
			-p 127.0.0.1:5000:5000 -v elemta_registry:/var/lib/registry registry:2 >/dev/null; \
		echo "✅ Registry on $(K8S_REGISTRY)"; \
	fi

k8s-ha-images: k8s-ha-registry
	@$(MAKE) --no-print-directory k8s-images K8S_IMAGE_LOAD=none
	@docker build $(DOCKER_BUILD_FLAGS) -t elemta-valkey:8.0.11-errqueue.1 -f docker/valkey/Dockerfile docker/valkey
	@for i in elemta elemta-mailbox elemta-ldap elemta-dns; do \
		docker tag $$i:$(IMAGE_TAG) $(K8S_REGISTRY)/$$i:$(IMAGE_TAG) && \
		docker push -q $(K8S_REGISTRY)/$$i:$(IMAGE_TAG) >/dev/null || exit 1; \
	done
	@docker tag elemta-valkey:8.0.11-errqueue.1 $(K8S_REGISTRY)/elemta-valkey:8.0.11-errqueue.1
	@docker push -q $(K8S_REGISTRY)/elemta-valkey:8.0.11-errqueue.1 >/dev/null
	@echo "✅ Images pushed to $(K8S_REGISTRY)"

# config/mailbox-main.toml with what the replicated deployment changes:
# bodies in S3 (elemta-objects), synchronous replication required, and the
# pod network allowed to deliver. Generated, like dev/minimal's, so the
# two can't drift; the copy is git-ignored.
k8s-ha-mailbox-config:
	@sed -e 's|^lmtp_allowed_networks = .*|lmtp_allowed_networks = ["$(K8S_POD_CIDR)", "127.0.0.0/8"]|' \
		-e 's|^require_synchronous_replication = .*|require_synchronous_replication = true|' \
		-e 's|^driver = "file"|driver = "s3"|' \
		-e 's|^endpoint = .*|endpoint = "elemta-objects:8333"|' \
		config/mailbox-main.toml > $(K8S_DIR)/dev/ha/mailbox.toml
	@for want in '"$(K8S_POD_CIDR)"' 'require_synchronous_replication = true' 'driver = "s3"' 'elemta-objects:8333'; do \
		grep -qF "$$want" $(K8S_DIR)/dev/ha/mailbox.toml || \
			{ echo "❌ config/mailbox-main.toml changed shape; could not set $$want"; exit 1; }; \
	done

# config/elemta.toml with what the HTTPS edge changes. The MTA serves the
# certificate cert-manager renews (mounted by ../production/edge) and checks
# LMTP against its CA. Admin and webmail are HTTPS origins behind HAProxy;
# their NetworkPolicy admits only its pods, so the pod network can be
# trusted to report the client's address. Generated and git-ignored, like
# the mailbox's.
k8s-ha-config:
	@sed -e 's|^cert_file = .*|cert_file = "/app/public-tls/tls.crt"|' \
		-e 's|^key_file = .*|key_file = "/app/public-tls/tls.key"|' \
		-e 's|^lmtp_tls_ca_file = .*|lmtp_tls_ca_file = "/app/public-tls/ca.crt"|' \
		-e 's|^allowed_origins = .*|allowed_origins = ["https://admin.elemta.test"]|' \
		-e 's|^secure_cookies = .*|secure_cookies = true|' \
		-e 's|^recovery_url = .*|recovery_url = "https://webmail.elemta.test"|' \
		-e 's|^\[webmail\]$$|&\ntrusted_proxies = ["$(K8S_POD_CIDR)"]|' \
		-e 's|^\[api.rate_limit\]$$|&\ntrusted_proxies = ["$(K8S_POD_CIDR)"]|' \
		config/elemta.toml > $(K8S_DIR)/dev/ha/elemta.toml
	@for want in '/app/public-tls/tls.crt' '/app/public-tls/tls.key' '/app/public-tls/ca.crt' \
		'"https://admin.elemta.test"' 'secure_cookies = true' '"https://webmail.elemta.test"' \
		'trusted_proxies = ["$(K8S_POD_CIDR)"]'; do \
		grep -qF "$$want" $(K8S_DIR)/dev/ha/elemta.toml || \
			{ echo "❌ config/elemta.toml changed shape; could not set $$want"; exit 1; }; \
	done

# Database passwords and the S3 key pair for dev/ha, made once. Letters and
# digits only: the queue's password goes into a URL.
k8s-ha-secrets: ensure-dev-secrets
	@mkdir -p $(K8S_HA_SECRETS) && chmod 700 $(K8S_HA_SECRETS)
	@for u in mailbox queue; do \
		f=$(K8S_HA_SECRETS)/db-$$u.env; \
		[ -f $$f ] || { umask 077; printf 'username=%s\npassword=%s\n' $$u "$$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)" > $$f; }; \
	done
	@f=$(K8S_HA_SECRETS)/s3.env; [ -f $$f ] || { \
		umask 077; . deployments/compose/.secrets/mailbox-storage.env; \
		printf 'ELEMTA_MAILBOX_S3_ACCESS_KEY=%s\nELEMTA_MAILBOX_S3_SECRET_KEY=%s\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' \
			"$$MAILBOX_S3_ACCESS_KEY" "$$MAILBOX_S3_SECRET_KEY" "$$MAILBOX_S3_ACCESS_KEY" "$$MAILBOX_S3_SECRET_KEY" > $$f; }

k8s-ha-apply: k8s-ha-mailbox-config k8s-ha-config k8s-ha-secrets
	@echo "🚀 Applying deployments/kubernetes/dev/ha..."
	@$(KUSTOMIZE) $(K8S_DIR)/dev/ha | $(KUBECTL) apply -f - | grep -v ' unchanged$$' || true
	@$(KUBECTL) annotate namespace $(K8S_NAMESPACE) elemta.dev/overlay=ha --overwrite >/dev/null

# Build, apply, wait for each tier in the order they depend on each other,
# load the directory, then a dashboard login.
#
# K8S_HA comes from the namespace's annotation, but make expands the whole
# recipe before its first line runs, when a fresh install has no namespace
# yet; without this the restart below named the single-pod workloads.
k8s-install-ha: K8S_HA = ha
k8s-install-ha: check-tools k8s-check ensure-dev-certs
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx elemta-node0; then \
		echo "❌ The Compose dev stack is running and holds the same ports. 'make down' first."; \
		exit 1; \
	fi
	@cur=$(K8S_CURRENT_OVERLAY); if [ -n "$$cur" ] && [ "$$cur" != ha ]; then \
		echo "❌ The '$$cur' dev overlay is installed in $(K8S_NAMESPACE). 'make k8s-down-volumes' first."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory k8s-ha-operator
	@$(MAKE) --no-print-directory k8s-ha-edge
	@$(MAKE) --no-print-directory k8s-ha-images
	@$(MAKE) --no-print-directory k8s-ha-apply
	@echo "⏳ Waiting for Postgres (three instances)..."
	@$(KC) wait cluster/elemta-db --for=condition=Ready --timeout=10m >/dev/null
	@echo "⏳ Waiting for the directory and Valkey..."
	@$(KC) rollout status statefulset/elemta-ldap --timeout=5m >/dev/null
	@$(KC) rollout status statefulset/elemta-valkey --timeout=5m >/dev/null
	@ELEMTA_STACK=k8s K8S_NAMESPACE=$(K8S_NAMESPACE) ./scripts/init-ldap-if-needed.sh || true
	@# Images are pushed under the same tag; restart so every pod runs them.
	@$(KC) rollout restart $(K8S_OWN_IMAGES) >/dev/null
	@$(KC) rollout status statefulset/elemta-mta --timeout=10m >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
	@$(MAKE) --no-print-directory k8s-bootstrap-admin
	@$(MAKE) --no-print-directory k8s-ha-status
	@$(MAKE) --no-print-directory k8s-ha-ca

# The development CA that signs dev/ha's certificates, for the browser and
# the system store to trust, and the names to point at this machine.
k8s-ha-ca:
	@$(KC) wait certificate/elemta-dev-ca --for=condition=Ready --timeout=2m >/dev/null
	@mkdir -p $(K8S_HA_SECRETS) && chmod 700 $(K8S_HA_SECRETS)
	@$(KC) get secret elemta-dev-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > $(K8S_HA_SECRETS)/ca.crt
	@echo "🔐 Development CA: $(K8S_HA_SECRETS)/ca.crt"
	@echo "   Trust it in the browser (or: sudo trust anchor $(K8S_HA_SECRETS)/ca.crt), and add"
	@echo "   $$($(KUBECTL) -n haproxy-controller get svc haproxy-kubernetes-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}') admin.elemta.test webmail.elemta.test mail.elemta.test"
	@echo "   to /etc/hosts."

k8s-ha-status:
	@$(KC) get cluster.postgresql.cnpg.io,statefulsets,deployments,hpa,pdb 2>/dev/null
	@echo "Valkey primary: $$($(KC) exec elemta-valkey-0 -c sentinel -- valkey-cli -p 26379 sentinel get-master-addr-by-name elemta 2>/dev/null | head -n 1)"

# ── Linode (LKE) production ──────────────────────────────────────────────
# deployments/kubernetes/production/linode/README.md. The committed overlay
# is generic; one deployment's settings, generated config and secrets live
# in LINODE_INSTANCE, which git ignores.
LINODE_DIR = $(K8S_DIR)/production/linode
LINODE_INSTANCE ?= $(LINODE_DIR)/instance
LINODE_CONTEXT ?=

# The LDAP scripts and the CloudNativePG install use kubectl's current
# context, so every target checks it is the one named, not mercury's.
define LINODE_GUARD
	@test -n "$(LINODE_CONTEXT)" || { echo "❌ Set LINODE_CONTEXT to the LKE cluster's kube context."; exit 1; }
	@cur=$$($(KUBECTL) config current-context 2>/dev/null); test "$$cur" = "$(LINODE_CONTEXT)" || { \
		echo "❌ kubectl's current context is '$$cur', not '$(LINODE_CONTEXT)'."; \
		echo "   kubectl config use-context $(LINODE_CONTEXT), then run this again."; exit 1; }
endef

# Settings to fill in, the secrets to add, and the ones generated once.
linode-init:
	@mkdir -p $(LINODE_INSTANCE)/secrets && chmod 700 $(LINODE_INSTANCE) $(LINODE_INSTANCE)/secrets
	@[ -f $(LINODE_INSTANCE)/settings.env ] || cp $(LINODE_DIR)/template/settings.env $(LINODE_INSTANCE)/settings.env
	@s=$(LINODE_INSTANCE)/secrets; umask 077; \
	[ -f $$s/s3.env ] || printf '%s\n' \
		'# Linode Object Storage keys for the bucket in settings.env.' \
		'ELEMTA_MAILBOX_S3_ACCESS_KEY=CHANGE-ME' 'ELEMTA_MAILBOX_S3_SECRET_KEY=CHANGE-ME' \
		'AWS_ACCESS_KEY_ID=CHANGE-ME' 'AWS_SECRET_ACCESS_KEY=CHANGE-ME' > $$s/s3.env; \
	[ -f $$s/recovery-smtp.env ] || printf '%s\n' \
		'# The password of RECOVERY_SENDER (settings.env), which sends password resets.' \
		'ELEMTA_WEBMAIL_RECOVERY_SMTP_PASSWORD=CHANGE-ME' > $$s/recovery-smtp.env; \
	for u in mailbox queue; do f=$$s/db-$$u.env; [ -f $$f ] || \
		printf 'username=%s\npassword=%s\n' $$u "$$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)" > $$f; done
	@ELEMTA_SECRETS_DIR=$(LINODE_INSTANCE)/secrets ./scripts/dev-secrets.sh >/dev/null
	@echo "✅ $(LINODE_INSTANCE) ready (git-ignored). Next:"
	@echo "   1. Fill in $(LINODE_INSTANCE)/settings.env"
	@echo "   2. Replace CHANGE-ME in secrets/s3.env and secrets/recovery-smtp.env"
	@echo "   3. make linode-config linode-check"
	@echo "   Back up $(LINODE_INSTANCE): its secrets exist nowhere else."

# The deployment from settings.env: the kustomization, and config/elemta.toml
# and config/mailbox-main.toml with this deployment's names, TLS, storage
# and networks. Regenerate after changing settings.env or those files.
linode-config:
	@[ -f $(LINODE_INSTANCE)/settings.env ] || { echo "❌ make linode-init first"; exit 1; }
	@set -a; . $(LINODE_INSTANCE)/settings.env; set +a; i=$(LINODE_INSTANCE); \
	sed "s|@IMAGE_TAG@|$$IMAGE_TAG|" $(LINODE_DIR)/template/kustomization.yaml > $$i/kustomization.yaml; \
	cp $(LINODE_DIR)/template/namespace.yaml $$i/namespace.yaml; \
	printf '# Generated by make linode-config from settings.env.\nWEBMAIL_URL=https://%s\n' "$$WEBMAIL_HOST" > $$i/derived.env; \
	sed -e "s|^hostname = .*|hostname = \"$$MAIL_HOST\"|" \
		-e "s|^local_domains = .*|local_domains = [\"$$MAIL_DOMAIN\", \"$$MAIL_HOST\"]|" \
		-e 's|^mode = "lmtp"|mode = "split"|' \
		-e 's|^cert_file = .*|cert_file = "/app/public-tls/tls.crt"|' \
		-e 's|^key_file = .*|key_file = "/app/public-tls/tls.key"|' \
		-e 's|^lmtp_tls_ca_file = .*|lmtp_tls_ca_file = ""|' \
		-e "s|^lmtp_tls_server_name = .*|lmtp_tls_server_name = \"$$MAIL_HOST\"|" \
		-e "s|^allowed_origins = .*|allowed_origins = [\"https://$$ADMIN_HOST\"]|" \
		-e 's|^secure_cookies = .*|secure_cookies = true|' \
		-e "s|^recovery_url = .*|recovery_url = \"https://$$WEBMAIL_HOST\"|" \
		-e "s|^recovery_sender = .*|recovery_sender = \"$$RECOVERY_SENDER\"|" \
		-e "s|^recovery_smtp_user = .*|recovery_smtp_user = \"$$RECOVERY_SENDER\"|" \
		-e "s|^\\[webmail\\]$$|&\\ntrusted_proxies = [\"$$POD_CIDR\"]|" \
		-e "s|^\\[api.rate_limit\\]$$|&\\ntrusted_proxies = [\"$$POD_CIDR\"]|" \
		config/elemta.toml > $$i/elemta.toml; \
	sed -e "s|^lmtp_allowed_networks = .*|lmtp_allowed_networks = [\"$$POD_CIDR\", \"127.0.0.0/8\"]|" \
		-e 's|^require_synchronous_replication = .*|require_synchronous_replication = true|' \
		-e 's|^driver = "file"|driver = "s3"|' \
		-e "s|^endpoint = .*|endpoint = \"$$S3_ENDPOINT\"|" \
		-e "s|^bucket = .*|bucket = \"$$S3_BUCKET\"|" \
		-e "s|^region = .*|region = \"$$S3_REGION\"|" \
		-e 's|^secure = false|secure = true|' \
		-e "s|^default_domain = .*|default_domain = \"$$MAIL_DOMAIN\"|" \
		-e "s|^hostname = .*|hostname = \"$$MAIL_HOST\"|" \
		config/mailbox-main.toml > $$i/mailbox.toml; \
	for want in 'mode = "split"' '/app/public-tls/tls.crt' 'lmtp_tls_ca_file = ""' 'secure_cookies = true' \
		"recovery_url = \"https://$$WEBMAIL_HOST\"" "recovery_sender = \"$$RECOVERY_SENDER\""; do \
		grep -qF "$$want" $$i/elemta.toml || { echo "❌ config/elemta.toml changed shape; could not set $$want"; exit 1; }; done; \
	[ "$$(grep -cF "trusted_proxies = [\"$$POD_CIDR\"]" $$i/elemta.toml)" = 2 ] || { echo "❌ config/elemta.toml changed shape; could not set trusted_proxies"; exit 1; }; \
	for want in 'driver = "s3"' "endpoint = \"$$S3_ENDPOINT\"" 'secure = true' 'require_synchronous_replication = true' \
		"default_domain = \"$$MAIL_DOMAIN\"" "\"$$POD_CIDR\", \"127.0.0.0/8\""; do \
		grep -qF "$$want" $$i/mailbox.toml || { echo "❌ config/mailbox-main.toml changed shape; could not set $$want"; exit 1; }; done
	@ELEMTA_SECRETS_DIR=$(LINODE_INSTANCE)/secrets ./scripts/dev-secrets.sh >/dev/null
	@echo "✅ Generated $(LINODE_INSTANCE) from settings.env"

# Refuses example values, missing secrets, or a build that doesn't render.
# With LINODE_CONTEXT set, also checks the cluster has what it needs.
linode-check:
	@i=$(LINODE_INSTANCE); [ -f $$i/kustomization.yaml ] || { echo "❌ make linode-config first"; exit 1; }; bad=0; \
	if grep -nE '^[A-Z_]+=.*(example\.(com|net)|elemta-mail-example)|^IMAGE_TAG=v0\.0\.0' $$i/settings.env; then \
		echo "❌ settings.env still has example values (above)"; bad=1; fi; \
	if grep -l CHANGE-ME $$i/secrets/s3.env $$i/secrets/recovery-smtp.env 2>/dev/null; then \
		echo "❌ replace CHANGE-ME in the secrets above"; bad=1; fi; \
	if grep -nE '^[^#]*("[^"]*@?example\.(com|net)"|localhost:80)' $$i/elemta.toml $$i/mailbox.toml; then \
		echo "❌ generated config still names example hosts (above)"; bad=1; fi; \
	$(KUSTOMIZE) $$i >/dev/null || { echo "❌ the deployment doesn't render"; bad=1; }; \
	if [ -n "$(LINODE_CONTEXT)" ]; then \
		set -a; . $$i/settings.env; set +a; k="$(KUBECTL) --context $(LINODE_CONTEXT)"; \
		$$k get storageclass "$$RWX_STORAGE_CLASS" >/dev/null 2>&1 || { echo "❌ no StorageClass $$RWX_STORAGE_CLASS (README.md, Storage)"; bad=1; }; \
		$$k get crd clusters.postgresql.cnpg.io >/dev/null 2>&1 || { echo "❌ CloudNativePG not installed: make linode-edge"; bad=1; }; \
		$$k get ingressclass haproxy >/dev/null 2>&1 || { echo "❌ HAProxy ingress not installed: make linode-edge"; bad=1; }; \
		echo "ℹ️  Node pod networks: $$($$k get nodes -o jsonpath='{.items[*].spec.podCIDR}') (POD_CIDR=$$POD_CIDR must contain them)"; \
	fi; \
	[ $$bad = 0 ] && echo "✅ $(LINODE_INSTANCE) is ready to apply"; exit $$bad

# cert-manager, the HAProxy ingress with Linode's settings, and the
# CloudNativePG operator, once per cluster.
linode-edge:
	$(LINODE_GUARD)
	@EDGE_CONTEXT=$(LINODE_CONTEXT) EDGE_HAPROXY_VALUES=$(LINODE_DIR)/haproxy-values.yaml HELM=$(HELM) \
		$(K8S_DIR)/production/edge/install-controllers.sh
	@$(MAKE) --no-print-directory k8s-ha-operator

# Apply, then wait for the directory and give it its service accounts:
# the schema and accounts only, never the dev fixture users.
# The namespace is marked like dev/ha's so the k8s-* helpers (status,
# logs, admin passwords) work against it from this machine.
linode-apply: linode-check
	$(LINODE_GUARD)
	@$(KUSTOMIZE) $(LINODE_INSTANCE) | $(KUBECTL) apply -f - | grep -v ' unchanged$$' || true
	@$(KUBECTL) annotate namespace $(K8S_NAMESPACE) elemta.dev/overlay=ha --overwrite >/dev/null
	@echo "⏳ Waiting for Postgres and the directory..."
	@$(KC) wait cluster/elemta-db --for=condition=Ready --timeout=15m >/dev/null
	@$(KC) rollout status statefulset/elemta-ldap --timeout=10m >/dev/null
	@for s in ldap-schema ldap-admin-password ldap-service-accounts; do \
		ELEMTA_STACK=k8s K8S_NAMESPACE=$(K8S_NAMESPACE) ELEMTA_SECRETS_DIR=$(LINODE_INSTANCE)/secrets ./scripts/$$s.sh || exit 1; \
	done
	@$(KC) get certificate,ingress,svc
	@echo "✅ Applied. Point DNS at the EXTERNAL-IPs above, then: make linode-admin"

# The first dashboard login.
linode-admin:
	$(LINODE_GUARD)
	@set -a; . $(LINODE_INSTANCE)/settings.env; set +a; \
	$(MAKE) --no-print-directory k8s-bootstrap-admin K8S_ADMIN_URL=https://$$ADMIN_HOST/

k8s-sink-up:
	@if [ -n "$(K8S_HA)" ]; then \
		echo "❌ The replicated overlay has no sink; it always delivers to the mailbox service."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-sink DELIVERY_PORT=2424
	@ov=$(K8S_CURRENT_OVERLAY); $(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$${ov:-minimal} >/dev/null
	@$(MAKE) --no-print-directory k8s-reseed >/dev/null
	@echo "✅ Delivery goes to the sink (elemta-sink:2424). Mail is discarded."
	@echo "   Sink rate:  kubectl -n $(K8S_NAMESPACE) logs -f deploy/elemta-sink"

k8s-sink-down:
	@if [ -n "$(K8S_HA)" ]; then \
		echo "❌ The replicated overlay has no sink; it always delivers to the mailbox service."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-mailbox DELIVERY_PORT=2424
	@ov=$(K8S_CURRENT_OVERLAY); $(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$${ov:-minimal} >/dev/null
	@$(MAKE) --no-print-directory k8s-reseed >/dev/null
	@echo "✅ Delivery goes to the mailbox service; mail lands in real mailboxes."

# The users file lives on the runtime volume, so these run inside the pod. The
# server re-reads the file when it changes, so nothing needs restarting.
k8s-bootstrap-admin:
	@needs_account=1; \
	if $(KC) exec $(K8S_ADMIN_TARGET) -c admin -- test -e /app/runtime-config/users.json 2>/dev/null; then \
		if ! $(K8S_ADMIN_EXEC) user list --file /app/runtime-config/users.json 2>/dev/null | grep -q '^No users'; then \
			needs_account=0; \
		fi; \
	fi; \
	if [ "$$needs_account" = "0" ]; then \
		echo "ℹ️  Dashboard account already exists (make k8s-reset-admin-password to change it)"; \
	else \
		PW="$(ADMIN_PASSWORD)"; \
		if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
		if printf '%s\n' "$$PW" | $(K8S_ADMIN_EXEC) user add $(ADMIN_USER) --file /app/runtime-config/users.json >/dev/null 2>&1; then \
			echo ""; \
			echo "🔑 Dashboard login created"; \
			echo "   URL:      $(K8S_ADMIN_URL)"; \
			echo "   Username: $(ADMIN_USER)"; \
			echo "   Password: $$PW"; \
			echo "   (shown once — make k8s-reset-admin-password if you lose it)"; \
			echo ""; \
		else \
			echo "❌ Could not create the dashboard account"; \
		fi; \
	fi

k8s-reset-admin-password:
	@PW="$(ADMIN_PASSWORD)"; \
	if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
	OUT=$$(printf '%s\n' "$$PW" | $(K8S_ADMIN_EXEC) user passwd $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
	if [ $$? -ne 0 ]; then \
		OUT=$$(printf '%s\n' "$$PW" | $(K8S_ADMIN_EXEC) user add $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
		if [ $$? -ne 0 ]; then \
			echo "❌ Could not set the password (is the stack running? make k8s-status):"; \
			echo "$$OUT" | sed 's/^/   /'; \
			exit 1; \
		fi; \
		echo "ℹ️  No account existed, so one was created."; \
	fi; \
	echo ""; \
	echo "🔑 Dashboard login"; \
	echo "   URL:      $(K8S_ADMIN_URL)"; \
	echo "   Username: $(ADMIN_USER)"; \
	echo "   Password: $$PW"; \
	echo ""

k8s-print-dev-summary:
	@echo ""
	@echo "✅ Development Environment Ready (Kubernetes, namespace $(K8S_NAMESPACE))"
	@echo "   📧 SMTP:      localhost:2525"
	@echo "   📊 Metrics:   http://localhost:9080/metrics"
	@echo "   🌐 Web UI:    $(K8S_ADMIN_URL)  (login required)"
	@echo "   ✉️  Webmail:   $(K8S_WEBMAIL_URL)  ·  IMAP: localhost:993 (TLS)"
	@target=$$($(KC) exec $(K8S_MTA) -c smtp -- sh -c "sed -n '/^\[delivery\]/,/^\[/p' /app/runtime-config/elemta.toml | grep -m1 '^host'" 2>/dev/null | sed 's/.*= *//; s/"//g'); \
	if [ "$$target" = "elemta-sink" ]; then \
		echo "   📭 Delivery:  a DISCARDING SINK. make k8s-sink-down for real mailboxes."; \
	elif [ -n "$$target" ]; then \
		echo "   📬 Delivery:  $$target — mail lands in real mailboxes."; \
	fi
	@echo "   👤 Mailbox user:   user@example.com / password"
	@echo "   📋 make k8s-status | k8s-logs | k8s-help"

# 'down' keeps everything but the running pods, as 'docker compose down' keeps
# the volumes; 'up' brings them back.
# The replicated overlay is scaled back by applying it again, which restores
# every replica count, and its Postgres is hibernated and woken through the
# operator rather than scaled.
k8s-up: k8s-check
	@if [ -n "$(K8S_HA)" ]; then \
		$(KC) annotate cluster elemta-db cnpg.io/hibernation=off --overwrite >/dev/null; \
		$(MAKE) --no-print-directory k8s-ha-apply >/dev/null; \
		$(KC) wait cluster/elemta-db --for=condition=Ready --timeout=10m >/dev/null; \
	else \
		$(KC) scale deployment --all --replicas=1 >/dev/null; \
		$(KC) scale deployment elemta-mailbox --replicas=2 >/dev/null 2>&1 || true; \
	fi
	@$(MAKE) --no-print-directory k8s-wait

k8s-down:
	@$(KC) scale deployment --all --replicas=0 >/dev/null
	@if [ -n "$(K8S_HA)" ]; then \
		$(KC) scale statefulset --all --replicas=0 >/dev/null; \
		$(KC) annotate cluster elemta-db cnpg.io/hibernation=on --overwrite >/dev/null; \
	fi
	@echo "✅ Stopped (volumes kept; make k8s-up to start again)"

k8s-down-volumes:
	@$(KUBECTL) delete namespace $(K8S_NAMESPACE) --ignore-not-found --wait=true
	@echo "✅ Namespace $(K8S_NAMESPACE) and its volumes removed"

k8s-restart:
	@$(KC) rollout restart deployment >/dev/null
	@$(KC) rollout restart statefulset >/dev/null 2>&1 || true
	@$(MAKE) --no-print-directory k8s-wait

k8s-status:
	@$(KC) get pods,services -o wide

k8s-logs:
	$(KC) logs -f --tail=50 --prefix --all-containers --max-log-requests=30 -l app.kubernetes.io/part-of=elemta

k8s-logs-elemta:
	$(KC) logs -f --tail=100 --prefix -l $(K8S_MTA_PODS) -c smtp

# Rebuild the images and roll the pods that run them. Config is left alone.
k8s-rebuild:
	@$(MAKE) --no-print-directory $(if $(K8S_HA),k8s-ha-images,k8s-images) DOCKER_BUILD_FLAGS=--no-cache
	@$(KC) rollout restart $(K8S_OWN_IMAGES) >/dev/null
	@$(MAKE) --no-print-directory k8s-wait

k8s-rebuild-dev:
	@$(MAKE) --no-print-directory $(if $(K8S_HA),k8s-ha-images,k8s-images)
	@$(KC) rollout restart $(K8S_OWN_IMAGES) >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
