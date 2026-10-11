.PHONY: all help gotchas build clean clean-certs certs install install-dev install-dev-full install-dev-postgres install-dev-mailauth \
	elk-up elk-down elk-status elk-dashboard elk-dashboard-check stress-corpus rspamd-train bench-queue sink-up sink-down configure-delivery-target \
	mailauth-check mailauth-check-fail \
	configure-queue-backend configure-plugins bootstrap-admin reset-admin-password ensure-dev-certs print-dev-summary check-tools \
	install-dev-bench uninstall run test test-load test-race-smoke test-dev test-docker up down down-volumes restart logs logs-elemta status \
	rebuild rebuild-dev docker docker-build docker-setup docker-down update lint lint-fix fmt \
	k8s-check k8s-images k8s-load k8s-apply k8s-install k8s-wait reseed

# The dev stack runs on Kubernetes (a single-node k3s on the dev box; see
# deployments/kubernetes/README.md). Each install-dev target applies one
# overlay under deployments/kubernetes/dev:
#   minimal   Elemta, caching DNS, LDAP, Dovecot, Valkey, LMTP sink
#   full      + ClamAV, Rspamd, Roundcube
#   bench     + ClamAV, Rspamd (delivery goes to the sink)
#   postgres  + Postgres for the queue
# elemta-sink runs in every dev stack but is not the delivery target: keeping it
# up means 'make sink-up' is a reseed rather than a deploy, and mail still goes
# to a real mailbox until someone asks otherwise.
KUBECTL ?= kubectl
K8S_NAMESPACE ?= elemta
K8S_DIR ?= deployments/kubernetes
K8S_OVERLAY ?= minimal
# The overlays read config/elemta.toml and the LDAP, Rspamd and Roundcube files
# from where they live in the repository, outside the kustomization's own
# directory, which kustomize refuses by default.
KUSTOMIZE = $(KUBECTL) kustomize --load-restrictor LoadRestrictionsNone
KC = $(KUBECTL) -n $(K8S_NAMESPACE)
# Applying an overlay removes what the previous one added and this one does
# not (Roundcube when going from full to minimal), as 'up -d <services>' never
# did. Volumes are not in the list on purpose: switching stacks must not take
# the ClamAV signatures or the Rspamd Bayes data with it. down-volumes does.
K8S_PRUNE = --prune -l app.kubernetes.io/part-of=elemta \
	--prune-allowlist=apps/v1/Deployment --prune-allowlist=core/v1/Service \
	--prune-allowlist=core/v1/ConfigMap --prune-allowlist=core/v1/Secret
# Images the dev stack builds rather than pulls.
IMAGE_TAG ?= dev
DOCKER_BUILD_FLAGS ?=
# How built images reach the cluster. auto works it out from the node:
#   docker  k3s running on Docker (k3s --docker) sees Docker's images already
#   kind    kind load docker-image
#   k3s     docker save | sudo k3s ctr images import  (asks for sudo)
K8S_IMAGE_LOAD ?= auto

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
POSTGRES_USER ?= elemta
POSTGRES_DB ?= elemta_queue

# Default target
all: build

# The knowledge that is not derivable from reading the targets. Split out of
# help because 26 lines of prose under 65 lines of target list means neither
# gets read.
gotchas:
	@echo "💡 Things that surprise people:"
	@echo "  • Benchmarks against Dovecot measure Dovecot (~70/s: maildir writes, indexing)."
	@echo "    'make sink-up' points delivery at a sink that absorbs ~4500/s, so the number"
	@echo "    is about Elemta. Mail is discarded while it is on; 'make sink-down' undoes it."
	@echo "  • Editing config/elemta.toml does not change a running stack. The services read a"
	@echo "    copy on a shared volume, seeded once, because the web UI writes to it too."
	@echo "    'make install-dev' and 'make reseed' re-seed from the file; 'up' and 'restart' do not."
	@echo "  • Scanner, allow/deny, blocklist and inbound mail-auth verification changes apply"
	@echo "    on their own within ~5 seconds. Listen address, size limits, timeouts, queue"
	@echo "    backend and ARC sealing need a restart; the UI and logs say so."
	@echo "  • The dev stack is Kubernetes (k3s). Images are built locally and loaded into the"
	@echo "    cluster; on plain k3s that is 'sudo k3s ctr images import', so a build asks for"
	@echo "    sudo. Run k3s with --docker (see deployments/kubernetes/README.md) to skip it."
	@echo "  • The mail-auth lab and ELK have not moved to Kubernetes yet; their targets say so."
	@echo "  • Logs are line-delimited JSON on stdout and in /app/logs/elemta.log. Only"
	@echo "    'level' from [logging] is read; type/output/file are ignored and the server"
	@echo "    warns if they are set. Shipping is 'make elk-up', which reads the log volume"
	@echo "    rather than making the mail server depend on a log store being up."
	@echo "    On Kubernetes the stdout half is 'make logs-elemta'."
	@echo "  • The dev TLS certificate expires in $(CERT_DAYS) days on purpose, so the expiry warning on"
	@echo "    the Health page is exercised. It is regenerated when it lapses."
	@echo "  • The dev stack is self-signed and its ports listen on every interface (k3s's"
	@echo "    service load balancer). Fine on a laptop; firewall them if it is not isolated."
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

# Local server run (for debugging outside the cluster)
run: build
	@echo "Running Elemta server locally (not in the cluster)..."
	@echo "⚠️  For normal use, run: make install-dev"
	./bin/elemta server --dev

# Test targets
test:
	@echo "Running Go tests..."
	@echo "⚠️  Note: Some packages require the dev stack to be running"
	@echo "For complete integration tests, run: make test-dev"
	@go test -v -short -timeout 60s ./internal/antispam ./internal/api ./internal/auth ./internal/datasource ./internal/delivery ./internal/plugin ./internal/queue 2>&1; \
	status=$$?; \
	echo ""; \
	if [ $$status -eq 0 ]; then \
		echo "✅ All unit tests passed"; \
	else \
		echo "⚠️  Some unit tests failed (exit code: $$status)"; \
		echo "Note: Integration tests may require the dev stack"; \
	fi; \
	echo "💡 Run 'make test-dev' for full integration test suite (21 tests)"; \
	exit $$status

test-centralized:
	@echo "Running centralized test suite..."
	./tests/run_centralized_tests.sh

init-test-env:
	@echo "🔧 Initializing test environment..."
	@./scripts/init-ldap-users.sh
	@echo "✅ Test environment ready"

test-dev: init-test-env
	@echo "Running dev stack integration tests..."
	./tests/run_centralized_tests.sh --deployment docker-dev

# The old name, from when the dev stack was Compose.
test-docker: test-dev

test-auth: ## Quick authentication test
	@echo "Running authentication test..."
	./install/test-auth.sh

test-security:
	@echo "Running security tests..."
	./tests/run_centralized_tests.sh --category security

test-load:
	@echo "Running SMTP load tests..."
	@echo "⚠️  Note: Requires the dev stack running (make install-dev-full)"
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

# Kubernetes plumbing for the dev stack.

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

# The three images the dev stack builds rather than pulls: Elemta from this
# tree, Dovecot with the stack's config baked in, and the caching resolver.
k8s-images:
	@echo "🔨 Building images ($(IMAGE_TAG))..."
	docker build $(DOCKER_BUILD_FLAGS) --build-arg VERSION=$$(git rev-parse --short HEAD 2>/dev/null || echo dev) -t elemta:$(IMAGE_TAG) .
	docker build $(DOCKER_BUILD_FLAGS) -t elemta-dovecot:$(IMAGE_TAG) docker/dovecot
	docker build $(DOCKER_BUILD_FLAGS) -t elemta-dns:$(IMAGE_TAG) deployments/dns
	@$(MAKE) --no-print-directory k8s-load

# A cluster does not see Docker's images unless it runs on Docker. Detected
# from the node rather than configured, so the same command works on k3s, k3s
# with --docker, and kind.
k8s-load:
	@mode="$(K8S_IMAGE_LOAD)"; \
	if [ "$$mode" = "auto" ]; then \
		runtime=$$($(KUBECTL) get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null); \
		context=$$($(KUBECTL) config current-context 2>/dev/null); \
		case "$$runtime" in docker://*) mode=docker ;; *) \
			case "$$context" in kind-*) mode=kind ;; *) mode=k3s ;; esac ;; \
		esac; \
	fi; \
	images="elemta:$(IMAGE_TAG) elemta-dovecot:$(IMAGE_TAG) elemta-dns:$(IMAGE_TAG)"; \
	case "$$mode" in \
		docker|none) echo "ℹ️  The cluster runs on Docker; images are already visible to it" ;; \
		kind) context=$$($(KUBECTL) config current-context); \
			kind load docker-image --name "$${context#kind-}" $$images ;; \
		k3s) echo "📦 Importing images into k3s (sudo k3s ctr images import)..."; \
			docker save $$images | sudo k3s ctr images import - ;; \
		*) echo "❌ Unknown K8S_IMAGE_LOAD=$$mode (auto|docker|kind|k3s|none)"; exit 1 ;; \
	esac

# Apply one overlay of the dev stack. See K8S_PRUNE for what switching removes.
k8s-apply:
	@echo "🚀 Applying deployments/kubernetes/dev/$(K8S_OVERLAY)..."
	@$(KUSTOMIZE) $(K8S_DIR)/dev/$(K8S_OVERLAY) | $(KUBECTL) apply $(K8S_PRUNE) -f - | grep -v ' unchanged$$' || true
	@# Remembered on the namespace, so sink-up and friends re-apply the stack
	@# that is running rather than the default one, which would prune the rest.
	@$(KUBECTL) annotate namespace $(K8S_NAMESPACE) elemta.dev/overlay=$(K8S_OVERLAY) --overwrite >/dev/null

# The overlay currently applied, for targets that change config on a running
# stack. Falls back to minimal before anything has been installed.
CURRENT_OVERLAY = $$($(KUBECTL) get namespace $(K8S_NAMESPACE) -o jsonpath='{.metadata.annotations.elemta\.dev/overlay}' 2>/dev/null || true)

# Wait for every Deployment to roll out. ClamAV downloads its signatures on a
# fresh volume, which is why the timeout is long; nothing else needs it.
k8s-wait:
	@echo "⏳ Waiting for the stack to become ready..."
	@for d in $$($(KC) get deployments -o name); do \
		$(KC) rollout status $$d --timeout=10m >/dev/null || { echo "❌ $$d did not become ready:"; $(KC) describe $$d | tail -15; exit 1; }; \
	done
	@echo "✅ All deployments ready"

# Make the next start take config/elemta.toml again, discarding what the web UI
# saved. The compose stack did this with ELEMTA_CONFIG_RESEED and a marker in
# the container; here it is explicit: remove the seeded copy and restart, and
# prepare-config.sh seeds a new one from the ConfigMap.
reseed:
	@$(KC) exec deploy/elemta -c smtp -- rm -f /app/runtime-config/elemta.toml 2>/dev/null || true
	@$(KC) rollout restart deploy/elemta >/dev/null
	@$(KC) rollout status deploy/elemta --timeout=5m >/dev/null
	@echo "✅ Runtime config re-seeded from config/elemta.toml"

# What every install-dev target does, for one overlay. Separate from the
# targets so the steps are in one place: build, configure, apply, re-seed, then
# accounts.
k8s-install: check-tools k8s-check ensure-dev-certs k8s-images
	@$(MAKE) --no-print-directory configure-queue-backend QUEUE_BACKEND=$(QUEUE_BACKEND) QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) --no-print-directory configure-plugins
	@$(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$(K8S_OVERLAY)
	@$(MAKE) --no-print-directory k8s-wait
	@# This install is authoritative: without the reseed the settings configured
	@# above would be ignored on every deploy after the first. And images are
	@# rebuilt under the same tag, so a Deployment whose spec did not change
	@# would keep running the old one. One restart of what runs our images
	@# covers both.
	@$(KC) exec deploy/elemta -c smtp -- rm -f /app/runtime-config/elemta.toml
	@$(KC) rollout restart deploy/elemta deploy/elemta-sink deploy/elemta-dovecot deploy/elemta-dns >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
	@echo "⏳ Initializing LDAP..."
	@./scripts/init-ldap-if-needed.sh || true
	@$(MAKE) --no-print-directory bootstrap-admin

# The old names.
docker-build: k8s-images
docker: install-dev

# Advanced/internal targets (not shown in help)

# Legacy CLI targets (cli tools built by main 'build' target)
cli-install: build
	@echo "Installing elemta-cli to $(GOPATH)/bin..."
	@cp bin/elemta-cli $(GOPATH)/bin/ 2>/dev/null || echo "⚠️  GOPATH not set, skipping install"

# Legacy docker targets (use 'up'/'down' instead)
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
# runtime volume, so this runs inside the pod: it has to be written by the user
# that reads it, and the host cannot write there. The server re-reads the file
# when it changes, so nothing needs restarting afterwards.
WEB_EXEC = $(KC) exec -i deploy/elemta -c web -- /app/elemta --config /app/runtime-config/elemta.toml
bootstrap-admin:
	@# Whether an *account* exists, not whether the file does: the runtime setup
	@# leaves an empty `{}` there so the service can start locked, and testing
	@# for the file would read that as an account and skip the bootstrap.
	@needs_account=1; \
	if $(KC) exec deploy/elemta -c web -- test -e /app/runtime-config/users.json 2>/dev/null; then \
		if ! $(WEB_EXEC) user list --file /app/runtime-config/users.json 2>/dev/null | grep -q '^No users'; then \
			needs_account=0; \
		fi; \
	fi; \
	if [ "$$needs_account" = "0" ]; then \
		echo "ℹ️  Dashboard account already exists (make reset-admin-password to change it)"; \
	else \
		PW="$(ADMIN_PASSWORD)"; \
		if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
		if printf '%s\n' "$$PW" | $(WEB_EXEC) user add $(ADMIN_USER) --file /app/runtime-config/users.json >/dev/null 2>&1; then \
			echo ""; \
			echo "🔑 Dashboard login created"; \
			echo "   URL:      http://localhost:8025/"; \
			echo "   Username: $(ADMIN_USER)"; \
			echo "   Password: $$PW"; \
			echo "   (shown once — make reset-admin-password if you lose it)"; \
			echo ""; \
		else \
			echo "❌ Could not create the dashboard account"; \
		fi; \
	fi

# Set a new password for the dashboard account, for when the generated one is
# lost — which is the normal outcome of a password shown once.
reset-admin-password:
	@PW="$(ADMIN_PASSWORD)"; \
	if [ -z "$$PW" ]; then PW=$$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20); fi; \
	if [ "$$($(KC) get deployment elemta -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" != "1" ]; then \
		echo "❌ The dev stack is not running — start it first (make up, or make install-dev)"; \
		exit 1; \
	fi; \
	OUT=$$(printf '%s\n' "$$PW" | $(WEB_EXEC) user passwd $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
	if [ $$? -ne 0 ]; then \
		OUT=$$(printf '%s\n' "$$PW" | $(WEB_EXEC) user add $(ADMIN_USER) --file /app/runtime-config/users.json 2>&1); \
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
	echo ""


check-tools:
	@for tool in docker $(KUBECTL) python3 openssl; do \
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

print-dev-summary:
	@echo ""
	@echo "✅ Development Environment Ready!"
	@echo "=================================="
	@echo "   📧 SMTP:      localhost:2525"
	@echo "   📊 Metrics:   http://localhost:9080/metrics"
	@echo "   🌐 Web UI:    http://localhost:8025  (login required)"
	@echo ""
	@# Report where mail actually goes rather than asserting it. The two installs
	@# differ on this, and a summary that guesses is worse than none.
	@target=$$($(KC) exec deploy/elemta -c smtp -- sh -c "sed -n '/^\[delivery\]/,/^\[/p' /app/runtime-config/elemta.toml | grep -m1 '^host'" 2>/dev/null | sed 's/.*= *//; s/"//g'); \
	if [ "$$target" = "elemta-sink" ]; then \
		echo "   📭 Delivery:  a DISCARDING SINK. Delivered mail is not stored anywhere."; \
		echo "                 make sink-down   → real mailboxes + Roundcube"; \
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
	@echo "   make test-load   # Run load tests"
	@echo "   make help        # Variables, plugin toggles, and the gotchas"

# Help target
help:
	@echo "Elemta - High Performance SMTP Server"
	@echo ""
	@echo "⚡ Quick Start (the dev stack runs on Kubernetes; see deployments/kubernetes/README.md):"
	@echo "  make install-dev              # Minimal dev stack, plugins on, prints a dashboard login"
	@echo "  make install-dev-full         # Everything, incl. ClamAV, Rspamd, Roundcube"
	@echo "  make install-dev-bench        # Scanners on, delivery DISCARDED — for throughput work"
	@echo "  make install-dev-postgres     # Dev stack with a Postgres queue"
	@echo "  make install-dev-mailauth     # (not on Kubernetes yet)"
	@echo "  make install                  # Interactive production setup (Compose)"
	@echo ""
	@echo "🔑 Accounts & Access:"
	@echo "  Web UI            http://localhost:8025  (login required — there is no guest access)"
	@echo "  bootstrap-admin       - Create the dashboard account; prints the password once"
	@echo "  reset-admin-password  - Generate and print a new password for it"
	@echo "                          ADMIN_USER=name ADMIN_PASSWORD=secret to choose your own"
	@echo "  The dashboard login is NOT the mailbox login. Mailbox users live in LDAP;"
	@echo "  the dashboard account lives in the users file and is managed with:"
	@echo "    kubectl -n $(K8S_NAMESPACE) exec -it deploy/elemta -c web -- /app/elemta \\"
	@echo "      --config /app/runtime-config/elemta.toml user list|add|passwd|remove"
	@echo "  The server re-reads that file when it changes; nothing needs restarting."
	@echo ""
	@echo "☸️  Services (namespace $(K8S_NAMESPACE)):"
	@echo "  up             - Start the stack again after 'down'"
	@echo "  down           - Stop everything (scale to zero), keep volumes"
	@echo "  down-volumes   - Delete the namespace: queue, config, mailboxes and login all go"
	@echo "  restart        - Restart all deployments"
	@echo "  rebuild        - Rebuild images without cache, load them, restart"
	@echo "  rebuild-dev    - Rebuild images with cache, load them, restart"
	@echo "  reseed         - Take config/elemta.toml again, discarding what the UI saved"
	@echo "  status         - Pods and services"
	@echo "  logs           - Follow all logs        logs-elemta - Elemta SMTP logs only"
	@echo ""
	@echo "⚙️  Configuration:"
	@echo "  configure-plugins        - Apply the PLUGIN_* settings below to config/elemta.toml"
	@echo "  configure-queue-backend  - Set the queue backend (QUEUE_BACKEND=file|sqlite|postgres)"
	@echo "  certs / clean-certs      - Generate or remove the dev TLS certificate"
	@echo ""
	@echo "📊 Logs & Observability:"
	@echo "  elk-up         - (not on Kubernetes yet)"
	@echo "  elk-dashboard  - Import the Elemta overview dashboard into Kibana"
	@echo "  elk-dashboard-check - Verify every dashboard panel has data behind it"
	@echo "  stress-corpus  - Send the message corpus at volume (MESSAGES=300 CONCURRENCY=10)"
	@echo "  bench-queue    - Measure DELIVERY throughput: fill the queue, then time the drain"
	@echo "  sink-up        - Discard delivered mail (~4500/s) so benchmarks measure Elemta"
	@echo "  sink-down      - Delivery to real mailboxes (Roundcube at :8026 on the full stack)"
	@echo "  rspamd-train   - Train Bayes from a labelled corpus and measure it on held-out mail"
	@echo "                   SPAM_DIR=/path/to/spam [HAM_DIR=... TRAIN=2000 TEST=200]"
	@echo "  elk-status     - Cluster health and how many events are indexed"
	@echo "  elk-down       - Stop them (indexed logs are kept in their volume)"
	@echo "  Kibana http://localhost:5601 > Discover > elemta-*   Elasticsearch :9200"
	@echo "  Adds to whatever dev stack is running; it changes nothing about Elemta."
	@echo ""
	@echo "🔧 Build & Test:"
	@echo "  build          - Build all binaries (server, queue, cli)   clean - Remove artifacts"
	@echo "  test           - Go unit tests            test-dev       - Integration suite"
	@echo "  test-load      - SMTP load tests          test-race-smoke - Session race checks"
	@echo "  test-auth      - Authentication tests     test-security  - Security tests"
	@echo "  lint / lint-fix / fmt   - Code quality"
	@echo "  On an install-dev-mailauth stack:"
	@echo "    mailauth-check       - Send a message that should pass SPF, DKIM and DMARC"
	@echo "    mailauth-check-fail  - Send one that fails SPF and DMARC; it is still accepted"
	@echo "                           because enforcement is off. Read both at :8027"
	@echo ""
	@echo "🎛️  Variables (override on the command line):"
	@echo "  ADMIN_USER=admin              Dashboard account name"
	@echo "  ADMIN_PASSWORD=               Dashboard password (generated when empty)"
	@echo "  CERT_DAYS=$(CERT_DAYS)                  Dev certificate lifetime, in days"
	@echo "  K8S_IMAGE_LOAD=$(K8S_IMAGE_LOAD)           How images reach the cluster: auto | docker | kind | k3s | none"
	@echo "  KUBECTL=$(KUBECTL)  K8S_NAMESPACE=$(K8S_NAMESPACE)"
	@echo "  QUEUE_BACKEND=$(QUEUE_BACKEND)           file | sqlite | postgres"
	@echo "  PLUGIN_RATE_LIMITER=$(PLUGIN_RATE_LIMITER)      PLUGIN_CLAMAV=$(PLUGIN_CLAMAV)   PLUGIN_RSPAMD=$(PLUGIN_RSPAMD)"
	@echo "  PLUGIN_ACCESS_CONTROL=$(PLUGIN_ACCESS_CONTROL)    PLUGIN_RBL=$(PLUGIN_RBL)      PLUGIN_MASS_MAILER=$(PLUGIN_MASS_MAILER)"
	@echo "  PLUGIN_SPF=$(PLUGIN_SPF)  PLUGIN_DKIM=$(PLUGIN_DKIM)  PLUGIN_DMARC=$(PLUGIN_DMARC)  PLUGIN_ARC=$(PLUGIN_ARC)"
	@echo "    e.g. make install-dev PLUGIN_RBL=off CERT_DAYS=90"
	@echo ""
	@echo "💡 make gotchas   - The things that surprise people (config reload, discarded"
	@echo "                    delivery, cert expiry, what [logging] ignores). Worth reading"
	@echo "                    once; HANDOFF.md has the same traps in depth."

install-dev:
	@echo "🚀 Elemta Development Setup (Minimal)"
	@echo "======================================"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=minimal
	@$(MAKE) --no-print-directory print-dev-summary

# A stack for measuring throughput: scanners on, delivery discarded.
#
# Separate from install-dev-full rather than a flag on it, because "mail is
# thrown away" is not a detail to bury in an option. Anyone running this has
# said so.
install-dev-bench:
	@echo "🚀 Elemta Development Setup (Benchmarking)"
	@echo "=========================================="
	@# The bench overlay has no Roundcube, and applying it prunes one left over
	@# from install-dev-full: there is nothing to read when mail is discarded.
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=bench
	@$(MAKE) --no-print-directory sink-up
	@$(MAKE) --no-print-directory print-dev-summary
	@echo "   Measure with: make bench-queue"
	@# The repo config stays as shipped: the sink lives in the seeded copy the
	@# server reads, and a benchmarking run should not rewrite the default
	@# everyone else gets.
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-dovecot DELIVERY_PORT=2424 >/dev/null

# The minimal stack with a Postgres queue. Postgres comes up with the rest
# (its Service name is what [queue.postgres] dsn already says). If Elemta wins
# the race it exits on the unreachable backend and Kubernetes restarts it until
# Postgres answers, so the compose version's sqlite-first two-step is gone.
install-dev-postgres:
	@echo "🐘 Elemta Development Setup (Postgres Queue)"
	@echo "============================================"
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=postgres QUEUE_BACKEND=postgres QUEUE_POSTGRES_DSN="$(QUEUE_POSTGRES_DSN)"
	@$(MAKE) --no-print-directory print-dev-summary
	@echo "   DSN: $(QUEUE_POSTGRES_DSN)"
	@echo "   Verify: kubectl -n $(K8S_NAMESPACE) exec deploy/elemta-postgres -- psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c 'select count(*) from queue_messages;'"

install-dev-full:
	@echo "🚀 Elemta Development Setup (Full)"
	@echo "=================================="
	@$(MAKE) --no-print-directory k8s-install K8S_OVERLAY=full
	@$(MAKE) --no-print-directory print-dev-summary
	@echo "   ✉️  Roundcube: http://localhost:8026"

# The mail-auth lab (fixed DNS zone, DKIM keys, a remote-SMTP sink at :8027)
# is still a Compose overlay of a stack that no longer runs on Compose. It moves
# to Kubernetes next; until then this says so rather than starting half a lab.
install-dev-mailauth:
	@echo "❌ The mail-auth lab has not moved to Kubernetes yet."
	@echo "   deployments/compose/docker-compose-mailauth.yml is what it was; it is next to port."
	@exit 1

# ELK ships the log volume Filebeat used to read from the compose stack. On
# Kubernetes that volume is inside the elemta pod, so shipping needs a Filebeat
# sidecar or a DaemonSet reading container logs instead; that is the next port.
# elk-status, elk-data-view and elk-dashboard only talk to localhost:9200 and
# :5601 and work against any Elasticsearch and Kibana there.
elk-up:
	@echo "❌ ELK has not moved to Kubernetes yet."
	@echo "   deployments/compose/docker-compose-elk.yml is what it was; it is next to port."
	@exit 1

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
# above real spam — see the trap in HANDOFF.md. HAM_DIR and SPAM_DIR must point
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

# Point delivery at a discarding LMTP sink instead of Dovecot.
#
# Benchmarking against Dovecot measures Dovecot — maildir writes, indexing and
# sieve, saturating near 70/s. The sink accepts and discards at ~4,500/s, so it
# cannot be the thing being measured. Dovecot and Roundcube keep running; only
# where the queue delivers changes.
sink-up:
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-sink DELIVERY_PORT=2424
	@# The setting reaches the server only through the seeded copy of the
	@# config, so it has to go into the ConfigMap and then be re-seeded. Same
	@# trap as install-dev.
	@ov=$(CURRENT_OVERLAY); $(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$${ov:-minimal} >/dev/null
	@$(MAKE) --no-print-directory reseed >/dev/null
	@echo "✅ Delivery goes to the sink (elemta-sink:2424). Mail is discarded."
	@echo "   Benchmark:  make bench-queue"
	@echo "   Sink rate:  kubectl -n $(K8S_NAMESPACE) logs -f deploy/elemta-sink"

# Real mailboxes: deliver to Dovecot again.
sink-down:
	@$(MAKE) --no-print-directory configure-delivery-target DELIVERY_HOST=elemta-dovecot DELIVERY_PORT=2424
	@ov=$(CURRENT_OVERLAY); $(MAKE) --no-print-directory k8s-apply K8S_OVERLAY=$${ov:-minimal} >/dev/null
	@$(MAKE) --no-print-directory reseed >/dev/null
	@echo "✅ Delivery goes to Dovecot; mail lands in real mailboxes."
	@echo "   ✉️  Roundcube is part of install-dev-full: http://localhost:8026  (user@example.com / password)"

# Rewrites [delivery] host/port. Same approach as configure-plugins: the repo
# config is the source that gets seeded, so it is what has to change.
DELIVERY_HOST ?= elemta-dovecot
DELIVERY_PORT ?= 2424
configure-delivery-target:
	@python3 scripts/dev/set_delivery_target.py "$(DELIVERY_HOST)" "$(DELIVERY_PORT)"

# Delivery throughput, which is a different number from acceptance throughput.
# Fills the queue, stops sending, and times the drain.
bench-queue:
	@python3 scripts/dev/bench_queue.py --messages $(or $(MESSAGES),6000) --concurrency $(or $(CONCURRENCY),40)

# Traffic worth looking at. The dashboard is mostly empty without it, because
# a mail server with no mail has nothing to show.
stress-corpus:
	@python3 scripts/dev/stress_corpus.py --messages $(or $(MESSAGES),300) --concurrency $(or $(CONCURRENCY),10)

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
	@echo "ELK does not run on the Kubernetes dev stack yet; nothing to stop."

mailauth-check:
	@printf 'EHLO lab\r\nMAIL FROM:<sender@pass.auth.test>\r\nRCPT TO:<user@receiver.auth.test>\r\nDATA\r\nFrom: sender@pass.auth.test\r\nTo: user@receiver.auth.test\r\nSubject: Elemta mail-auth lab\r\nDate: Tue, 11 Aug 2026 12:00:00 -0400\r\nMessage-ID: <mailauth-lab@pass.auth.test>\r\n\r\nSPF, DKIM and DMARC lab message.\r\n.\r\nQUIT\r\n' | nc localhost 2525
	@echo "Message queued. The remote SMTP worker signs it; inspect http://localhost:8027"

mailauth-check-fail:
	@printf 'EHLO lab-fail\r\nMAIL FROM:<sender@fail.auth.test>\r\nRCPT TO:<user@receiver.auth.test>\r\nDATA\r\nFrom: sender@fail.auth.test\r\nTo: user@receiver.auth.test\r\nSubject: Elemta mail-auth negative lab\r\nDate: Tue, 11 Aug 2026 12:01:00 -0400\r\nMessage-ID: <mailauth-fail@fail.auth.test>\r\n\r\nExpected SPF and DMARC failure in reporting mode.\r\n.\r\nQUIT\r\n' | nc localhost 2525
	@echo "Failure example queued. SPF/DMARC fail but reporting mode accepts it."


docker-setup: install-dev-full

# Day-to-day control of the dev stack. install-dev* create it; these act on
# whatever is running in $(K8S_NAMESPACE).

# 'down' keeps everything but the running pods, as 'docker compose down' kept
# the volumes; 'up' brings them back.
up: k8s-check
	@echo "🚀 Starting Elemta services..."
	@$(KC) scale deployment --all --replicas=1 >/dev/null
	@$(MAKE) --no-print-directory k8s-wait

down:
	@echo "🛑 Stopping Elemta services..."
	@$(KC) scale deployment --all --replicas=0 >/dev/null
	@echo "✅ Services stopped (volumes kept; make up to start again)"

down-volumes:
	@echo "🛑 Deleting the $(K8S_NAMESPACE) namespace and everything in it..."
	@$(KUBECTL) delete namespace $(K8S_NAMESPACE) --ignore-not-found --wait=true
	@echo "✅ Services and volumes removed"

restart:
	@echo "🔄 Restarting Elemta services..."
	@$(KC) rollout restart deployment >/dev/null
	@$(MAKE) --no-print-directory k8s-wait

logs:
	@echo "📋 Showing Elemta logs (Ctrl+C to exit)..."
	$(KC) logs -f --tail=50 --prefix --all-containers --max-log-requests=30 -l app.kubernetes.io/part-of=elemta

logs-elemta:
	@echo "📋 Showing Elemta SMTP server logs..."
	$(KC) logs -f --tail=100 deploy/elemta -c smtp

status:
	@echo "📊 Elemta Services Status:"
	@$(KC) get pods,services -o wide

# Rebuild the images and roll the pods that run them. Configuration is left
# alone: that is install-dev's job (or reseed's).
rebuild:
	@echo "🔨 Rebuilding and restarting Elemta..."
	@$(MAKE) --no-print-directory k8s-images DOCKER_BUILD_FLAGS=--no-cache
	@$(KC) rollout restart deploy/elemta deploy/elemta-sink deploy/elemta-dovecot deploy/elemta-dns >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
	@echo "✅ Rebuild complete"

rebuild-dev:
	@echo "🔨 Quick rebuild for development..."
	@$(MAKE) --no-print-directory k8s-images
	@$(KC) rollout restart deploy/elemta deploy/elemta-sink deploy/elemta-dovecot deploy/elemta-dns >/dev/null
	@$(MAKE) --no-print-directory k8s-wait
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
	@echo "   4. Run: docker compose -f deployments/compose/docker-compose.prod.yml up -d"
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
# Kept because install/README.md and deployments/compose/README.md name them.
update: rebuild
update-restart: restart
