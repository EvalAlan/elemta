#!/bin/bash
# One-command rebuild script for Elemta

set -e  # Exit on any error

echo "🚀 Starting Elemta rebuild..."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Not in Elemta directory. Please run this from the Elemta project root."
    exit 1
fi

# Stop all containers
echo "🛑 Stopping all containers..."
docker-compose -f docker-compose.yml down 2>/dev/null || true

# Clean up old config
echo "🧹 Cleaning up old config..."
rm -f config/elemta-generated.toml

# Create .env.linode if it doesn't exist
if [ ! -f ".env.linode" ]; then
    echo "📝 Creating .env.linode from template..."
    if [ -f "env-linode-template.txt" ]; then
        cp env-linode-template.txt .env.linode
    else
        echo "❌ Template file not found. Creating basic .env.linode..."
        cat > .env.linode << 'EOF'
# Server Configuration
ELEMTA_HOSTNAME=mail.dev.example.net
ELEMTA_DOMAIN=dev.example.net
ELEMTA_EMAIL=admin@example.com

# Environment Settings
TZ=UTC
DEBUG=false
TEST_MODE=false
NODE_ID=0

# Port Configuration
SMTP_PORT=25
SMTPS_PORT=465
SMTP_STARTTLS_PORT=587
IMAP_PORT=143
WEB_UI_PORT=8025
WEBMAIL_PORT=8026
HTTP_PORT=8080
METRICS_PORT=8080
API_PORT=8081

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=elemta
DB_USER=elemta
DB_PASSWORD=elemta123
DB_TYPE=sqlite

# LDAP Configuration
LDAP_HOST=ldap
LDAP_PORT=389
LDAP_BASE_DN=dc=dev,dc=example,dc=net
LDAP_ADMIN_DN=cn=admin,dc=dev,dc=example,dc=net
LDAP_ADMIN_PASSWORD=admin123
LDAP_ORGANISATION=Example Development
LDAP_DOMAIN=dev.example.net

# Test User Configuration
TEST_USER=user
TEST_PASSWORD=change-me

# Let's Encrypt Configuration
LETSENCRYPT_ENABLED=true
LETSENCRYPT_STAGING=false
LETSENCRYPT_EMAIL=admin@example.com

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=text
LOG_FILE=/app/logs/elemta.log

# Monitoring Configuration
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
ELASTICSEARCH_PORT=9200
KIBANA_PORT=5601

# Delivery Configuration
DELIVERY_HOST=elemta-dovecot
DELIVERY_PORT=2424
DELIVERY_MODE=lmtp
DELIVERY_TIMEOUT=30

# Docker Configuration
DOCKER_IMAGE=elemta_node
DOCKER_TAG=latest

# Rspamd Configuration
RSPAMD_PORT=11334

# Queue Configuration
QUEUE_INTERVAL=10
QUEUE_WORKERS=5

# Metrics and HTTP Configuration
METRICS_ENABLED=true
HTTP_ENABLED=true
ACME_CHALLENGE=true

# Check Interval (24 hours in nanoseconds)
CHECK_INTERVAL_NANOS=86400000000000
EOF
    fi
fi

# Generate config using the alternative method
echo "🔧 Generating configuration..."
./generate-config-alt.sh .env.linode

# Create users.txt file for authentication
echo "👥 Creating users.txt for authentication..."
mkdir -p config
cat > config/users.txt << 'EOF'
user@dev.example.net:change-me
admin@dev.example.net:change-me
EOF

# Verify config was generated
if [ ! -f "config/elemta-generated.toml" ]; then
    echo "❌ Failed to generate configuration!"
    exit 1
fi

echo "📄 Generated config preview:"
echo "================================"
grep -A 3 -B 3 "hostname\|check_interval" config/elemta-generated.toml
echo "================================"

# Build and start containers
echo "🐳 Building and starting containers..."
docker-compose -f docker-compose.yml --env-file .env.linode up -d --build

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 15

# Check status
echo "📊 Service status:"
docker-compose -f docker-compose.yml ps

# Show recent logs
echo "📋 Recent elemta logs:"
docker-compose -f docker-compose.yml logs --tail=10 elemta

echo "✅ Rebuild complete!"
echo "🔍 To check logs: docker-compose -f docker-compose.yml logs -f elemta" 