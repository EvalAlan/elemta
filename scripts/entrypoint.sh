#!/bin/sh

# Secure entrypoint script for Elemta (runs as non-root user)

echo "Starting Elemta SMTP server..."

# Initialize volume directories as non-root user
echo "Initializing volume directories as non-root user..."
mkdir -p /app/queue/active /app/queue/deferred /app/queue/hold /app/queue/failed /app/logs 2>/dev/null || true
chmod 700 /app/queue 2>/dev/null || true
chmod 755 /app/logs 2>/dev/null || true

# Resolve the runtime configuration, seeding it onto the shared volume the first
# time. See scripts/prepare-config.sh for why it does not live under /tmp.
ELEMTA_CONFIG="$(/app/prepare-config.sh)" || ELEMTA_CONFIG=""
if [ -n "$ELEMTA_CONFIG" ]; then
    echo "Using configuration from $ELEMTA_CONFIG"
fi

# Create test messages in the queue if TEST_MODE is enabled
if [ "$TEST_MODE" = "true" ]; then
    echo "TEST MODE ENABLED: Creating test messages in the queue..."
    
    # Ensure queue directories exist
    mkdir -p /app/queue/active
    mkdir -p /app/queue/deferred
    mkdir -p /app/queue/hold
    mkdir -p /app/queue/failed
    
    # Generate a few sample messages with random data
    for i in {1..5}; do
        msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        timestamp=$(date +%s)
        
        # Create message file in active queue
        cat > "/app/queue/active/msg-${msg_id}.eml" << EOF
From: sender${i}@example.com
To: recipient${i}@example.org
Subject: Test Message ${i}
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>

This is test message ${i} created automatically by Elemta in test mode.
This message was created at $(date).
EOF
        echo "Created test message ${i} with ID ${msg_id} in active queue"
    done
    
    # Create a few deferred messages
    for i in {1..3}; do
        msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        timestamp=$(date +%s)
        future_timestamp=$((timestamp + 1800)) # 30 minutes in seconds
        
        # Create message file in deferred queue
        cat > "/app/queue/deferred/msg-${msg_id}.eml" << EOF
From: deferred${i}@example.com
To: unreachable${i}@example.net
Subject: Deferred Test Message ${i}
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Defer-Count: 2
X-Elemta-Next-Attempt: $(date -R -d "@$future_timestamp")

This is a deferred test message ${i} created automatically by Elemta in test mode.
This message was created at $(date) and will be retried later.
EOF
        echo "Created deferred test message ${i} with ID ${msg_id}"
    done
    
    # Create a held message
    msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
    cat > "/app/queue/hold/msg-${msg_id}.eml" << EOF
From: suspicious@example.com
To: admin@example.org
Subject: [HELD] Suspicious Message
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Hold-Reason: Suspicious content detected

This message was automatically held by Elemta's content filter.
It contains suspicious content that requires administrator review.
EOF
    echo "Created held message with ID ${msg_id}"
    
    # Create a failed message
    msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
    cat > "/app/queue/failed/msg-${msg_id}.eml" << EOF
From: failure@example.com
To: nonexistent@invalid.example
Subject: [FAILED] Delivery Failure
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Failure-Reason: Permanent failure - recipient does not exist

This is a failed message that could not be delivered after multiple attempts.
The recipient domain does not exist or the recipient was rejected.
EOF
    echo "Created failed message with ID ${msg_id}"
    
    echo "Finished creating test messages"
fi

# Check if we have the actual Go binary
ls -la /app/elemta
if [ -x "/app/elemta" ]; then
    echo "Found elemta binary, using that instead of mock server"
    
    # Start the API server in background if enabled
    if [ -f "/app/api_server.py" ] && [ "$API_ENABLED" != "false" ]; then
        echo "Starting API server in background..."
        python3 /app/api_server.py &
        API_PID=$!
        echo "API server started with PID: $API_PID"
        
        # Wait a moment for API server to start
        sleep 2
        
        # Setup trap to kill API server on exit
        trap 'kill $API_PID; exit' TERM INT
    fi
    
    # Check if we need to run elemta-cli
    if [ "$1" = "cli" ]; then
        shift
        echo "Running elemta-cli with args: $@"
        exec /app/elemta-cli "$@"
    # Check if we need to start as a server or handle other commands
    elif [ "$1" = "server" ]; then
        echo "Starting elemta server..."
        if [ -n "$ELEMTA_CONFIG" ]; then
            exec /app/elemta --config "$ELEMTA_CONFIG" server
        fi
        exec /app/elemta server
    else
        # If any arguments were provided, run the elemta binary with them
        if [ $# -gt 0 ]; then
            echo "Running elemta with args: $@"
            exec /app/elemta "$@"
        else
            # Default to starting the server if no arguments
            echo "Starting elemta server with no args..."
            if [ -n "$ELEMTA_CONFIG" ]; then
                exec /app/elemta --config "$ELEMTA_CONFIG" server
            fi
            exec /app/elemta server
        fi
    fi
    
    exit 0
fi

# If we reach here the binary is missing or not executable. This used to start a
# Python mock SMTP server on port 25 that accepted mail and discarded it, which
# in a broken production image is the worst possible failure: the health check
# passes, senders get 250, and every message is lost. Fail loudly instead.
echo "FATAL: /app/elemta is missing or not executable; refusing to start." >&2
echo "The image is broken. Rebuild it rather than running a substitute." >&2
exit 1
