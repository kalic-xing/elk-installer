#!/bin/bash
set -e

STATE="/usr/share/elastic-agent/state"
TOKEN_FILE="/tokens/enrollment_tokens.txt"
TIMEOUT=300  # 5 minutes timeout

echo "🚀 Starting Fleet Server setup..."

# Check if agent is already enrolled by looking for configuration files
if ls $STATE/* > /dev/null 2>&1; then
    echo "✅ Elastic Agent already configured (persistent data found)"
    echo "🔧 Starting previously enrolled agent..."

    # Start the agent directly - it will use existing configuration
    exec /usr/local/bin/docker-entrypoint
fi

echo "🆕 First time setup detected, proceeding with enrollment..."

# Wait for token file to be available AND contain the fleet service token
echo "Waiting for enrollment tokens to be generated..."
counter=0
while [ ! -f "$TOKEN_FILE" ] || [ ! -s "$TOKEN_FILE" ] || ! grep -q "fleet-service-token:" "$TOKEN_FILE"; do
    sleep 5
    counter=$((counter + 5))
    
    if [ $counter -ge $TIMEOUT ]; then
        echo "❌ Timeout: Fleet service token not found within ${TIMEOUT} seconds"
        if [ -f "$TOKEN_FILE" ]; then
            echo "Token file exists but fleet-service-token not found. Available tokens:"
            cat "$TOKEN_FILE"
        else
            echo "Token file does not exist"
        fi
        exit 1
    fi
    
    if [ $((counter % 30)) -eq 0 ]; then
        if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
            echo "Still waiting for fleet-service-token in existing token file... (${counter}s elapsed)"
        else
            echo "Still waiting for token file... (${counter}s elapsed)"
        fi
    fi
done

echo "✅ Token file found with fleet service token!"

FLEET_SERVICE_TOKEN=$(grep "fleet-service-token:" "$TOKEN_FILE" | cut -d: -f2)

if [ -z "$FLEET_SERVICE_TOKEN" ]; then
    echo "❌ Failed to extract fleet service token"
    exit 1
fi

echo "✅ Fleet service token extracted successfully"
echo "📋 Token length: ${#FLEET_SERVICE_TOKEN} characters"


# Set up environment variables for elastic-agent
export FLEET_SERVER_ENABLE=true
export FLEET_SERVER_ELASTICSEARCH_HOST=http://elasticsearch:9200
export FLEET_SERVER_SERVICE_TOKEN="$FLEET_SERVICE_TOKEN"
export FLEET_SERVER_PORT=8220
export FLEET_SERVER_HOST=0.0.0.0

echo "🔧 Starting Elastic Agent with Fleet Server..."
echo "   - Elasticsearch: $FLEET_SERVER_ELASTICSEARCH_HOST"
echo "   - Fleet Server Port: $FLEET_SERVER_PORT"
echo "   - Service Token: ${FLEET_SERVICE_TOKEN:0:20}..." # Show only first 20 chars

# Start elastic-agent
exec /usr/local/bin/docker-entrypoint