#!/bin/bash
set -e

TOKEN_FILE="/tokens/enrollment_tokens.txt"
TIMEOUT=300  # 5 minutes timeout

echo "🚀 Starting Fleet Server setup..."

# Wait for token file to be available
echo "Waiting for enrollment tokens to be generated..."
counter=0
while [ ! -f "$TOKEN_FILE" ] || [ ! -s "$TOKEN_FILE" ]; do
    sleep 5
    counter=$((counter + 5))
    
    if [ $counter -ge $TIMEOUT ]; then
        echo "❌ Timeout: Token file not found within ${TIMEOUT} seconds"
        exit 1
    fi
    
    if [ $((counter % 30)) -eq 0 ]; then
        echo "Still waiting for tokens... (${counter}s elapsed)"
    fi
done

echo "✅ Token file found!"

# Extract the fleet service token
if ! grep -q "fleet-service-token:" "$TOKEN_FILE"; then
    echo "❌ Fleet service token not found in token file"
    echo "Available tokens:"
    cat "$TOKEN_FILE"
    exit 1
fi

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