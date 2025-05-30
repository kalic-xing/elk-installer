#!/bin/sh

# Enable better error handling
set -eu

# Variables
KIBANA_URL="http://kibana:5601"
TOKEN_FILE="/tokens/enrollment_tokens.txt"
TIMEOUT=600  # 10 minutes timeout for Kibana to be ready

# Function to check HTTP response and exit on failure
check_response() {
    local response="$1"
    local operation="$2"
    local http_code=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    local response_body=$(echo "$response" | sed -e 's/HTTPSTATUS:.*//g')
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "✅ $operation successful (HTTP $http_code)"
        return 0
    else
        echo "❌ $operation failed (HTTP $http_code)"
        echo "Response: $response_body"
        exit 1
    fi
}

# Install necessary packages
echo "Installing required packages..."
if ! apk add --no-cache curl jq >/dev/null 2>&1; then
    echo "❌ Failed to install required packages"
    exit 1
fi
echo "✅ Packages installed successfully"

# Wait for Kibana to be ready with timeout
echo "Waiting for Kibana to be ready..."
counter=0
while [ $counter -lt $TIMEOUT ]; do
    if curl -s "$KIBANA_URL/api/status" | grep -q '"level":"available"' >/dev/null 2>&1; then
        echo "✅ Kibana is ready!"
        break
    fi
    
    sleep 5
    counter=$((counter + 5))
    
    if [ $((counter % 60)) -eq 0 ]; then  # Show progress every minute
        echo "Still waiting for Kibana... (${counter}s elapsed)"
    fi
done

if [ $counter -ge $TIMEOUT ]; then
    echo "❌ Timeout: Kibana did not become ready within ${TIMEOUT} seconds"
    exit 1
fi

# Verify Elasticsearch authentication works
echo "Verifying Elasticsearch authentication..."
auth_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -u "elastic:${ELASTIC_PASSWORD}" "http://elasticsearch:9200/_security/_authenticate")
check_response "$auth_response" "Elasticsearch authentication"

# Register Fleet Server hosts
echo "Registering Fleet Server hosts..."
fleet_host_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/fleet_server_hosts" \
-H 'Content-Type: application/json' \
-H 'kbn-xsrf: true' \
-d '{
  "name": "fleet01",
  "host_urls": ["https://fleet01:8220"],
  "is_default": true
}')

# Check if it succeeded or if it already exists (409 conflict is OK)
fleet_http_code=$(echo "$fleet_host_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
if [ "$fleet_http_code" = "200" ] || [ "$fleet_http_code" = "409" ]; then
    echo "✅ Fleet Server host registered (or already exists)"
else
    check_response "$fleet_host_response" "Fleet Server host registration"
fi

# Fetch all existing policies once
echo "Fetching existing agent policies..."
policies_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/agent_policies" -H 'Content-Type: application/json')
check_response "$policies_response" "Fetching agent policies"

existing_policies=$(echo "$policies_response" | sed -e 's/HTTPSTATUS:.*//g' | jq -r '.items[].name' 2>/dev/null || echo "")

# Function to check if a policy exists in the fetched list
policy_exists_in_list() {
    echo "$existing_policies" | grep -q "^$1$" 2>/dev/null
}

# Function to create policy if it doesn't exist
create_policy_if_not_exists() {
    local policy_name="$1"
    local policy_data="$2"
    
    if ! policy_exists_in_list "$policy_name"; then
        echo "Creating policy: $policy_name"
        policy_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/agent_policies" \
        -d "$policy_data" \
        -H 'Content-Type: application/json' -H 'kbn-xsrf: true')
        check_response "$policy_response" "Creating policy '$policy_name'"
    else
        echo "✅ Policy '$policy_name' already exists"
    fi
}

# Create policies
create_policy_if_not_exists "fleet-server-default" '{"name": "fleet-server-default", "namespace": "default", "monitoring_enabled": ["metrics"], "description": "Policy for Fleet Server", "has_fleet_server": true}'

create_policy_if_not_exists "Windows Policy" '{"name": "Windows Policy", "namespace": "default", "monitoring_enabled": ["logs"], "description": "Policy for Windows Machines"}'

create_policy_if_not_exists "Linux Policy" '{"name": "Linux Policy", "namespace": "default", "monitoring_enabled": ["logs"], "description": "Policy for Linux Machines"}'

# Create token directory if it doesn't exist
mkdir -p "$(dirname "$TOKEN_FILE")"

# Fetch enrollment tokens
echo "Fetching enrollment tokens..."
token_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X GET "$KIBANA_URL/api/fleet/enrollment_api_keys" -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' -H 'kbn-xsrf: xx')
check_response "$token_response" "Fetching enrollment tokens"

# Clear the token file in case it exists
: > "$TOKEN_FILE"
echo "Processing enrollment tokens..."

token_data=$(echo "$token_response" | sed -e 's/HTTPSTATUS:.*//g')

# Create a temporary file to track unique policy names
temp_policies="/tmp/processed_policies.txt"
: > "$temp_policies"

echo "$token_data" | jq -c '.list[]' 2>/dev/null | while read token; do
    policy_id=$(echo "$token" | jq -r '.policy_id')
    secret=$(echo "$token" | jq -r '.api_key')
    
    # Get policy name
    policy_response=$(curl -s -X GET "$KIBANA_URL/api/fleet/agent_policies/$policy_id" -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' -H 'kbn-xsrf: xx')
    policy_name=$(echo "$policy_response" | jq -r '.item.name' 2>/dev/null || echo "unknown")
    
    # Check if we've already processed this policy
    if ! grep -q "^$policy_name$" "$temp_policies" 2>/dev/null; then
        # Save policy name and enrollment token to the file
        echo "$policy_name:$secret" >> "$TOKEN_FILE"
        echo "$policy_name" >> "$temp_policies"
        echo "  Added token for policy: $policy_name"
    else
        echo "  Skipped duplicate token for policy: $policy_name"
    fi
done

# Clean up temp file
rm -f "$temp_policies"

# Generate service token
echo "Generating service token..."
service_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/service_tokens" -H 'Content-Type: application/json' -H 'kbn-xsrf: true')
check_response "$service_response" "Generating service token"

service_token=$(echo "$service_response" | sed -e 's/HTTPSTATUS:.*//g' | jq -r '.value' 2>/dev/null)
if [ "$service_token" = "null" ] || [ -z "$service_token" ]; then
    echo "❌ Failed to extract service token"
    exit 1
fi

# Add the service token to the file
echo "fleet-service-token:$service_token" >> "$TOKEN_FILE"

# Update the outputs configuration
echo "Updating Fleet outputs configuration..."
output_response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X PUT -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/outputs/fleet-default-output" \
  -d '{"name": "default", "type": "elasticsearch", "hosts": ["http://fleet01:9200"], "is_default": true}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true')

# Check if update succeeded or if output doesn't exist (404 is expected if no fleet setup yet)
output_http_code=$(echo "$output_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
if [ "$output_http_code" = "200" ] || [ "$output_http_code" = "404" ]; then
    echo "✅ Fleet outputs configuration updated (or will be set on first Fleet setup)"
else
    check_response "$output_response" "Updating Fleet outputs"
fi

# Verify tokens file was created successfully
if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
    token_count=$(wc -l < "$TOKEN_FILE")
    echo "✅ Token file created with $token_count entries"
    echo "📁 Tokens saved to: $TOKEN_FILE"
    echo "📋 Token file contents:"
    while IFS= read -r line; do
        policy_name=$(echo "$line" | cut -d: -f1)
        echo "   - $policy_name"
    done < "$TOKEN_FILE"
else
    echo "❌ Failed to create tokens file or file is empty"
    exit 1
fi

printf '\n🎉 Successfully configured Kibana and generated tokens!\n'
printf 'Next steps:\n'
printf '  1. Use tokens from %s to enroll agents\n' "$TOKEN_FILE"
printf '  2. Configure Fleet Server with the fleet-service-token\n'
printf '  3. Deploy agents using the appropriate policy tokens\n'