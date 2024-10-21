#!/bin/sh

# Enable better error handling
set -eu

# Variables
ELASTIC_URL="http://elasticsearch:9200"
KIBANA_URL="http://kibana:5601"
TOKEN_FILE="/tokens/enrollment_tokens.txt"

# Install necessary packages
apk add --no-cache curl jq

# Wait until Elasticsearch is ready
echo "Waiting for Elasticsearch..."
until curl -s "$ELASTIC_URL" >/dev/null; do 
  sleep 2
done

# Change Kibana system user password
curl -su "elastic:${ELASTIC_PASSWORD}" -X POST "$ELASTIC_URL/_security/user/kibana_system/_password" \
  -d "{\"password\": \"${KIBANA_PASSWORD}\"}" -H 'Content-Type: application/json'

printf '\nSuccessfully configured Elasticsearch\n'

# Wait for Kibana to be ready
echo "Waiting for Kibana..."
until curl -s "$KIBANA_URL/api/status" | grep -q '"level":"available"'; do
  sleep 2
done

# Register Fleet Server hosts
curl -sX POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/fleet_server_hosts" \
  -d '{"name": "fleet01", "host_urls": ["https://fleet01:8220"], "is_default": true}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true'

# Create Fleet Server, Windows, and Linux policies in parallel
(
  curl -sX POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/agent_policies" \
  -d '{"name": "fleet-server-default", "namespace": "default", "monitoring_enabled": ["metrics"], "description": "Policy for Fleet Server", "has_fleet_server": true}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true'
) &
(
  curl -sX POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/agent_policies" \
  -d '{"name": "Windows Policy", "namespace": "default", "monitoring_enabled": ["logs"], "description": "Policy for Windows Machines"}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true'
) &
(
  curl -sX POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/agent_policies" \
  -d '{"name": "Linux Policy", "namespace": "default", "monitoring_enabled": ["logs"], "description": "Policy for Linux Machines"}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true'
)
wait  # Wait for all background tasks to complete

# Fetch enrollment tokens
token_response=$(curl -sX GET "$KIBANA_URL/api/fleet/enrollment_api_keys" -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' -H 'kbn-xsrf: xx')

# Clear the token file in case it exists
: > "$TOKEN_FILE"

echo "$token_response" | jq -c '.list[]' | while read token; do
  policy_id=$(echo "$token" | jq -r '.policy_id')
  secret=$(echo "$token" | jq -r '.api_key')
  policy_response=$(curl -sX GET "$KIBANA_URL/api/fleet/agent_policies/$policy_id" -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' -H 'kbn-xsrf: xx')
  policy_name=$(echo "$policy_response" | jq -r '.item.name')

  # Save policy name and enrollment token (secret) to the file
  echo "$policy_name:$secret" >> "$TOKEN_FILE"
done

# Generate service token and append it to the enrollment token file
service_token=$(curl -sX POST -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/service-tokens" -H 'Content-Type: application/json' -H 'kbn-xsrf: true' | jq -r '.value')

# Add the service token on a new line with the correct format
echo "fleet-service-token:$service_token" >> "$TOKEN_FILE"

# Update the outputs configuration
curl -sX PUT -u "elastic:${ELASTIC_PASSWORD}" "$KIBANA_URL/api/fleet/outputs/fleet-default-output" \
  -d '{"name": "default", "type": "elasticsearch", "hosts": ["http://elasticsearch:9200"], "is_default": true}' \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true'

printf '\nSuccessfully configured Kibana and generated tokens\n'