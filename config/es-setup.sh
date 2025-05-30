#!/bin/sh
set -e

# variable
ELASTIC_URL="http://elasticsearch:9200"

# Install necessary packages
apk add --no-cache curl &>/dev/null

echo "Waiting for Elasticsearch to be ready..."
timeout=300
counter=0

while [ $counter -lt $timeout ]; do
  # Check if ES is responding and authentication works
  if curl -s -u "elastic:${ELASTIC_PASSWORD}" "$ELASTIC_URL/_cluster/health" | grep -E "(green|yellow)" >/dev/null 2>&1; then
    echo "✅ Elasticsearch is ready!"
    break
  fi
  
  sleep 2
  counter=$((counter + 2))
  
  if [ $((counter % 30)) -eq 0 ]; then
    echo "Still waiting for Elasticsearch... (${counter}s elapsed)"
  fi
done

if [ $counter -ge $timeout ]; then
  echo "❌ Timeout: Elasticsearch did not become ready within ${timeout} seconds"
  exit 1
fi

# Change Kibana system user password
echo "Updating Kibana system user password..."
password_response=$(curl -sw "HTTPSTATUS:%{http_code}" -u "elastic:${ELASTIC_PASSWORD}" -X POST "$ELASTIC_URL/_security/user/kibana_system/_password" \
  -d "{\"password\": \"${KIBANA_PASSWORD}\"}" -H 'Content-Type: application/json')

# Extract HTTP status code
password_http_code=$(echo $password_response | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
password_body=$(echo $password_response | sed -e 's/HTTPSTATUS:.*//g')

echo "Password update HTTP Status: $password_http_code"
if [ ! -z "$password_body" ]; then
    echo "Password update response: $password_body"
fi

# Verify the password works by testing authentication
echo "Verifying new Kibana password..."
verify_response=$(curl -sw "HTTPSTATUS:%{http_code}" -u "kibana_system:${KIBANA_PASSWORD}" "$ELASTIC_URL/_security/_authenticate")

verify_http_code=$(echo $verify_response | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
verify_body=$(echo $verify_response | sed -e 's/HTTPSTATUS:.*//g')

echo "Verification HTTP Status: $verify_http_code"

if [ "$verify_http_code" = "200" ]; then
    echo "✅ Success! Kibana system user password has been updated and verified."
    echo "Kibana user authenticated as: $(echo $verify_body | grep -o '"username":"[^"]*"')"
else
    echo "❌ Failed! Password verification failed."
    echo "Verification response: $verify_body"
    exit 1
fi

printf '\n🎉 Successfully configured Elasticsearch!\n'