#!/bin/sh

# Install curl
apk add --no-cache curl

# Wait for Kibana to be fully ready
until curl -s http://kibana:5601/api/status | grep -q '"level":"available"'; do 
  echo 'Waiting for Kibana to be fully ready...'
  sleep 2
done

# Register Fleet Server hosts
curl -sX POST -u elastic:${ELASTIC_PASSWORD} 'http://kibana:5601/api/fleet/fleet_server_hosts' \
-H 'Content-Type: application/json' \
-H 'kbn-xsrf: true' \
-d '{
  "name": "fleet01",
  "host_urls": ["https://fleet01:8220"],
  "is_default": true
}'

# Create Fleet Server policy
curl -sX POST -u elastic:${ELASTIC_PASSWORD} 'http://kibana:5601/api/fleet/agent_policies' \
-H 'Content-Type: application/json' \
-H 'kbn-xsrf: true' \
-d '{
  "name": "fleet-server-default",
  "namespace": "default",
  "monitoring_enabled": ["metrics"],
  "description": "Policy for Fleet Server",
  "has_fleet_server": true
}'

# Generate service token and extract the value
curl -sX POST -u elastic:${ELASTIC_PASSWORD} 'http://kibana:5601/api/fleet/service-tokens' \
-H 'Content-Type: application/json' \
-H 'kbn-xsrf: true' | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' > /tokens/token.txt

# update the outputs
curl -sX PUT -u elastic:${ELASTIC_PASSWORD} "http://kibana:5601/api/fleet/outputs/fleet-default-output" \
-H 'Content-Type: application/json' \
-H 'kbn-xsrf: true' \
-d '
{
  "name": "default",
  "type": "elasticsearch",
  "hosts": ["http://elasticsearch:9200"],
  "is_default": true
}'

printf '\nSuccessfully configured Kibana'