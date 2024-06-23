#!/bin/sh

# Install curl
apk add --no-cache curl

# Wait until Elasticsearch is ready
until curl -s http://elasticsearch:9200; do 
  echo 'Waiting for Elasticsearch to be ready...'
  sleep 2
done

# Change the Kibana system user password
curl -su elastic:$ELASTIC_PASSWORD -X POST 'http://elasticsearch:9200/_security/user/kibana_system/_password' -H 'Content-Type: application/json' -d \
  '{
    "password": "'"$KIBANA_PASSWORD"'"
  }'

printf '\nSuccessfully configured Elasticsearch'