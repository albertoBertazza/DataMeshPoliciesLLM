#!/bin/bash
set -euo pipefail

REALM="trino"
CLIENT_ID="trino"
CLIENT_SECRET="trino-client-secret"
USERNAME="trino"
PASSWORD="trino123"

SERVER="https://trino-coordinator:8443"

echo "🔐 Requesting OAuth token inside Docker network..."

TOKEN_RESPONSE=$(docker run --rm \
  --network docker-compose_trino-network \
  curlimages/curl:8.5.0 \
  -s \
  -X POST "http://keycloak:8080/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" \
  --data-urlencode "scope=openid email profile")

TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
    echo "❌ Failed to obtain OAuth token"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Token OK"

echo "🚀 Starting Trino CLI in Docker..."

docker run --rm -it \
  --network docker-compose_trino-network \
  trinodb/trino:480 \
  trino \
  --server "$SERVER" \
  --access-token "$TOKEN" \
  --insecure \
  --debug