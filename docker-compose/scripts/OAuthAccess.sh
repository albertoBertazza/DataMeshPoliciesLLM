#!/bin/bash
set -euo pipefail

KEYCLOAK_URL="http://keycloak:8080"
REALM="trino"

CLIENT_ID="trino"
CLIENT_SECRET="trino-client-secret"

USERNAME="trino"
PASSWORD="trino123"

SERVER="https://trino-coordinator:8443"

echo "Waiting for Trino..."

until curl -skf "${SERVER}/v1/info" >/dev/null; do
    echo "Trino not ready yet..."
    sleep 3
done

echo "Requesting OAuth token..."

TOKEN_RESPONSE=$(curl -s \
  -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" \
  --data-urlencode "scope=openid profile email")

TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
    echo "FAILED to obtain OAuth token"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Token received"

echo "🚀 Running Trino CLI inside container..."

docker run --rm -i \
  --network docker-compose_trino-network \
  trinodb/trino:480 \
  trino \
  --server "$SERVER" \
  --access-token "$TOKEN" \
  --insecure