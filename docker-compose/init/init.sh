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
  --data-urlencode "scope=openid email profile")

TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
    echo "FAILED to obtain OAuth token"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo "Running schema init..."

run_trino() {
    trino \
        --server "$SERVER" \
        --access-token "$TOKEN" \
        --insecure \
        --debug \
        --file "$1"
}

run_trino /init/01-schemas.sql
run_trino /init/02-hr.sql
run_trino /init/03-mobility.sql

echo "INIT COMPLETE"