#!/bin/bash
set -euo pipefail

# ----------------------------
# DEFAULTS
# ----------------------------
REALM="trino"
CLIENT_ID="trino"
CLIENT_SECRET="trino-client-secret"
SERVER="https://trino-coordinator:8443"
NETWORK="docker-compose_trino-network"

USERNAME=""
PASSWORD=""

# ----------------------------
# PARSE CLI ARGS
# ----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      USERNAME="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --server)
      SERVER="$2"
      shift 2
      ;;
    --realm)
      REALM="$2"
      shift 2
      ;;
    --client-id)
      CLIENT_ID="$2"
      shift 2
      ;;
    --client-secret)
      CLIENT_SECRET="$2"
      shift 2
      ;;
    *)
      echo "❌ Unknown argument: $1"
      exit 1
      ;;
  esac
done

# ----------------------------
# VALIDATION
# ----------------------------
if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "❌ Usage: $0 --user <username> --password <password>"
  exit 1
fi

echo "🔐 Requesting OAuth token inside Docker network..."

# ----------------------------
# GET TOKEN (inside Docker)
# ----------------------------
TOKEN_RESPONSE=$(docker run --rm \
  --network "$NETWORK" \
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

# ----------------------------
# START TRINO CLI
# ----------------------------
echo "🚀 Starting Trino CLI..."

exec docker run --rm -it \
  --network "$NETWORK" \
  trinodb/trino:480 \
  trino \
  --server "$SERVER" \
  --user "$USERNAME" \
  --access-token "$TOKEN" \
  --insecure \
  --debug