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

DEBUG=false

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
    --debug)
      DEBUG=true
      shift
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_FILE="$PROJECT_ROOT/Structure/data_mesh.json"

mkdir -p "$(dirname "$OUTPUT_FILE")"

echo "🔐 Requesting OAuth token..."

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

run_sql() {
    local SQL="$1"

    if [[ "$DEBUG" == "true" ]]; then
        echo "==============================" >&2
        echo "SQL SENT TO TRINO:" >&2
        echo "$SQL" >&2
        echo "==============================" >&2
    fi

    printf "%s\n" "$SQL" | docker run --rm -i \
        --network "$NETWORK" \
        trinodb/trino:480 \
        trino \
            --server "$SERVER" \
            --user "$USERNAME" \
            --access-token "$TOKEN" \
            --insecure \
            --output-format CSV_HEADER_UNQUOTED \
        | tail -n +2
}

mapfile -t CATALOGS < <(run_sql "SHOW CATALOGS" | grep '^iceberg$' || true)

if [[ ${#CATALOGS[@]} -eq 0 ]]; then
    echo "❌ Iceberg catalog not found"
    exit 1
fi

echo '{"catalogs":[' > "$OUTPUT_FILE"

FIRST_CATALOG=true

for catalog in "${CATALOGS[@]}"; do

    [[ -z "$catalog" ]] && continue
    [[ "$catalog" == "system" ]] && continue

    $FIRST_CATALOG || echo "," >> "$OUTPUT_FILE"
    FIRST_CATALOG=false

    echo "{\"name\":\"$catalog\",\"schemas\":[" >> "$OUTPUT_FILE"

    mapfile -t SCHEMAS < <(run_sql "SHOW SCHEMAS FROM $catalog")

    FIRST_SCHEMA=true

    for schema in "${SCHEMAS[@]}"; do

        [[ "$schema" == "information_schema" ]] && continue
        [[ "$schema" == "system" ]] && continue

        $FIRST_SCHEMA || echo "," >> "$OUTPUT_FILE"
        FIRST_SCHEMA=false

        echo "{\"name\":\"$schema\",\"tables\":[" >> "$OUTPUT_FILE"

        mapfile -t TABLES < <(run_sql "SHOW TABLES FROM $catalog.$schema" 2>/dev/null || true)

        FIRST_TABLE=true

        for table in "${TABLES[@]}"; do

            [[ -z "$table" ]] && continue

            $FIRST_TABLE || echo "," >> "$OUTPUT_FILE"
            FIRST_TABLE=false

            echo "{\"name\":\"$table\",\"columns\":[" >> "$OUTPUT_FILE"

            FIRST_COLUMN=true

            while IFS=',' read -r column type extra comment; do

                [[ -z "$column" ]] && continue

                $FIRST_COLUMN || echo "," >> "$OUTPUT_FILE"
                FIRST_COLUMN=false

                printf '{"name":"%s","type":"%s"}' \
                    "$column" \
                    "$type" >> "$OUTPUT_FILE"

            done < <(run_sql "SHOW COLUMNS FROM $catalog.$schema.$table" 2>/dev/null || true)

            echo "]}" >> "$OUTPUT_FILE"

        done

        echo "]}" >> "$OUTPUT_FILE"

    done

    echo "]}" >> "$OUTPUT_FILE"

done

echo "]}" >> "$OUTPUT_FILE"

TMP_JSON=$(mktemp)

jq '.' "$OUTPUT_FILE" > "$TMP_JSON"
mv "$TMP_JSON" "$OUTPUT_FILE"

# remove raw CSV as Hive external table
jq '
  .catalogs[].schemas |= map(select(.name | startswith("raw_") | not))
' "$OUTPUT_FILE" > /tmp/data_mesh.json && mv /tmp/data_mesh.json "$OUTPUT_FILE"

echo "✅ Data mesh written to:"
echo "$OUTPUT_FILE"