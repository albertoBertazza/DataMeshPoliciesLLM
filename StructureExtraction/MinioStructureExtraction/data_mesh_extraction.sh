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

# ----------------------------
# TIMER / PROGRESS FUNCTIONS
# ----------------------------
START_TIME=$(date +%s)

format_seconds() {
    local total="$1"

    local hours=$((total / 3600))
    local minutes=$(((total % 3600) / 60))
    local seconds=$((total % 60))

    if (( hours > 0 )); then
        printf "%02dh %02dm %02ds" "$hours" "$minutes" "$seconds"
    elif (( minutes > 0 )); then
        printf "%02dm %02ds" "$minutes" "$seconds"
    else
        printf "%02ds" "$seconds"
    fi
}

print_progress() {
    local current="$1"
    local total="$2"

    local now
    now=$(date +%s)

    local elapsed=$((now - START_TIME))

    if (( current > 0 && total > 0 )); then
        local estimated_total=$((elapsed * total / current))
        local eta=$((estimated_total - elapsed))

        if (( eta < 0 )); then
            eta=0
        fi

        local percent=$((current * 100 / total))

        echo "   📊 Progress: ${current}/${total} (${percent}%) | Elapsed: $(format_seconds "$elapsed") | ETA: $(format_seconds "$eta")"
    else
        echo "   📊 Elapsed: $(format_seconds "$elapsed")"
    fi
}

# ----------------------------
# REQUEST OAUTH TOKEN
# ----------------------------
echo
echo "============================================================"
echo "DATA MESH EXTRACTION"
echo "============================================================"
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
  --data-urlencode "scope=openid email profile"
)

TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "❌ Failed to obtain OAuth token"
  echo "$TOKEN_RESPONSE"
  exit 1
fi

echo "✅ Token OK"

# ----------------------------
# RUN SQL
# ----------------------------
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

# ----------------------------
# FIND ICEBERG CATALOG
# ----------------------------
echo
echo "🔎 Looking for Iceberg catalog..."

mapfile -t CATALOGS < <(
    run_sql "SHOW CATALOGS" | grep '^iceberg$' || true
)

if [[ ${#CATALOGS[@]} -eq 0 ]]; then
    echo "❌ Iceberg catalog not found"
    exit 1
fi

echo "✅ Iceberg catalog found"

# ----------------------------
# INITIALIZE JSON
# ----------------------------
echo '{"catalogs":[' > "$OUTPUT_FILE"

FIRST_CATALOG=true

# Counters
TOTAL_SCHEMAS=0
TOTAL_OBJECTS=0
TOTAL_COLUMNS=0

PROCESSED_SCHEMAS=0
PROCESSED_OBJECTS=0

# ----------------------------
# CATALOGS
# ----------------------------
for catalog in "${CATALOGS[@]}"; do

    [[ -z "$catalog" ]] && continue
    [[ "$catalog" == "system" ]] && continue

    echo
    echo "============================================================"
    echo "📦 CATALOG: $catalog"
    echo "============================================================"

    $FIRST_CATALOG || echo "," >> "$OUTPUT_FILE"
    FIRST_CATALOG=false

    echo "{\"name\":\"$catalog\",\"schemas\":[" >> "$OUTPUT_FILE"

    # ----------------------------
    # SCHEMAS
    # ----------------------------
    mapfile -t SCHEMAS < <(
        run_sql "SHOW SCHEMAS FROM $catalog"
    )

    FILTERED_SCHEMAS=()

    for schema in "${SCHEMAS[@]}"; do
        [[ -z "$schema" ]] && continue
        [[ "$schema" == "information_schema" ]] && continue
        [[ "$schema" == "system" ]] && continue
        [[ "$schema" == raw_* ]] && continue

        FILTERED_SCHEMAS+=("$schema")
    done

    TOTAL_SCHEMAS=$((TOTAL_SCHEMAS + ${#FILTERED_SCHEMAS[@]}))

    echo "📁 Schemas to process: ${#FILTERED_SCHEMAS[@]}"

    FIRST_SCHEMA=true

    for schema in "${FILTERED_SCHEMAS[@]}"; do

        PROCESSED_SCHEMAS=$((PROCESSED_SCHEMAS + 1))

        echo
        echo "------------------------------------------------------------"
        echo "📁 Schema [$PROCESSED_SCHEMAS/$TOTAL_SCHEMAS]: $catalog.$schema"
        echo "------------------------------------------------------------"

        $FIRST_SCHEMA || echo "," >> "$OUTPUT_FILE"
        FIRST_SCHEMA=false

        # ----------------------------
        # SCHEMA STRUCTURE
        # ----------------------------
        echo "{\"name\":\"$schema\",\"tables\":[" >> "$OUTPUT_FILE"

        # ----------------------------
        # GET OBJECTS
        # ----------------------------
        mapfile -t OBJECTS < <(
            run_sql "
                SELECT table_name || ',' || table_type
                FROM ${catalog}.information_schema.tables
                WHERE table_schema = '${schema}'
                ORDER BY table_name
            "
        )

        # All schema objects are stored in one array.
        # The second value identifies the object type:
        #
        #   table
        #   view
        #   materialized view
        #
        TABLES=()

        for object in "${OBJECTS[@]}"; do

            [[ -z "$object" ]] && continue

            IFS=',' read -r object_name object_type <<< "$object"

            [[ -z "$object_name" ]] && continue

            case "$object_type" in

                "VIEW")
                    TABLES+=("$object_name|view")
                    ;;

                "BASE TABLE")
                    # Iceberg reports materialized views as BASE TABLE.
                    # Explicitly test whether the relation is a
                    # materialized view.

                    if run_sql \
                        "SHOW CREATE MATERIALIZED VIEW ${catalog}.${schema}.${object_name}" \
                        >/dev/null 2>&1; then

                        TABLES+=("$object_name|materialized view")

                    else
                        TABLES+=("$object_name|table")
                    fi
                    ;;

                *)
                    echo "⚠️ Unknown object type '$object_type': $object_name"
                    ;;

            esac

        done

        OBJECT_COUNT=${#TABLES[@]}

        TOTAL_OBJECTS=$((TOTAL_OBJECTS + OBJECT_COUNT))

        echo "   📊 Objects: $OBJECT_COUNT"

        # ----------------------------
        # PROCESS ALL OBJECTS
        # ----------------------------
        FIRST_OBJECT=true

        for object_info in "${TABLES[@]}"; do

            [[ -z "$object_info" ]] && continue

            IFS='|' read -r object_name object_kind <<< "$object_info"

            PROCESSED_OBJECTS=$((PROCESSED_OBJECTS + 1))

            $FIRST_OBJECT || echo "," >> "$OUTPUT_FILE"
            FIRST_OBJECT=false

            # ----------------------------
            # OBJECT
            # ----------------------------
            echo "{\"name\":\"$object_name\",\"type\":\"$object_kind\",\"columns\":[" >> "$OUTPUT_FILE"

            FIRST_COLUMN=true

            # ----------------------------
            # COLUMNS
            # ----------------------------
            while IFS=',' read -r column type extra comment; do

                [[ -z "$column" ]] && continue

                TOTAL_COLUMNS=$((TOTAL_COLUMNS + 1))

                $FIRST_COLUMN || echo "," >> "$OUTPUT_FILE"
                FIRST_COLUMN=false

                printf '{"name":"%s","type":"%s"}' \
                    "$column" \
                    "$type" >> "$OUTPUT_FILE"

            done < <(
                run_sql \
                    "SHOW COLUMNS FROM $catalog.$schema.$object_name" \
                    2>/dev/null || true
            )

            echo "]}" >> "$OUTPUT_FILE"

            # ----------------------------
            # LOG OBJECT
            # ----------------------------
            case "$object_kind" in
                "table")
                    echo "   🗃️  Table: $object_name"
                    ;;
                "view")
                    echo "   👁️  View: $object_name"
                    ;;
                "materialized view")
                    echo "   📊 Materialized view: $object_name"
                    ;;
            esac

            print_progress "$PROCESSED_OBJECTS" "$TOTAL_OBJECTS"

        done

        echo "]}" >> "$OUTPUT_FILE"

        echo
        print_progress "$PROCESSED_SCHEMAS" "$TOTAL_SCHEMAS"

    done

    echo "]}" >> "$OUTPUT_FILE"

done

echo "]}" >> "$OUTPUT_FILE"

# ----------------------------
# VALIDATE JSON
# ----------------------------
echo
echo "🔍 Validating generated JSON..."

TMP_JSON=$(mktemp)

jq '.' "$OUTPUT_FILE" > "$TMP_JSON"
mv "$TMP_JSON" "$OUTPUT_FILE"

echo "✅ JSON valid"

# ----------------------------
# REMOVE RAW CSV SCHEMAS
# ----------------------------
echo "🧹 Removing raw_* schemas..."

jq '
  .catalogs[].schemas |=
    map(select(.name | startswith("raw_") | not))
' "$OUTPUT_FILE" > /tmp/data_mesh.json

mv /tmp/data_mesh.json "$OUTPUT_FILE"

# ----------------------------
# FINAL STATISTICS
# ----------------------------
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo
echo "============================================================"
echo "✅ DATA MESH EXTRACTION COMPLETE"
echo "============================================================"
echo "📄 Output:              $OUTPUT_FILE"
echo "📁 Schemas:             $TOTAL_SCHEMAS"
echo "🗃️  Objects:             $TOTAL_OBJECTS"
echo "🧱 Columns:             $TOTAL_COLUMNS"
echo "⏱️  Total time:          $(format_seconds "$ELAPSED")"
echo "============================================================"