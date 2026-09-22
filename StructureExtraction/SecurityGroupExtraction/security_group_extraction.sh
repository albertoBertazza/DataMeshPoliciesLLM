#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REALM_FILE="$PROJECT_ROOT/docker-compose/keycloak/import/trino-realm.json"
OUTPUT_FILE="$PROJECT_ROOT/docker-compose/etc/user-group/groups.txt"
SECURITY_GROUPS_JSON="$PROJECT_ROOT/Structure/security_groups.json"

mkdir -p "$(dirname "$OUTPUT_FILE")"
mkdir -p "$(dirname "$SECURITY_GROUPS_JSON")"

# Generate groups.txt
jq -r '
  .users
  | map({
      username,
      groups: (.groups // [] | map(sub("^/"; "")))
    })
  | map(.groups[] as $g | [$g, .username])
  | group_by(.[0])
  | map("\(.[0][0]):\(map(.[1]) | join(","))")
  | .[]
' "$REALM_FILE" > "$OUTPUT_FILE"

# Generate security_groups.json
jq '
[
  .users[]
  | (.groups // [])
  | map(sub("^/"; ""))
  | .[]
]
| unique
' "$REALM_FILE" > "$SECURITY_GROUPS_JSON"

echo "Generated $OUTPUT_FILE"
cat "$OUTPUT_FILE"

echo
echo "Generated $SECURITY_GROUPS_JSON"
cat "$SECURITY_GROUPS_JSON"