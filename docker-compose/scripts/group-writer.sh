#!/bin/bash
set -euo pipefail
cd ..

REALM_FILE="keycloak/import/trino-realm.json"
OUTPUT_FILE="etc/user-group/groups.txt"

mkdir -p "$(dirname "$OUTPUT_FILE")"

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

echo "Generated $OUTPUT_FILE"
cat "$OUTPUT_FILE"