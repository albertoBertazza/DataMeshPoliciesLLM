#!/bin/bash
set -e

unset TRINO_SERVER

echo "Waiting for Trino..."

until curl -skf https://trino-coordinator:8443/v1/info --insecure; do
  sleep 3
done

echo "Running schema init..."

SERVER="https://trino-coordinator:8443"

trino --server "$SERVER" --user alice --password --insecure --file /init/01-schemas.sql <<EOF
alice123
EOF

trino --server "$SERVER" --user alice --password --insecure --file /init/02-hr.sql <<EOF
alice123
EOF

trino --server "$SERVER" --user alice --password --insecure --file /init/03-mobility.sql <<EOF
alice123
EOF

echo "INIT COMPLETE"
