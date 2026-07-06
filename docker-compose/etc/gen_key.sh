#!/usr/bin/env bash
# Generates keystore.jks for the Trino coordinator (matches the path/password
# already referenced in config.properties: /etc/trino/keystore.jks / dataMeshProject).
# OAuth2 auth requires the coordinator to be served over HTTPS.
# Requires a JDK (keytool) on the machine running this script.
set -e

OUT_DIR="$(dirname "$0")/../etc"
PASSWORD="dataMeshProject"

mkdir -p "$OUT_DIR"

keytool -genkeypair \
  -alias trino \
  -keyalg RSA -keysize 2048 -validity 365 \
  -keystore "$OUT_DIR/keystore.jks" \
  -storepass "$PASSWORD" \
  -keypass "$PASSWORD" \
  -dname "CN=trino-coordinator" \
  -ext "SAN=DNS:trino-coordinator,DNS:localhost,IP:127.0.0.1"

echo "Keystore written to $OUT_DIR/keystore.jks (password: $PASSWORD)"