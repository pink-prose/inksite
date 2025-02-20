#!/bin/bash
#
# Script to install pg_uuidv7. See https://github.com/fboulnois/pg_uuidv7?tab=readme-ov-file#quickstart

set -euo pipefail

TEMP_DIR="$(mktemp -d)"
cd "$TEMP_DIR"

curl -LO "https://github.com/fboulnois/pg_uuidv7/releases/download/v1.6.0/{pg_uuidv7.tar.gz,SHA256SUMS}"
tar xf pg_uuidv7.tar.gz
sha256sum -c SHA256SUMS
PG_MAJOR=$(pg_config --version | sed 's/^.* \([0-9]\{1,\}\).*$/\1/')
cp "$PG_MAJOR/pg_uuidv7.so" "$(pg_config --pkglibdir)"
cp pg_uuidv7--1.6.sql pg_uuidv7.control "$(pg_config --sharedir)/extension"

rm -r "$TEMP_DIR"
