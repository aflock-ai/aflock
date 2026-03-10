#!/bin/sh
# Verify that generated docs are up-to-date.
# Run this in CI to catch stale documentation.

set -e

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

# Copy current docs
mkdir -p "$tmpdir/current/reference" "$tmpdir/current/schemas"
cp docs/reference/commands.md "$tmpdir/current/reference/" 2>/dev/null || true
cp docs/schemas/*.json "$tmpdir/current/schemas/" 2>/dev/null || true

# Generate fresh docs
mkdir -p "$tmpdir/fresh"
go run ./docgen --dir "$tmpdir/fresh"

echo "###########################################"
echo "If diffs are found, run: make docgen"
echo "###########################################"

# Compare CLI reference
if [ -f "$tmpdir/current/reference/commands.md" ]; then
    diff -u "$tmpdir/current/reference/commands.md" "$tmpdir/fresh/reference/commands.md" || {
        echo "FAIL: docs/reference/commands.md is out of date"
        exit 1
    }
fi

# Compare schemas
for schema in "$tmpdir/fresh/schemas/"*.json; do
    name=$(basename "$schema")
    if [ -f "$tmpdir/current/schemas/$name" ]; then
        diff -u "$tmpdir/current/schemas/$name" "$schema" || {
            echo "FAIL: docs/schemas/$name is out of date"
            exit 1
        }
    fi
done

echo "All generated docs are up-to-date."
