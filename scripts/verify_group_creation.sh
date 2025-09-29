#!/bin/bash

# Script to verify KeePass database group creation
# Usage: ./verify_group_creation.sh

set -e

echo "=== KEEPASS GROUP VERIFICATION ==="

# Check if secrets.yaml exists
if [ ! -f "secrets.yaml" ]; then
    echo "ERROR: secrets.yaml not found in current directory"
    exit 1
fi

# Extract profile from secrets.yaml
PROFILE=$(grep "profile:" secrets.yaml | head -1 | sed 's/.*profile:[[:space:]]*"\([^"]*\)".*/\1/' | sed 's/.*profile:[[:space:]]*\([^[:space:]]*\).*/\1/')

if [ -z "$PROFILE" ]; then
    echo "ERROR: No profile found in secrets.yaml"
    exit 1
fi

echo "Profile from secrets.yaml: $PROFILE"

# Clean any existing database
rm -rf .secrets_yohnah

# Create database using CLI
echo "Creating KeePass database..."
echo "testpassword123" | timeout 10 ./bin/secrets load test_load.yml -v -f || {
    echo "ERROR: Failed to create database"
    exit 1
}

# Check if database files were created
if [ ! -f ".secrets_yohnah/secrets.kdbx" ]; then
    echo "ERROR: KeePass database not created"
    exit 1
fi

if [ ! -f ".secrets_yohnah/secrets.key" ]; then
    echo "ERROR: KeePass keyfile not created"
    exit 1
fi

echo "SUCCESS: Database and keyfile created"

# Verify only correct files exist (no .kdbx.key)
EXTRA_FILES=$(find .secrets_yohnah -name "*.kdbx.key" | wc -l)
if [ "$EXTRA_FILES" -gt 0 ]; then
    echo "ERROR: Found unwanted .kdbx.key files"
    ls -la .secrets_yohnah/
    exit 1
fi

echo "SUCCESS: Only correct keyfile exists"

# Use Go test to verify group structure
echo "Verifying group structure in database..."
cd go && go run ../scripts/verify_keepass_groups.go ../.secrets_yohnah/secrets.kdbx ../secrets.yaml testpassword123

echo "=== GROUP VERIFICATION COMPLETED SUCCESSFULLY ==="